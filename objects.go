package authy

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base32"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

// ViaMethod represents the methods available for new device registration
type ViaMethod string

const (
	// ViaMethodPush to recieve an Authy app-based push notification
	ViaMethodPush ViaMethod = "push"
	// ViaMethodCall to receive a phone call
	ViaMethodCall ViaMethod = "call"
	// ViaMethodSMS to receive an SMS message
	ViaMethodSMS ViaMethod = "sms"
)

// UserStatus is the response from:
// https://api.authy.com/json/users/{Country}-{Phone}/status
type UserStatus struct {
	// Presumably, force device validation over HTTP rather than
	// allowing a phone call or SMS. ("Over the top").
	ForceOTT bool `json:"force_ott"`

	// How many devices are registered to this Authy user
	DevicesCount int `json:"devices_count"`

	// Authy User ID
	AuthyID uint64 `json:"authy_id"`

	// Presumably some kind of opaque status string
	Message string

	// Whether this request was successful
	Success bool
}

// IsActiveUser reports whether this is an an active, registered
// Authy user.
func (us UserStatus) IsActiveUser() bool {
	return us.Success && us.AuthyID > 0 && us.Message == "active"
}

// StartDeviceRegistrationResponse is the response from:
// https://api.authy.com/json/users/{User_ID}/devices/registration/start
type StartDeviceRegistrationResponse struct {
	// Message to display to the user upon receiving this response
	Message string `json:"message"`

	// The Request ID is used to poll the status of the device registration process
	RequestID string `json:"request_id"`

	// Purpose unclear
	ApprovalPIN int `json:"approval_pin"`

	// The ViaMethod
	Provider string `json:"provider"`

	// Whether the device registration request was accepted.
	// This is distinct to the device registration being successful/complete.
	Success bool `json:"success"`
}

// DeviceRegistrationStatus is the response from:
// https://api.authy.com/json/users/{User_ID}/devices/registration/{Request_ID}/status?api_key={API_Key}&locale=en-GB&signature=b54ff1b646b207ff2da50ecb9a0bc2c770a1357b04278c8dd402f835db2824f4
type DeviceRegistrationStatus struct {
	// pending, accepted, rejected, ??
	Status string `json:"status"`

	// PIN is required to complete the device registration
	PIN string `json:"pin"`

	// Whether this status request was successful, distinct to whether the
	// registration process is complete.
	Success bool `json:"success"`
}

// CompleteDeviceRegistrationResponse is the response from:
// https://api.authy.com/json/users/16480/devices/registration/complete
type CompleteDeviceRegistrationResponse struct {
	Device struct {
		// The Device ID
		ID uint64 `json:"id"`

		// The Device Secret Seed (hex-encoded, 32-bytes). It is the TOTP
		// secret that protects the authenticated endpoints.
		SecretSeed string `json:"secret_seed"`

		// Purpose not known.
		APIKey string `json:"api_key"`

		// Purpose not known, but probably whether this device is being
		// re-installed.
		Reinstall bool `json:"reinstall"`
	} `json:"device"`

	// The Authy User ID
	AuthyID uint64 `json:"authy_id"`
}

// DevicePrivateKeyResponse is the response from
// https://api.authy.com/json/devices/{Device_ID}/rsa_key?api_key={API_Key}&&otp1={OTP_1}&otp2={OTP_2}&otp3={OTP_3}&device_id={DEVICE_ID}
type DevicePrivateKeyResponse struct {
	Message    string `json:"message"`
	PrivateKey string `json:"private_key"`
	Success    bool   `json:"success"`
}

// AsPrivateKey parses the PEM private key in PrivateKey
func (r DevicePrivateKeyResponse) AsPrivateKey() (*rsa.PrivateKey, error) {
	if !r.Success || r.PrivateKey == "" {
		return nil, errors.New("This response does not contain a device private key")
	}
	blk, _ := pem.Decode([]byte(r.PrivateKey))
	pk, err := x509.ParsePKCS1PrivateKey(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("Couldn't parse private key: %v", err)
	}
	return pk, nil
}

// AuthenticatorTokensResponse is the response from:
// https://api.authy.com/json/users/{User_ID}/authenticator_tokens?api_key={API_Key}&otp1={OTP_1}&otp2={OTP_2}&otp3={OTP_3}&device_id={Device_ID
type AuthenticatorTokensResponse struct {
	// Display to user
	Message string `json:"message"`

	// Active encrypted authenticator token
	AuthenticatorTokens []AuthenticatorToken `json:"authenticator_tokens"`

	// Recently deleted, but not removed encrypted authenticator tokens
	Deleted []AuthenticatorToken `json:"deleted"`

	// Whether this request succeeded
	Success bool `json:"success"`
}

// AuthenticatorToken is embedded in AuthenticatorTokensResponse
type AuthenticatorToken struct {
	// In the Authy app, this is the visual icon type of this token
	AccountType string `json:"account_type"`

	// How many digits this TOTP token is
	Digits int `json:"digits"`

	// The encrypted TOTP seed
	EncryptedSeed string `json:"encrypted_seed"`

	// The number of rounds for password-based key derivation
	KDFRounds int `json:"key_derivation_iterations"`

	// User-nominated name for the token
	Name string `json:"name"`

	// Purpose not known
	OriginalName string `json:"original_name"`

	// Purpose not known
	PasswordTimestamp uint64 `json:"password_timestamp"`

	// The salt used to encrypt the EncryptedSeed
	Salt string `json:"salt"`

	// The ID of this token
	UniqueID string `json:"unique_id"`
}

// Decrypt returns the base32-encoded seed for this TOTP token, decrypted
// by passphrase.
func (t AuthenticatorToken) Decrypt(passphrase string) (string, error) {
	secret, err := decryptToken(t.KDFRounds, t.EncryptedSeed, t.Salt, passphrase)
	if err != nil {
		return "", err
	}
	buf, err := hex.DecodeString(secret)
	if err != nil {
		return "", err
	}
	return strings.ToUpper(string(buf)), nil
}

// Description returns OriginalName if not empty, otherwise Name,
// otherwise `Token-{UniqueID}`.
func (t AuthenticatorToken) Description() string {
	if t.OriginalName != "" {
		return t.OriginalName
	}
	if t.Name != "" {
		return t.Name
	}
	return "Token-" + t.UniqueID
}

// AuthenticatorAppsResponse is the response from:
// https://api.authy.com/json/users/{User_ID}/devices/{Device_ID}/apps/sync
type AuthenticatorAppsResponse struct {
	// Display to user
	Message string `json:"message"`

	// Active encrypted authenticator apps
	AuthenticatorApps []AuthenticatorApp `json:"apps"`

	// Recently deleted, but not removed encrypted authenticator apps
	Deleted []AuthenticatorApp `json:"deleted"`

	// Whether this request succeeded
	Success bool `json:"success"`
}

// AuthenticatorApp is embedded in AuthenticatorAppsResponse
type AuthenticatorApp struct {
	ID string `json:"_id"`

	// Display name of the token
	Name string `json:"name"`

	SerialID int `json:"serial_id"`

	Version int `json:"version"`

	AssetsGroup string `json:"assets_group"`

	AuthyID uint64 `json:"authy_id"`

	// The Device Secret Seed (hex-encoded). It is the TOTP
	// secret that protects the authenticated endpoints.
	SecretSeed string `json:"secret_seed"`

	// How many digits in the TOTP
	Digits int `json:"digits"`
}

// Token produces the base32-encoded TOTP token backing
// this app. It has a period of 10.
func (a AuthenticatorApp) Token() (string, error) {
	decoded, err := hex.DecodeString(a.SecretSeed)
	if err != nil {
		return "", err
	}
	encoder := base32.StdEncoding.WithPadding(base32.NoPadding)
	return encoder.EncodeToString(decoded), nil
}
