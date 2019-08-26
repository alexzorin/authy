package authy

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	jab "github.com/cloudfoundry-attic/jibber_jabber"
)

const (
	baseURL = "https://api.authy.com/json/"

	// This is copied from app.js of AuthyChrome
	apiKey = "37b312a3d682b823c439522e1fd31c82"
)

// Client provides API interaction with the Authy API.
// See NewClient()
type Client struct {
	httpCl    http.Client
	UserAgent string
	APIKey    string

	// This doesn't seem to be a real nonce nor a signature, since
	// it actually appears to be random bytes that get re-used between
	// requests
	nonce []byte
}

// NewClient creates a new Authy API client.
func NewClient() (Client, error) {
	nonce, err := randomBytes(32)
	if err != nil {
		return Client{}, err
	}
	return Client{
		httpCl:    http.Client{},
		UserAgent: "authy (https://github.com/alexzorin/authy)",
		APIKey:    apiKey,
		nonce:     nonce,
	}, nil
}

func (c Client) doRequest(ctx context.Context, method, url string, body io.Reader, dest interface{}) error {
	req, err := http.NewRequest(method, baseURL+url, body)
	if err != nil {
		return err
	}
	if ctx == nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
	}
	req = req.WithContext(ctx)
	req.Header.Set("user-agent", c.UserAgent)

	resp, err := c.httpCl.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var r io.Reader = resp.Body
	if os.Getenv("AUTHY_DEBUG") == "1" {
		var debugBuf bytes.Buffer
		r = io.TeeReader(resp.Body, &debugBuf)
		defer func() {
			fmt.Fprintf(os.Stderr, "[AUTHY_DEBUG] Sent request to: %s, got response: %s\n",
				req.URL.String(), debugBuf.String())
		}()
	}

	return json.NewDecoder(r).Decode(&dest)
}

// QueryUser fetches the status of an Authy user account.
func (c Client) QueryUser(ctx context.Context, countryCallingCode int, phone string) (UserStatus, error) {
	var us UserStatus
	return us, c.doRequest(ctx, http.MethodGet, fmt.Sprintf("users/%d-%s/status", countryCallingCode, phone),
		nil, &us)
}

// RequestDeviceRegistration begins a new device registration for an Authy User account,
// via the nominated mechanism.
func (c Client) RequestDeviceRegistration(ctx context.Context, userID uint64, via ViaMethod) (StartDeviceRegistrationResponse, error) {
	form := url.Values{}
	form.Set("api_key", c.APIKey)
	form.Set("via", string(via))
	form.Set("device_app", "authy")
	form.Set("signature", hex.EncodeToString(c.nonce))

	var resp StartDeviceRegistrationResponse
	return resp, c.doRequest(ctx, http.MethodPost, fmt.Sprintf("users/%d/devices/registration/start", userID),
		strings.NewReader(form.Encode()), &resp)
}

// CheckDeviceRegistration fetches the status of the device registration request (requestID) for the
// nominated Authy User ID (userID). This should be polled with a timeout.
func (c Client) CheckDeviceRegistration(ctx context.Context, userID uint64, requestID string) (DeviceRegistrationStatus, error) {
	form := url.Values{}
	form.Set("api_key", c.APIKey)
	form.Set("signature", hex.EncodeToString(c.nonce))

	var resp DeviceRegistrationStatus
	return resp, c.doRequest(ctx, http.MethodGet,
		fmt.Sprintf("users/%d/devices/registration/%s/status?%s", userID, requestID, form.Encode()), nil, &resp)
}

// CompleteDeviceRegistration completes the device registration process for the nominated Authy User ID
// (userID) and PIN (from the DeviceRegistrationStatus)
func (c Client) CompleteDeviceRegistration(ctx context.Context, userID uint64, pin string) (CompleteDeviceRegistrationResponse, error) {
	form := url.Values{}
	form.Set("api_key", c.APIKey)
	form.Set("pin", pin)
	form.Set("device_app", "authy")

	var resp CompleteDeviceRegistrationResponse
	return resp, c.doRequest(ctx, http.MethodPost,
		fmt.Sprintf("users/%d/devices/registration/complete", userID), strings.NewReader(form.Encode()), &resp)
}

// QueryDevicePrivateKey fetches the PKCS#1 private key for the nominated device ID, using the
// known device secret TOTP seed from CompleteDeviceRegistrationResponse.
func (c Client) QueryDevicePrivateKey(ctx context.Context, deviceID uint64, deviceSeed string) (DevicePrivateKeyResponse, error) {
	// We need to generate 3 OTPs using the device seed in order to get access to the device private key
	codes, err := generateTOTPCodes(deviceSeed, totpDigits, totpTimeStep, false)
	if err != nil {
		return DevicePrivateKeyResponse{}, fmt.Errorf("Failed to generate TOTP codes: %v", err)
	}

	form := url.Values{}
	form.Set("api_key", apiKey)
	form.Set("device_id", strconv.FormatUint(deviceID, 10))
	form.Set("otp1", codes[0])
	form.Set("otp2", codes[1])
	form.Set("otp3", codes[2])

	var resp DevicePrivateKeyResponse
	return resp, c.doRequest(ctx, http.MethodGet,
		fmt.Sprintf("devices/%d/rsa_key?%s", deviceID, form.Encode()), nil, &resp)
}

// QueryAuthenticatorTokens fetches the encrypted TOTP tokens for userID, authenticating
// using the deviceSeed (hex-encoded).
func (c Client) QueryAuthenticatorTokens(ctx context.Context, userID uint64, deviceID uint64, deviceSeed string) (AuthenticatorTokensResponse, error) {
	codes, err := generateTOTPCodes(deviceSeed, totpDigits, totpTimeStep, false)
	if err != nil {
		return AuthenticatorTokensResponse{}, fmt.Errorf("Failed to generate TOTP codes: %v", err)
	}

	form := url.Values{}
	form.Set("api_key", apiKey)
	form.Set("device_id", strconv.FormatUint(deviceID, 10))
	form.Set("otp1", codes[0])
	form.Set("otp2", codes[1])
	form.Set("otp3", codes[2])
	form.Set("apps", "")

	var resp AuthenticatorTokensResponse
	return resp, c.doRequest(ctx, http.MethodGet,
		fmt.Sprintf("users/%d/authenticator_tokens?%s", userID, form.Encode()), nil, &resp)
}

// QueryAuthenticatorApps fetches the encrypted Authy App tokens for userID,
// authenticating using the deviceSeed (hex-encoded).
func (c Client) QueryAuthenticatorApps(ctx context.Context, userID uint64, deviceID uint64, deviceSeed string) (AuthenticatorAppsResponse, error) {
	codes, err := generateTOTPCodes(deviceSeed, totpDigits, totpTimeStep, false)
	if err != nil {
		return AuthenticatorAppsResponse{}, fmt.Errorf("Failed to generate TOTP codes: %v", err)
	}

	form := url.Values{}
	form.Set("api_key", apiKey)
	form.Set("device_id", strconv.FormatUint(deviceID, 10))
	form.Set("otp1", codes[0])
	form.Set("otp2", codes[1])
	form.Set("otp3", codes[2])
	language, err := jab.DetectIETF();
	if err != nil {
		language = "en-GB";
	}
	form.Set("locale", language)

	var resp AuthenticatorAppsResponse
	return resp, c.doRequest(ctx, http.MethodPost,
		fmt.Sprintf("users/%d/devices/%d/apps/sync?%s", userID, deviceID, form.Encode()), strings.NewReader(form.Encode()), &resp)
}
