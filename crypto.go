package authy

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"strings"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

const (
	totpTimeStep = 10
	totpDigits   = 7
	kdfKeyLen    = 256
)

func generateTOTPCodes(hexSecret string, digits int, timeStep int64, decodeBase32 bool) ([3]string, error) {
	codes := [3]string{}

	// Outer encoding is hex
	decoded, err := hex.DecodeString(hexSecret)
	if err != nil {
		return codes, err
	}

	if decodeBase32 {
		// Inner encoding is lowercase base32 string which we further need to decode
		decoded, err = base32.StdEncoding.DecodeString(strings.ToUpper(string(decoded)))
		if err != nil {
			return codes, err
		}
	}

	// Generate 3 codes with timeStep
	t := time.Now()
	tDelta := time.Second * time.Duration(timeStep)

	for i := range codes {
		code, err := generateTOTP(decoded, t, digits, timeStep)
		if err != nil {
			return codes, err
		}
		codes[i] = code
		t = t.Add(tDelta)
	}

	return codes, nil
}

// Largely copied from https://github.com/pquerna/otp/blob/master/hotp/hotp.go
func generateTOTP(secret []byte, t time.Time, digits int, timeStep int64) (string, error) {
	t1 := t.Unix()
	C := t1 / timeStep

	cBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(cBuf, uint64(C))

	mac := hmac.New(sha1.New, secret)
	mac.Write(cBuf)

	H := mac.Sum(nil)

	offset := H[len(H)-1] & 0xf
	value := int64(((int(H[offset]) & 0x7f) << 24) |
		((int(H[offset+1] & 0xff)) << 16) |
		((int(H[offset+2] & 0xff)) << 8) |
		(int(H[offset+3]) & 0xff))

	mod := int32(value % int64(math.Pow10(digits)))

	f := fmt.Sprintf("%%0%dd", digits)
	return fmt.Sprintf(f, mod), nil
}

func decryptToken(kdfRounds int, encryptedSeedB64, salt, passphrase string) (string, error) {
	encryptedSeed, err := base64.StdEncoding.DecodeString(encryptedSeedB64)
	if err != nil {
		return "", fmt.Errorf("Error decoding encrypted seed: %v", err)
	}

	k := pbkdf2.Key([]byte(passphrase), []byte(salt), kdfRounds, kdfKeyLen/8, sha1.New)

	blk, err := aes.NewCipher(k)
	if err != nil {
		return "", err
	}
	// IV is all zeros
	iv := make([]byte, aes.BlockSize)
	cbc := cipher.NewCBCDecrypter(blk, iv)

	out := make([]byte, len(encryptedSeed))
	cbc.CryptBlocks(out, encryptedSeed)

	// The padding scheme seems to me that the final block will be padded with
	// the length of the padding. In the case when the plaintext aligns with
	// the block size, the final block will be padding-only.
	// Additionally, since CBC is not authenticated, we need to ensure that the
	// padding is not just garbage bytes.
	paddingLen := out[len(out)-1]
	paddingStart := len(out) - int(paddingLen)

	if paddingLen > aes.BlockSize || paddingStart >= len(out) || paddingStart <= 0 {
		return "", errors.New("decryption failed")
	}

	var cmp byte
	for _, pad := range out[paddingStart:] {
		cmp |= pad ^ paddingLen
	}
	if subtle.ConstantTimeByteEq(cmp, 0) != 1 {
		return "", errors.New("decryption failed")
	}

	return hex.EncodeToString(out[:paddingStart]), nil
}

func randomBytes(byteSize int) ([]byte, error) {
	buf := make([]byte, byteSize)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return nil, err
	}
	return buf, nil
}
