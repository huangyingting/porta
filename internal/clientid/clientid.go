package clientid

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
)

func derive(platform, value string) (string, error) {
	value = strings.TrimSpace(value)
	var prefix string
	switch platform {
	case "windows":
		if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
			return "", errors.New("invalid Windows MachineGuid")
		}
		value = strings.ReplaceAll(value, "-", "")
		prefix = "w-"
	case "linux":
		prefix = "l-"
	default:
		return "", errors.New("unsupported device identity platform")
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != 16 {
		return "", errors.New("OS device identity must be a 128-bit hexadecimal value")
	}
	if [16]byte(decoded) == [16]byte{} {
		return "", errors.New("OS device identity must not be zero")
	}

	// Keep this domain and encoding stable: changing them creates new enrollments.
	// The app-specific digest avoids sending a system-wide identifier to servers.
	digest := hmac.New(sha256.New, []byte("porta/device-id/v1/"+platform))
	_, _ = digest.Write(decoded)
	return prefix + base64.RawURLEncoding.EncodeToString(digest.Sum(nil)[:16]), nil
}
