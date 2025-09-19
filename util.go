package wit_wpt_go

import (
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

func generateJTI() (string, error) {
	b := make([]byte, 32)
	if _, err := cryptorand.Read(b); err != nil {
		return "", fmt.Errorf("reading rand: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// base64SHA256 calculates the SHA-256 hash of the input string and encodes it
// using base64 URL encoding.
// This is mandated by the W2W spec to be used for the ATH, TTH, OTH and WTH
// claims.
func base64SHA256(raw string) string {
	if raw == "" {
		return ""
	}

	h := sha256.New()
	h.Write([]byte(raw))

	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(h.Sum(nil))
}
