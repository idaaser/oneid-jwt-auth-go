package oneidjwtauth

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
)

func parseRSAPrivateKey(s string) (any, error) {
	s = normalizeLegacyPrivateKey(s)
	pemBlock, _ := pem.Decode([]byte(s))

	if pemBlock == nil {
		return nil, fmt.Errorf("invalid key: %s", s)
	}
	// try with pkcs8
	return x509.ParsePKCS8PrivateKey(pemBlock.Bytes)
}

func normalizeLegacyPrivateKey(s string) string {
	s = strings.TrimSpace(s)
	prefix, suffix := `-----BEGIN PRIVATE KEY-----`, `-----END PRIVATE KEY-----`
	if strings.HasPrefix(s, prefix) {
		s = strings.ReplaceAll(s, prefix, "")
		s = strings.ReplaceAll(s, suffix, "")
	}

	return strings.TrimSpace(prefix + "\r\n" + s + "\r\n" + suffix)
}
