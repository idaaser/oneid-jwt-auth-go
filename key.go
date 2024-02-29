package oneidjwtauth

import (
	"strings"

	"golang.org/x/crypto/ssh"
)

func parseRSAPrivateKey(s string) (any, error) {
	s = normalizeLegacyPrivateKey(s)
	return ssh.ParseRawPrivateKey([]byte(s))
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
