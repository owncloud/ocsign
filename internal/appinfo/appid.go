// Package appinfo determines and validates the app identity from appinfo/info.xml
// and enforces the CN==appId comparison rules shared with the verifier
// (spec-core-verifier §7, design §4.1).
package appinfo

import (
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
)

// appIDPattern is the canonical appId / leaf-CN form (§7).
var appIDPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{1,63}$`)

// AppID reads appinfo/info.xml under root, extracts the <id>, ASCII case-folds it
// (A–Z → a–z, the 26 ASCII bytes only — never locale/Unicode lowercasing), and
// validates it against the canonical pattern (§7). It is the authoritative appId.
func AppID(root string) (string, error) {
	path := filepath.Join(root, "appinfo", "info.xml")
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read info.xml: %w", err)
	}

	var info struct {
		ID string `xml:"id"`
	}
	if err := xml.Unmarshal(data, &info); err != nil {
		return "", fmt.Errorf("parse info.xml: %w", err)
	}
	if info.ID == "" {
		return "", fmt.Errorf("no <id> element in %s", path)
	}

	id := asciiFold(info.ID)
	if !appIDPattern.MatchString(id) {
		return "", fmt.Errorf("app id %q is not a valid identifier (must match %s)", id, appIDPattern)
	}
	return id, nil
}

// ValidateCN validates a leaf certificate CN against the canonical pattern with
// no normalization — the CN is canonical by issuance (§7).
func ValidateCN(cn string) error {
	if !appIDPattern.MatchString(cn) {
		return fmt.Errorf("leaf CN %q is not a valid identifier (must match %s)", cn, appIDPattern)
	}
	return nil
}

// asciiFold lowercases only the 26 ASCII uppercase bytes, leaving every other
// byte (including multibyte UTF-8 sequences) untouched.
func asciiFold(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}
