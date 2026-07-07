package manifest

import (
	"regexp"
	"strings"
)

// signatureFile is the app-mode signature file, excluded from its own manifest
// (spec §3.2 item 1).
const signatureFile = "appinfo/signature.json"

// cruftBaseNames are OS / file-manager artifacts excluded by exact base filename
// in any directory (spec §3.2 item 2). They are created at rest, never by the app.
var cruftBaseNames = map[string]struct{}{
	".DS_Store":  {}, // macOS
	"Thumbs.db":  {}, // Windows
	".directory": {}, // KDE Dolphin
	".webapp":    {}, // Gentoo webapp-config
}

// cruftPattern matches Gentoo webapp-config markers by base filename (spec §3.2
// item 3).
var cruftPattern = regexp.MustCompile(`^\.webapp-owncloud-.*`)

// isExcluded reports whether the manifest key (a forward-slash relative path)
// must be excluded from the app-mode manifest per §3.2.
func isExcluded(key string) bool {
	if key == signatureFile {
		return true
	}
	base := key
	if i := strings.LastIndexByte(key, '/'); i >= 0 {
		base = key[i+1:]
	}
	if _, ok := cruftBaseNames[base]; ok {
		return true
	}
	return cruftPattern.MatchString(base)
}
