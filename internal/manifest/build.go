package manifest

import (
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// htaccessMarker delimits the core .htaccess baseline from the dynamic content
// the server appends at install time (core lib/private/Setup.php). In core mode
// only the bytes above it are hashed (spec §3.6), so signer and verifier agree
// despite install-time mutation.
const htaccessMarker = "#### DO NOT CHANGE ANYTHING ABOVE THIS LINE ####"

// Build walks the app tree rooted at root and produces the canonical manifest
// per spec §3.1–§3.4: every regular file (minus the exclusions for mode) is
// hashed with SHA-512 (lowercase hex) under its normalized forward-slash
// relative key. Core mode additionally normalizes the root .htaccess (§3.6).
//
// Directories, symlinks, and other non-regular entries are not hashed and
// symlinks are never followed (§3.1).
func Build(root string, mode Mode) (*Manifest, error) {
	m := &Manifest{hashes: make(map[string]string)}

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		// Only regular files are hashed. DirEntry.Type() reports the raw entry
		// type without following symlinks, so a symlink is Type()&Symlink != 0
		// and is skipped here rather than dereferenced.
		if !d.Type().IsRegular() {
			return nil
		}

		key, err := relKey(root, path)
		if err != nil {
			return err
		}
		if isExcluded(key, mode) {
			return nil
		}

		sum, err := hashFileForMode(path, key, mode)
		if err != nil {
			return err
		}
		m.hashes[key] = sum
		return nil
	})
	if err != nil {
		return nil, err
	}
	return m, nil
}

// hashFileForMode returns the manifest hash for path under its manifest key,
// applying core-mode normalization where required (spec §3.6).
//
// The only normalized file is the server-root .htaccess (key == ".htaccess",
// no slash) in core mode. The root .user.ini is NOT special-cased: the legacy
// Checker::generateHashes "resets" it by copying to a temp dir and hashing that
// copy verbatim — a no-op that yields the same bytes as a plain file hash, so
// no handling is needed here.
func hashFileForMode(path, key string, mode Mode) (string, error) {
	if mode == ModeCore && key == ".htaccess" {
		sum, matched, err := hashHtaccessBeforeMarker(path)
		if err != nil {
			return "", err
		}
		if matched {
			return sum, nil
		}
		// Marker absent or ambiguous: fall through to a whole-file hash.
	}
	return hashFile(path)
}

// hashHtaccessBeforeMarker hashes the bytes of the root .htaccess that precede
// the DO-NOT-CHANGE marker (spec §3.6). It reports matched=true only when the
// marker occurs exactly once; if it is absent (one part) or appears more than
// once (three+ parts), it reports matched=false so the caller hashes the whole
// file, mirroring the legacy explode()+count()===2 check.
func hashHtaccessBeforeMarker(path string) (sum string, matched bool, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", false, err
	}
	parts := strings.Split(string(data), htaccessMarker)
	if len(parts) != 2 {
		return "", false, nil
	}
	h := sha512.Sum512([]byte(parts[0]))
	return hex.EncodeToString(h[:]), true, nil
}

// relKey computes the manifest key for path relative to root (spec §3.3):
// forward slashes, no leading slash, no ./ prefix, no trailing slash, no case or
// Unicode transformation.
func relKey(root, path string) (string, error) {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return "", fmt.Errorf("relativize %q: %w", path, err)
	}
	return filepath.ToSlash(rel), nil
}

// hashFile returns the lowercase-hex SHA-512 of the raw file bytes (spec §3.4).
func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	// Read-only handle: a Close error cannot affect the computed digest.
	defer func() { _ = f.Close() }()

	h := sha512.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
