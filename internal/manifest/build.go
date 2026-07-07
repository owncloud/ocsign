package manifest

import (
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

// Build walks the app tree rooted at root and produces the canonical manifest
// per spec §3.1–§3.4: every regular file (minus the §3.2 exclusions) is hashed
// with SHA-512 (lowercase hex) under its normalized forward-slash relative key.
//
// Directories, symlinks, and other non-regular entries are not hashed and
// symlinks are never followed (§3.1).
func Build(root string) (*Manifest, error) {
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
		if isExcluded(key) {
			return nil
		}

		sum, err := hashFile(path)
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
	defer f.Close()

	h := sha512.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
