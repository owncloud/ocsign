// Package manifest implements the normative canonicalization rules (spec §3):
// discovering an app tree's files, hashing them, and serializing the result to
// the exact canonical byte sequence M that gets signed and verified.
//
// The single hardest requirement is that M is byte-identical to what the server
// verifier recomputes; the golden vectors under testdata/ are the shared
// conformance artifact for both implementations.
package manifest

import "sort"

// Mode selects the canonicalization rules Build applies. App mode signs a
// third-party app tree; core mode signs the ownCloud server root and carries the
// historical special cases (spec §3.6): extra exclusions and .htaccess
// normalization, matching the legacy verifier byte-for-byte.
type Mode int

const (
	ModeApp  Mode = iota // appinfo/signature.json + OS-cruft exclusions (§3.2)
	ModeCore             // core exclusions + root .htaccess normalization (§3.6)
)

// Manifest is a set of manifest-key -> lowercase-hex-SHA-512 entries.
type Manifest struct {
	hashes map[string]string
}

// Hashes returns the manifest's path -> hash map. The returned map is the
// manifest's own storage; callers must not mutate it.
func (m *Manifest) Hashes() map[string]string {
	return m.hashes
}

// Keys returns the manifest keys sorted by raw byte order (spec §3.5 step 2).
func (m *Manifest) Keys() []string {
	keys := make([]string, 0, len(m.hashes))
	for k := range m.hashes {
		keys = append(keys, k)
	}
	// Go string comparison is a byte-wise (lexicographic on UTF-8 bytes)
	// comparison, which is exactly the ordering §3.5 requires.
	sort.Strings(keys)
	return keys
}
