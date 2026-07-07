package manifest

import "testing"

// TestSerializeEscaping pins the minimal RFC 8259 escaping of §3.5: escape only
// '"', '\', and control chars U+0000–U+001F (short forms where defined, else
// \uXXXX lowercase); do NOT escape '/' or non-ASCII bytes.
func TestSerializeEscaping(t *testing.T) {
	cases := []struct {
		name  string
		pairs [][2]string
		want  string
	}{
		{
			name: "no escaping for slash or non-ascii",
			// byte order: "a/b/c" (0x61 0x2f...) sorts before "café/x" (0x63...).
			pairs: [][2]string{{"café/x", "ab"}, {"a/b/c", "cd"}},
			want:  "{\"a/b/c\":\"cd\",\"café/x\":\"ab\"}",
		},
		{
			name:  "quote and backslash escaped",
			pairs: [][2]string{{"a\"b\\c", "00"}},
			want:  "{\"a\\\"b\\\\c\":\"00\"}",
		},
		{
			name:  "control chars short forms",
			pairs: [][2]string{{"tab\tnl\n", "00"}},
			want:  "{\"tab\\tnl\\n\":\"00\"}",
		},
		{
			name:  "control char uXXXX lowercase",
			pairs: [][2]string{{"x\x01y", "00"}},
			want:  "{\"x\\u0001y\":\"00\"}",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := fromPairs(tc.pairs)
			if got := string(m.Canonical()); got != tc.want {
				t.Errorf("Canonical() = %q, want %q", got, tc.want)
			}
		})
	}
}

// fromPairs builds a Manifest directly from key/value pairs, bypassing the
// filesystem, so escaping/ordering can be tested in isolation.
func fromPairs(pairs [][2]string) *Manifest {
	m := &Manifest{hashes: make(map[string]string, len(pairs))}
	for _, p := range pairs {
		m.hashes[p[0]] = p[1]
	}
	return m
}
