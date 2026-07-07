package manifest

import "strings"

const hexdigits = "0123456789abcdef"

// Canonical returns the canonical manifest bytes M (spec §3.5): a compact JSON
// object with keys in raw byte order, minimal RFC 8259 escaping, and no
// insignificant whitespace. This is the exact message that is signed and
// verified, and the exact bytes written as the signature.json "hashes" value.
//
// It deliberately does NOT use encoding/json (spec §7): Go's encoder HTML-escapes
// '<', '>', '&' and may otherwise diverge from the verifier. This serializer
// implements §3.5 exactly.
func (m *Manifest) Canonical() []byte {
	var b strings.Builder
	b.WriteByte('{')
	for i, key := range m.Keys() {
		if i > 0 {
			b.WriteByte(',')
		}
		writeJSONString(&b, key)
		b.WriteByte(':')
		writeJSONString(&b, m.hashes[key])
	}
	b.WriteByte('}')
	return []byte(b.String())
}

// writeJSONString writes s as a JSON string with minimal escaping per §3.5:
// escape only '"', '\', and control characters U+0000–U+001F. Control chars use
// the short forms \b \t \n \f \r where defined, otherwise \uXXXX with lowercase
// hex. '/' and non-ASCII bytes are emitted verbatim (UTF-8 on disk).
func writeJSONString(b *strings.Builder, s string) {
	b.WriteByte('"')
	// Iterate over bytes, not runes: the key is the exact relative-path bytes and
	// only ASCII control bytes / '"' / '\' are ever escaped. Multibyte UTF-8
	// sequences pass through byte-for-byte.
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"':
			b.WriteString(`\"`)
		case c == '\\':
			b.WriteString(`\\`)
		case c == '\b':
			b.WriteString(`\b`)
		case c == '\t':
			b.WriteString(`\t`)
		case c == '\n':
			b.WriteString(`\n`)
		case c == '\f':
			b.WriteString(`\f`)
		case c == '\r':
			b.WriteString(`\r`)
		case c < 0x20:
			b.WriteString(`\u00`)
			b.WriteByte(hexdigits[c>>4])
			b.WriteByte(hexdigits[c&0x0f])
		default:
			b.WriteByte(c)
		}
	}
	b.WriteByte('"')
}
