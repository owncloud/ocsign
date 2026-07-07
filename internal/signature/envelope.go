// Package signature builds the signature.json output envelope (schema v2, §5).
package signature

import "encoding/json"

// Envelope is the schema-v2 signature.json document.
//
// Hashes carries the canonical manifest bytes M verbatim (spec §5 "critical
// write rule"): M is built once, signed, and written as the hashes value without
// re-encoding, so the verifier — which reconstructs M from the stored hashes —
// sees byte-identical input to what was signed.
type Envelope struct {
	Alg       string
	Hashes    []byte // the canonical bytes M, emitted verbatim
	Signature string // base64(DER ECDSA) or base64(RSA-PSS)
	Leaf      string // PEM leaf certificate
	Chain     []string
}

// wire is the exact on-disk JSON shape (§5). Hashes is json.RawMessage so the
// canonical bytes M pass through unmodified rather than being re-serialized from
// a map (which would reorder keys and change whitespace/escaping).
type wire struct {
	V            int             `json:"v"`
	Alg          string          `json:"alg"`
	Hashes       json.RawMessage `json:"hashes"`
	Signature    string          `json:"signature"`
	Certificates certificates    `json:"certificates"`
}

type certificates struct {
	Leaf  string   `json:"leaf"`
	Chain []string `json:"chain"`
}

// Marshal renders the envelope as signature.json bytes. The emitted "hashes"
// value is byte-identical to Hashes (M).
func (e Envelope) Marshal() ([]byte, error) {
	chain := e.Chain
	if chain == nil {
		// Emit "chain":[] rather than null when no intermediates are embedded
		// (the field is always present in schema v2, §5).
		chain = []string{}
	}
	return json.Marshal(wire{
		V:         2,
		Alg:       e.Alg,
		Hashes:    json.RawMessage(e.Hashes),
		Signature: e.Signature,
		Certificates: certificates{
			Leaf:  e.Leaf,
			Chain: chain,
		},
	})
}
