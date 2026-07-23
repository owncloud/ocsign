package signature_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/owncloud/ocsign/internal/signature"
)

var (
	canonicalM = []byte(`{"appinfo/info.xml":"deadbeef","js/app.js":"cafe"}`)
	leafPEM    = "-----BEGIN CERTIFICATE-----\nLEAF\n-----END CERTIFICATE-----\n"
	chainPEM   = []string{"-----BEGIN CERTIFICATE-----\nINT\n-----END CERTIFICATE-----\n"}
)

// TestHashesBytesEqualM is the critical write rule (spec §5): the bytes emitted
// for the "hashes" value must be byte-identical to the signed canonical bytes M.
func TestHashesBytesEqualM(t *testing.T) {
	env := signature.Envelope{
		Alg:       "ecdsa-p384-sha384",
		Hashes:    canonicalM,
		Signature: "c2ln",
		Leaf:      leafPEM,
		Chain:     chainPEM,
	}

	out, err := env.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	// Locate the raw bytes following "hashes": and confirm they equal M exactly.
	marker := []byte(`"hashes":`)
	i := bytes.Index(out, marker)
	if i < 0 {
		t.Fatalf("no hashes field in output:\n%s", out)
	}
	rest := out[i+len(marker):]
	if !bytes.HasPrefix(rest, canonicalM) {
		t.Fatalf("hashes value is not the verbatim canonical bytes M\n got: %s\nwant prefix: %s", rest, canonicalM)
	}
}

// TestHashesBytesEqualMWithHTMLChars is the critical write rule (spec §5) for
// path keys containing '&', '<', '>'. encoding/json HTML-escapes these to
// &/</> by default — even inside a json.RawMessage — which would
// make the written "hashes" bytes diverge from the signed canonical bytes M and
// break verification (issue #19). The emitted bytes must contain the literal
// characters, byte-identical to M.
func TestHashesBytesEqualMWithHTMLChars(t *testing.T) {
	m := []byte(`{"a & b <c>.txt":"deadbeef"}`)
	env := signature.Envelope{
		Alg:       "ecdsa-p384-sha384",
		Hashes:    m,
		Signature: "c2ln",
		Leaf:      leafPEM,
		Chain:     chainPEM,
	}

	out, err := env.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	marker := []byte(`"hashes":`)
	i := bytes.Index(out, marker)
	if i < 0 {
		t.Fatalf("no hashes field in output:\n%s", out)
	}
	rest := out[i+len(marker):]
	if !bytes.HasPrefix(rest, m) {
		t.Fatalf("hashes value is not the verbatim canonical bytes M\n got: %s\nwant prefix: %s", rest, m)
	}
	// Belt and suspenders: the JSON \u-escaped forms that encoding/json emits by
	// default for & < > must not appear.
	for _, esc := range []string{`\u0026`, `\u003c`, `\u003e`} {
		if bytes.Contains(out, []byte(esc)) {
			t.Errorf("output contains escaped %s; hashes bytes were re-escaped:\n%s", esc, out)
		}
	}
}

// TestEnvelopeSchema confirms the schema-v2 shape and field names (spec §5).
func TestEnvelopeSchema(t *testing.T) {
	env := signature.Envelope{
		Alg:       "ecdsa-p384-sha384",
		Hashes:    canonicalM,
		Signature: "c2ln",
		Leaf:      leafPEM,
		Chain:     chainPEM,
	}
	out, err := env.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var parsed struct {
		V            int    `json:"v"`
		Alg          string `json:"alg"`
		Hashes       map[string]string
		Signature    string `json:"signature"`
		Certificates struct {
			Leaf  string   `json:"leaf"`
			Chain []string `json:"chain"`
		} `json:"certificates"`
	}
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, out)
	}

	if parsed.V != 2 {
		t.Errorf("v = %d, want 2", parsed.V)
	}
	if parsed.Alg != "ecdsa-p384-sha384" {
		t.Errorf("alg = %q", parsed.Alg)
	}
	if parsed.Signature != "c2ln" {
		t.Errorf("signature = %q", parsed.Signature)
	}
	if parsed.Certificates.Leaf != leafPEM {
		t.Errorf("leaf mismatch")
	}
	if len(parsed.Certificates.Chain) != 1 || parsed.Certificates.Chain[0] != chainPEM[0] {
		t.Errorf("chain mismatch: %v", parsed.Certificates.Chain)
	}
	if parsed.Hashes["appinfo/info.xml"] != "deadbeef" || parsed.Hashes["js/app.js"] != "cafe" {
		t.Errorf("hashes parsed wrong: %v", parsed.Hashes)
	}
}

// TestEmptyChainOmitsToEmptyArray confirms an omitted chain serializes as [].
func TestEmptyChainOmitsToEmptyArray(t *testing.T) {
	env := signature.Envelope{
		Alg:       "ecdsa-p384-sha384",
		Hashes:    canonicalM,
		Signature: "c2ln",
		Leaf:      leafPEM,
		Chain:     nil,
	}
	out, err := env.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !bytes.Contains(out, []byte(`"chain":[]`)) {
		t.Errorf("expected empty chain array, got:\n%s", out)
	}
}
