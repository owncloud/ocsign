package cli_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/owncloud/ocsign/internal/manifest"
)

// envelope is the subset of signature.json (schema v2) an end-to-end verifier
// needs: the canonical bytes M (hashes), the base64 signature, and the leaf cert
// the signature must verify against.
type envelope struct {
	V            int             `json:"v"`
	Alg          string          `json:"alg"`
	Hashes       json.RawMessage `json:"hashes"`
	Signature    string          `json:"signature"`
	Certificates struct {
		Leaf  string   `json:"leaf"`
		Chain []string `json:"chain"`
	} `json:"certificates"`
}

// TestSignAndVerifyWithOpenSSL is the full round trip the unit tests stop short
// of: run the CLI to sign a real app tree, then independently prove the written
// appinfo/signature.json is valid — the stored manifest matches a freshly
// recomputed one, and the signature verifies against the embedded leaf cert
// using the OpenSSL CLI (mirroring the external ownCloud core verifier).
func TestSignAndVerifyWithOpenSSL(t *testing.T) {
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl CLI not available; skipping sign+verify round trip")
	}

	cases := []struct {
		name     string
		keyFile  string
		certFile string
		wantAlg  string
		rsaPSS   bool
	}{
		{name: "ec-p384", keyFile: "ec-leaf.key", certFile: "ec-leaf.crt", wantAlg: "ecdsa-p384-sha384"},
		{name: "rsa-4096", keyFile: "rsa-leaf.key", certFile: "rsa-leaf.crt", wantAlg: "rsa-pss-sha384", rsaPSS: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := copyTree(t, "tree-basic")

			code, _, stderr := run(t,
				"--path", tree,
				"--key", key(t, tc.keyFile),
				"--cert", key(t, tc.certFile),
			)
			if code != 0 {
				t.Fatalf("sign exit = %d, want 0; stderr: %s", code, stderr)
			}

			env := readEnvelope(t, filepath.Join(tree, "appinfo", "signature.json"))
			if env.V != 2 {
				t.Errorf("v = %d, want 2", env.V)
			}
			if env.Alg != tc.wantAlg {
				t.Errorf("alg = %q, want %q", env.Alg, tc.wantAlg)
			}

			// The stored hashes (M) must match a manifest recomputed from the
			// signed tree — the signature is meaningless if the tree it covers
			// drifted from what was recorded.
			assertManifestMatches(t, tree, manifest.ModeApp, env.Hashes)

			verifyWithOpenSSL(t, openssl, env, tc.rsaPSS)
		})
	}
}

// TestSignAndVerifyCoreWithOpenSSL is the core-mode counterpart of the app-mode
// round trip: sign tree-core with a CN=core leaf, confirm the stored manifest
// matches a freshly recomputed core-mode manifest, and verify the signature with
// the OpenSSL CLI (mirroring the external ownCloud core verifier).
func TestSignAndVerifyCoreWithOpenSSL(t *testing.T) {
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl CLI not available; skipping core sign+verify round trip")
	}

	cases := []struct {
		name     string
		keyFile  string
		certFile string
		wantAlg  string
		rsaPSS   bool
	}{
		{name: "ec-p384", keyFile: "ec-leaf.key", certFile: "ec-core-leaf.crt", wantAlg: "ecdsa-p384-sha384"},
		{name: "rsa-4096", keyFile: "rsa-leaf.key", certFile: "rsa-core-leaf.crt", wantAlg: "rsa-pss-sha384", rsaPSS: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := copyTree(t, "tree-core")

			code, _, stderr := run(t,
				"--path", tree,
				"--key", key(t, tc.keyFile),
				"--cert", key(t, tc.certFile),
				"--core",
			)
			if code != 0 {
				t.Fatalf("sign exit = %d, want 0; stderr: %s", code, stderr)
			}

			env := readEnvelope(t, filepath.Join(tree, "core", "signature.json"))
			if env.V != 2 {
				t.Errorf("v = %d, want 2", env.V)
			}
			if env.Alg != tc.wantAlg {
				t.Errorf("alg = %q, want %q", env.Alg, tc.wantAlg)
			}

			assertManifestMatches(t, tree, manifest.ModeCore, env.Hashes)
			verifyWithOpenSSL(t, openssl, env, tc.rsaPSS)
		})
	}
}

// TestSignAndVerifyHTMLCharsWithOpenSSL is the end-to-end regression guard for
// issue #19: a signed path containing '&' must still verify. Before the fix,
// Marshal HTML-escaped '&' to & in the written "hashes" value, so the
// on-disk bytes diverged from the signed canonical bytes M and OpenSSL verify —
// like ownCloud core's G2 verifier — rejected it.
//
// Only '&' is exercised on the filesystem here: '<' and '>' (the other two
// characters encoding/json escapes) are reserved and cannot appear in Windows
// filenames, and they are already covered filesystem-free by
// signature.TestHashesBytesEqualMWithHTMLChars.
func TestSignAndVerifyHTMLCharsWithOpenSSL(t *testing.T) {
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl CLI not available; skipping sign+verify round trip")
	}

	tree := t.TempDir()
	writeTreeFile(t, tree, "appinfo/info.xml", "<info><id>example-app</id></info>")
	// '&' is HTML-escaped by encoding/json but is a valid filename byte on every
	// platform (unlike '<' and '>').
	writeTreeFile(t, tree, "js/a & b.js", "console.log('hi');")

	code, _, stderr := run(t,
		"--path", tree,
		"--key", key(t, "ec-leaf.key"),
		"--cert", key(t, "ec-leaf.crt"),
	)
	if code != 0 {
		t.Fatalf("sign exit = %d, want 0; stderr: %s", code, stderr)
	}

	sigPath := filepath.Join(tree, "appinfo", "signature.json")
	raw, err := os.ReadFile(sigPath)
	if err != nil {
		t.Fatalf("read signature.json: %v", err)
	}
	// The written bytes must carry the literal '&': the \u-escaped form that
	// encoding/json emits by default must not appear.
	if bytes.Contains(raw, []byte(`\u0026`)) {
		t.Fatalf("signature.json contains escaped &; hashes bytes were re-escaped:\n%s", raw)
	}

	env := readEnvelope(t, sigPath)
	assertManifestMatches(t, tree, manifest.ModeApp, env.Hashes)
	verifyWithOpenSSL(t, openssl, env, false)
}

// writeTreeFile writes rel (forward-slash relative path) under root, creating
// parent dirs, so a test tree can be assembled in a temp dir.
func writeTreeFile(t *testing.T, root, rel, content string) {
	t.Helper()
	full := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", rel, err)
	}
}

// readEnvelope reads and unmarshals a signature.json file.
func readEnvelope(t *testing.T, path string) envelope {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read signature.json: %v", err)
	}
	var env envelope
	if err := json.Unmarshal(data, &env); err != nil {
		t.Fatalf("signature.json invalid: %v", err)
	}
	return env
}

// assertManifestMatches recomputes the canonical manifest bytes from tree and
// checks they equal want (the hashes stored in the envelope). Build excludes
// appinfo/signature.json, so the freshly written signature does not perturb the
// recomputation.
func assertManifestMatches(t *testing.T, tree string, mode manifest.Mode, want []byte) {
	t.Helper()
	m, err := manifest.Build(tree, mode)
	if err != nil {
		t.Fatalf("recompute manifest: %v", err)
	}
	if got := m.Canonical(); !bytes.Equal(got, want) {
		t.Errorf("recomputed manifest != stored hashes\n got: %s\nwant: %s", got, want)
	}
}

// verifyWithOpenSSL proves the envelope's signature verifies against its own
// embedded leaf certificate over SHA-384(hashes), using the openssl CLI so the
// verification path is entirely OpenSSL's — not Go's — matching what the PHP
// verifier relies on. rsaPSS selects the RSA-PSS sigopts.
func verifyWithOpenSSL(t *testing.T, openssl string, env envelope, rsaPSS bool) {
	t.Helper()

	der, err := base64.StdEncoding.DecodeString(env.Signature)
	if err != nil {
		t.Fatalf("signature is not standard base64: %v", err)
	}

	dir := t.TempDir()
	msgPath := filepath.Join(dir, "message")
	sigPath := filepath.Join(dir, "sig.der")
	leafPath := filepath.Join(dir, "leaf.pem")
	pubPath := filepath.Join(dir, "pub.pem")

	if err := os.WriteFile(msgPath, env.Hashes, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sigPath, der, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(leafPath, []byte(env.Certificates.Leaf), 0o644); err != nil {
		t.Fatal(err)
	}

	// Extract the public key from the embedded leaf cert via openssl, so the
	// whole verify chain (cert parse -> pubkey -> verify) is OpenSSL's.
	pub, err := exec.Command(openssl, "x509", "-in", leafPath, "-pubkey", "-noout").Output()
	if err != nil {
		t.Fatalf("openssl x509 -pubkey: %v", err)
	}
	if err := os.WriteFile(pubPath, pub, 0o644); err != nil {
		t.Fatal(err)
	}

	args := []string{"dgst", "-sha384", "-verify", pubPath, "-signature", sigPath}
	if rsaPSS {
		args = append(args,
			"-sigopt", "rsa_padding_mode:pss",
			"-sigopt", "rsa_pss_saltlen:-1", // salt length = digest length
		)
	}
	args = append(args, msgPath)

	out, err := exec.Command(openssl, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("openssl verify failed: %v\n%s", err, out)
	}
	if got := string(out); len(got) < 8 || got[:8] != "Verified" {
		t.Fatalf("unexpected openssl output: %q", got)
	}
}
