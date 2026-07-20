package sign_test

import (
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/owncloud/ocsign/internal/keys"
	"github.com/owncloud/ocsign/internal/sign"
)

// TestOpenSSLCrossCheck verifies that a signature ocsign produces is accepted by
// the OpenSSL CLI, not just by Go (spec §9, REQUIRED). A Go-only test would miss
// encoder incompatibilities in the DER/base64 conventions the PHP verifier and
// `openssl` rely on.
func TestOpenSSLCrossCheck(t *testing.T) {
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl CLI not available; skipping cross-check")
	}

	cases := []struct {
		name    string
		keyFile string
	}{
		{name: "ecdsa-p384", keyFile: "ec-leaf.key"},
		{name: "rsa-pss", keyFile: "rsa-leaf.key"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			key, err := keys.LoadPrivateKey(keyPath(t, tc.keyFile))
			if err != nil {
				t.Fatal(err)
			}

			_, sigB64, err := sign.Sign(key, messageM)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			der, err := base64.StdEncoding.DecodeString(sigB64)
			if err != nil {
				t.Fatalf("decode base64: %v", err)
			}

			dir := t.TempDir()
			msgPath := filepath.Join(dir, "message")
			sigPath := filepath.Join(dir, "sig.der")
			pubPath := filepath.Join(dir, "pub.pem")
			if err := os.WriteFile(msgPath, messageM, 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(sigPath, der, 0o644); err != nil {
				t.Fatal(err)
			}

			// Extract the public key from the private key via openssl so the
			// verification path is entirely OpenSSL's.
			pub, err := exec.Command(openssl, "pkey", "-in", keyPath(t, tc.keyFile), "-pubout").Output()
			if err != nil {
				t.Fatalf("openssl pkey -pubout: %v", err)
			}
			if err := os.WriteFile(pubPath, pub, 0o644); err != nil {
				t.Fatal(err)
			}

			// Verify SHA-384(message) with the appropriate scheme.
			args := []string{"dgst", "-sha384", "-verify", pubPath, "-signature", sigPath}
			if tc.name == "rsa-pss" {
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
			if got := string(out); got == "" || got[:8] != "Verified" {
				t.Fatalf("unexpected openssl output: %q", got)
			}
		})
	}
}
