package keys_test

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"path/filepath"
	"testing"

	"github.com/DeepDiver1975/ocsign/internal/keys"
)

func keyPath(t *testing.T, name string) string {
	t.Helper()
	p, err := filepath.Abs(filepath.Join("..", "..", "testdata", "keys", name))
	if err != nil {
		t.Fatalf("abs: %v", err)
	}
	return p
}

// TestLoadPrivateKeyEC_PKCS8 loads the PKCS#8-encoded EC P-384 test key (§9).
func TestLoadPrivateKeyEC_PKCS8(t *testing.T) {
	k, err := keys.LoadPrivateKey(keyPath(t, "ec-leaf.key"))
	if err != nil {
		t.Fatalf("LoadPrivateKey: %v", err)
	}
	ec, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PrivateKey, got %T", k)
	}
	if ec.Curve.Params().Name != "P-384" {
		t.Errorf("expected P-384, got %s", ec.Curve.Params().Name)
	}
}

// TestLoadPrivateKeyEC_SEC1 loads the same EC key in SEC1 form (§9).
func TestLoadPrivateKeyEC_SEC1(t *testing.T) {
	k, err := keys.LoadPrivateKey(keyPath(t, "ec-leaf.sec1.key"))
	if err != nil {
		t.Fatalf("LoadPrivateKey: %v", err)
	}
	if _, ok := k.(*ecdsa.PrivateKey); !ok {
		t.Fatalf("expected *ecdsa.PrivateKey, got %T", k)
	}
}

// TestLoadPrivateKeyRSA loads the PKCS#8 RSA-4096 fallback key (§9).
func TestLoadPrivateKeyRSA(t *testing.T) {
	k, err := keys.LoadPrivateKey(keyPath(t, "rsa-leaf.key"))
	if err != nil {
		t.Fatalf("LoadPrivateKey: %v", err)
	}
	rk, ok := k.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("expected *rsa.PrivateKey, got %T", k)
	}
	if rk.N.BitLen() != 4096 {
		t.Errorf("expected 4096-bit RSA, got %d", rk.N.BitLen())
	}
}

// TestLoadCertificate parses the leaf PEM certificate.
func TestLoadCertificate(t *testing.T) {
	cert, err := keys.LoadCertificate(keyPath(t, "ec-leaf.crt"))
	if err != nil {
		t.Fatalf("LoadCertificate: %v", err)
	}
	if cert.Subject.CommonName != "example-app" {
		t.Errorf("CN = %q, want example-app", cert.Subject.CommonName)
	}
}

// TestLoadChain parses a PEM file that may hold multiple certs.
func TestLoadChain(t *testing.T) {
	chain, err := keys.LoadChain(keyPath(t, "ec-intermediate.crt"))
	if err != nil {
		t.Fatalf("LoadChain: %v", err)
	}
	if len(chain) != 1 {
		t.Fatalf("expected 1 cert in chain, got %d", len(chain))
	}
}

// TestPublicKeyMatches confirms the key/cert consistency check (spec §2): the
// EC leaf key matches the EC leaf cert, but not the RSA leaf cert.
func TestPublicKeyMatches(t *testing.T) {
	ecKey, err := keys.LoadPrivateKey(keyPath(t, "ec-leaf.key"))
	if err != nil {
		t.Fatal(err)
	}
	ecCert, err := keys.LoadCertificate(keyPath(t, "ec-leaf.crt"))
	if err != nil {
		t.Fatal(err)
	}
	rsaCert, err := keys.LoadCertificate(keyPath(t, "rsa-leaf.crt"))
	if err != nil {
		t.Fatal(err)
	}

	if !keys.PublicKeyMatches(ecKey, ecCert) {
		t.Error("EC key should match EC leaf cert")
	}
	if keys.PublicKeyMatches(ecKey, rsaCert) {
		t.Error("EC key must NOT match RSA leaf cert")
	}
}
