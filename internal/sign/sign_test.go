package sign_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha512"
	"encoding/base64"
	"path/filepath"
	"testing"

	"github.com/owncloud/ocsign/internal/keys"
	"github.com/owncloud/ocsign/internal/sign"
)

func keyPath(t *testing.T, name string) string {
	t.Helper()
	p, err := filepath.Abs(filepath.Join("..", "..", "testdata", "keys", name))
	if err != nil {
		t.Fatalf("abs: %v", err)
	}
	return p
}

var messageM = []byte(`{"appinfo/info.xml":"deadbeef","js/app.js":"cafe"}`)

// TestSignEC signs M with the EC P-384 key and verifies the ECDSA-DER signature
// against the leaf public key over SHA-384(M) (spec §4).
func TestSignEC(t *testing.T) {
	key, err := keys.LoadPrivateKey(keyPath(t, "ec-leaf.key"))
	if err != nil {
		t.Fatal(err)
	}

	alg, sig, err := sign.Sign(key, messageM)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if alg != "ecdsa-p384-sha384" {
		t.Errorf("alg = %q, want ecdsa-p384-sha384", alg)
	}

	der, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {
		t.Fatalf("signature is not standard base64: %v", err)
	}
	pub := key.Public().(*ecdsa.PublicKey)
	digest := sha512.Sum384(messageM)
	if !ecdsa.VerifyASN1(pub, digest[:], der) {
		t.Fatal("ECDSA signature did not verify")
	}
}

// TestSignRSA signs M with the RSA-4096 fallback key and verifies the RSA-PSS
// signature over SHA-384(M) (spec §4): MGF1-SHA384, salt length = hash length.
func TestSignRSA(t *testing.T) {
	key, err := keys.LoadPrivateKey(keyPath(t, "rsa-leaf.key"))
	if err != nil {
		t.Fatal(err)
	}

	alg, sig, err := sign.Sign(key, messageM)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if alg != "rsa-pss-sha384" {
		t.Errorf("alg = %q, want rsa-pss-sha384", alg)
	}

	raw, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {
		t.Fatalf("signature is not standard base64: %v", err)
	}
	pub := key.Public().(*rsa.PublicKey)
	digest := sha512.Sum384(messageM)
	opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}
	if err := rsa.VerifyPSS(pub, crypto.SHA384, digest[:], raw, opts); err != nil {
		t.Fatalf("RSA-PSS signature did not verify: %v", err)
	}
}
