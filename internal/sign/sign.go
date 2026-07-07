// Package sign signs the canonical manifest bytes M and reports the algorithm
// identifier recorded in signature.json (spec §4).
package sign

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
)

// Algorithm identifiers written to signature.json (spec §4, §5).
const (
	AlgECDSAP384SHA384 = "ecdsa-p384-sha384"
	AlgRSAPSSSHA384    = "rsa-pss-sha384"
)

// Sign signs the canonical manifest bytes m and returns the algorithm identifier
// and the base64 (standard, padded) signature (spec §4).
//
//   - EC P-384: ECDSA over SHA-384(m), ASN.1 DER (ecdsa.SignASN1).
//   - RSA-4096: RSA-PSS over SHA-384(m), MGF1-SHA384, salt length = hash length.
//
// SHA-1 is never used. Any other key type is rejected.
func Sign(key crypto.Signer, m []byte) (alg string, signature string, err error) {
	digest := sha512.Sum384(m)

	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		if name := k.Curve.Params().Name; name != "P-384" {
			return "", "", fmt.Errorf("%w: EC curve %s (only P-384 supported)", ErrUnsupportedKeyType, name)
		}
		der, err := ecdsa.SignASN1(rand.Reader, k, digest[:])
		if err != nil {
			return "", "", fmt.Errorf("ecdsa sign: %w", err)
		}
		return AlgECDSAP384SHA384, base64.StdEncoding.EncodeToString(der), nil

	case *rsa.PrivateKey:
		if bits := k.N.BitLen(); bits != 4096 {
			return "", "", fmt.Errorf("%w: RSA-%d (only RSA-4096 supported)", ErrUnsupportedKeyType, bits)
		}
		opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA384}
		sig, err := rsa.SignPSS(rand.Reader, k, crypto.SHA384, digest[:], opts)
		if err != nil {
			return "", "", fmt.Errorf("rsa-pss sign: %w", err)
		}
		return AlgRSAPSSSHA384, base64.StdEncoding.EncodeToString(sig), nil

	default:
		return "", "", fmt.Errorf("%w: %T", ErrUnsupportedKeyType, key)
	}
}
