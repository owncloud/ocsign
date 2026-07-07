// Package keys loads OpenSSL-produced PEM private keys and certificates and
// checks key/cert consistency (spec §2, §9). Standard library only.
package keys

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

// publicKeyEqualer is implemented by the standard library's *ecdsa.PublicKey and
// *rsa.PublicKey via their Equal(crypto.PublicKey) bool method.
type publicKeyEqualer interface {
	Equal(crypto.PublicKey) bool
}

// LoadPrivateKey reads a PEM private key produced by OpenSSL. It accepts SEC1 EC
// keys (-----BEGIN EC PRIVATE KEY-----), PKCS#8 keys (-----BEGIN PRIVATE KEY-----,
// EC or RSA), and PKCS#1 RSA keys (-----BEGIN RSA PRIVATE KEY-----), matching the
// forms the OpenSSL CLI emits (spec §9).
func LoadPrivateKey(path string) (crypto.Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %q", path)
	}

	var key any
	switch block.Type {
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unsupported PEM block type %q in %q", block.Type, path)
	}
	if err != nil {
		return nil, fmt.Errorf("parse private key %q: %w", path, err)
	}

	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("private key in %q does not implement crypto.Signer", path)
	}
	return signer, nil
}

// LoadCertificate parses the first certificate from a PEM file.
func LoadCertificate(path string) (*x509.Certificate, error) {
	certs, err := LoadChain(path)
	if err != nil {
		return nil, err
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificate found in %q", path)
	}
	return certs[0], nil
}

// LoadChain parses every certificate in a PEM file, in file order.
func LoadChain(path string) ([]*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var certs []*x509.Certificate
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse certificate in %q: %w", path, err)
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("no CERTIFICATE PEM block found in %q", path)
	}
	return certs, nil
}

// PublicKeyMatches reports whether the private key's public half equals the
// certificate's subject public key (spec §2 consistency check).
func PublicKeyMatches(key crypto.Signer, cert *x509.Certificate) bool {
	pub, ok := key.Public().(publicKeyEqualer)
	if !ok {
		return false
	}
	return pub.Equal(cert.PublicKey)
}
