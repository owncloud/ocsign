package cli

import (
	"crypto/x509"
	"encoding/pem"
	"strings"
)

// encodeCertPEM renders a DER certificate as a PEM block with standard framing
// and LF line endings (spec §5).
func encodeCertPEM(der []byte) string {
	block := &pem.Block{Type: "CERTIFICATE", Bytes: der}
	return string(pem.EncodeToMemory(block))
}

// encodeChain renders each chain certificate as a PEM string for the
// certificates.chain[] field, preserving file order.
func encodeChain(certs []*x509.Certificate) []string {
	out := make([]string, 0, len(certs))
	for _, c := range certs {
		out = append(out, strings.TrimRight(encodeCertPEM(c.Raw), "\n")+"\n")
	}
	return out
}
