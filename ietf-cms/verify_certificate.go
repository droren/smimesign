//go:build !darwin || !cgo

package cms

import "crypto/x509"

func verifyCertificate(cert *x509.Certificate, _ []*x509.Certificate, opts x509.VerifyOptions) ([][]*x509.Certificate, error) {
	return cert.Verify(opts)
}
