//go:build linux && !cgo

package certstore

import (
	"crypto"
	"crypto/x509"
	"errors"
)

type pkcs11State struct{}

type p11Identity struct{}

func initPKCS11(s *memStore) error {
	return nil
}

func closePKCS11(s *memStore) {}

func (p *p11Identity) Signer(cert *x509.Certificate) (crypto.Signer, error) {
	return nil, errors.New("PKCS#11 support requires cgo")
}
