package fakeca

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"fmt"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// Identity is a certificate and private key.
type Identity struct {
	Issuer      *Identity
	PrivateKey  crypto.Signer
	Certificate *x509.Certificate
	NextSN      int64
}

// New creates a new CA.
func New(opts ...Option) *Identity {
	c := &configuration{}

	for _, opt := range opts {
		option(opt)(c)
	}

	return c.generate()
}

// Issue issues a new Identity with this one as its parent.
func (id *Identity) Issue(opts ...Option) *Identity {
	opts = append(opts, Issuer(id))
	return New(opts...)
}

// PFX wraps the certificate and private key in an encrypted PKCS#12 packet. The
// provided password must be alphanumeric.
func (id *Identity) PFX(password string) []byte {
	// Include full chain when exporting so tests behave consistently
	return toPFX(id.Certificate, id.PrivateKey, password, id.IssuerChain()...)
}

// Chain builds a slice of *x509.Certificate from this CA and its issuers.
func (id *Identity) Chain() []*x509.Certificate {
	chain := []*x509.Certificate{}
	for this := id; this != nil; this = this.Issuer {
		chain = append(chain, this.Certificate)
	}

	return chain
}

// IssuerChain returns the certificate chain for the issuers of this identity
// excluding the identity's own certificate.
func (id *Identity) IssuerChain() []*x509.Certificate {
	var chain []*x509.Certificate
	for this := id.Issuer; this != nil; this = this.Issuer {
		chain = append(chain, this.Certificate)
	}
	return chain
}

// ChainPool builds an *x509.CertPool from this CA and its issuers.
func (id *Identity) ChainPool() *x509.CertPool {
	chain := x509.NewCertPool()
	for this := id; this != nil; this = this.Issuer {
		chain.AddCert(this.Certificate)
	}

	return chain
}

// IncrementSN returns the next serial number.
func (id *Identity) IncrementSN() int64 {
	defer func() {
		id.NextSN++
	}()

	return id.NextSN
}

func toPFX(cert *x509.Certificate, priv interface{}, password string, chain ...*x509.Certificate) []byte {
	// only allow alphanumeric passwords
	for _, c := range password {
		switch {
		case c >= 'a' && c <= 'z':
		case c >= 'A' && c <= 'Z':
		case c >= '0' && c <= '9':
		default:
			panic("password must be alphanumeric")
		}
	}

	pfx, err := pkcs12.Encode(rand.Reader, priv, cert, chain, fmt.Sprintf("%s", password))
	if err != nil {
		panic(err)
	}

	return pfx
}
