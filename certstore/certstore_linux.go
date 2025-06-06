package certstore

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
)

// memStore implements an in-memory certificate store for Linux.
type memStore struct {
	idents []*memIdentity
}

// openStore opens a memory backed certificate store. If the environment
// variable SMIMESIGN_P12 is set, the referenced PKCS#12 file will be loaded
// automatically.
func openStore() (Store, error) {
	s := &memStore{}

	if path := os.Getenv("SMIMESIGN_P12"); path != "" {
		password := os.Getenv("SMIMESIGN_P12_PASSWORD")
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		if err := s.Import(data, password); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// Identities implements the Store interface.
func (s *memStore) Identities() ([]Identity, error) {
	var out []Identity
	for _, id := range s.idents {
		if !id.deleted {
			out = append(out, id)
		}
	}
	return out, nil
}

// Import implements the Store interface.
func (s *memStore) Import(data []byte, password string) error {
	priv, cert, chain, err := parsePKCS12(data, password)
	if err != nil {
		return err
	}

	id := &memIdentity{
		store: s,
		priv:  priv,
		cert:  cert,
		chain: chain,
	}
	s.idents = append(s.idents, id)
	return nil
}

// Close implements the Store interface.
func (s *memStore) Close() {}

// memIdentity implements the Identity interface for memStore.
type memIdentity struct {
	store   *memStore
	priv    interface{}
	cert    *x509.Certificate
	chain   []*x509.Certificate
	deleted bool
}

// memSigner wraps a crypto.Signer and adds basic hash checking similar to the
// platform implementations.
type memSigner struct {
	priv crypto.Signer
}

func (s *memSigner) Public() crypto.PublicKey { return s.priv.Public() }

func (s *memSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	hash := opts.HashFunc()
	if hash != 0 && len(digest) != hash.Size() {
		return nil, errors.New("bad digest for hash")
	}

	switch pk := s.priv.(type) {
	case *rsa.PrivateKey:
		switch hash {
		case crypto.SHA1, crypto.SHA256, crypto.SHA384, crypto.SHA512:
			return rsa.SignPKCS1v15(rand, pk, hash, digest)
		default:
			return nil, ErrUnsupportedHash
		}
	case *ecdsa.PrivateKey:
		switch hash {
		case crypto.SHA1, crypto.SHA256, crypto.SHA384, crypto.SHA512:
			return ecdsa.SignASN1(rand, pk, digest)
		default:
			return nil, ErrUnsupportedHash
		}
	default:
		return nil, errors.New("unsupported key type")
	}
}

// Certificate implements the Identity interface.
func (i *memIdentity) Certificate() (*x509.Certificate, error) {
	return i.cert, nil
}

// CertificateChain implements the Identity interface.
func (i *memIdentity) CertificateChain() ([]*x509.Certificate, error) {
	return i.chain, nil
}

// Signer implements the Identity interface.
func (i *memIdentity) Signer() (crypto.Signer, error) {
	signer, ok := i.priv.(crypto.Signer)
	if !ok {
		return nil, errors.New("private key is not a crypto.Signer")
	}
	return &memSigner{signer}, nil
}

// Delete implements the Identity interface.
func (i *memIdentity) Delete() error {
	i.deleted = true
	return nil
}

// Close implements the Identity interface.
func (i *memIdentity) Close() {}

// parsePKCS12 uses the openssl command to decode PKCS#12 data since the
// standard library does not support all variants used by OpenSSL.
func parsePKCS12(data []byte, password string) (interface{}, *x509.Certificate, []*x509.Certificate, error) {
	passin := fmt.Sprintf("pass:%s", password)
	cmd := exec.Command("openssl", "pkcs12", "-nodes", "-passin", passin)
	cmd.Stdin = bytes.NewReader(data)
	out, err := cmd.Output()
	if err != nil {
		return nil, nil, nil, err
	}

	var (
		block *pem.Block
		rest  = out
		key   interface{}
		certs []*x509.Certificate
	)

	for {
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		switch block.Type {
		case "PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY":
			if pk, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
				key = pk
			} else if pk, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
				key = pk
			} else if pk, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
				key = pk
			}
		case "CERTIFICATE":
			if c, err := x509.ParseCertificate(block.Bytes); err == nil {
				certs = append(certs, c)
			}
		}
	}

	if len(certs) == 0 || key == nil {
		return nil, nil, nil, errors.New("failed to parse pkcs12 data")
	}

	return key, certs[0], certs, nil
}
