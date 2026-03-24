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

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// memStore implements an in-memory certificate store for Linux.
type memStore struct {
	idents []*memIdentity
	p11    *pkcs11State
}

// openStore opens a memory backed certificate store. If the environment
// variable SMIMESIGN_P12 is set, the referenced PKCS#12 file will be loaded
// automatically.
func openStore() (Store, error) {
	s := &memStore{}

	if err := initPKCS11(s); err != nil {
		return nil, err
	}

	if path := os.Getenv("SMIMESIGN_P12"); path != "" {
		password := os.Getenv("SMIMESIGN_P12_PASSWORD")
		data, err := os.ReadFile(path) // #nosec G304,G703 -- path is intentionally user-configurable via SMIMESIGN_P12.
		if err != nil {
			return nil, fmt.Errorf("failed to read PKCS#12 file %q: %w", path, err)
		}
		if err := s.Import(data, password); err != nil {
			return nil, fmt.Errorf("failed to import PKCS#12 data from %q: %w", path, err)
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
func (s *memStore) Close() {
	closePKCS11(s)
}

// memIdentity implements the Identity interface for memStore.
type memIdentity struct {
	store   *memStore
	priv    interface{}
	cert    *x509.Certificate
	chain   []*x509.Certificate
	deleted bool
	p11     *p11Identity
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
		return nil, fmt.Errorf("invalid digest length for hash algorithm: expected %d, got %d", hash.Size(), len(digest))
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
		return nil, errors.New("unsupported private key type for signing")
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
	if i.p11 != nil {
		return i.p11.Signer(i.cert)
	}
	signer, ok := i.priv.(crypto.Signer)
	if !ok {
		return nil, errors.New("private key does not implement crypto.Signer interface")
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
	if key, cert, chain, err := pkcs12.DecodeChain(data, password); err == nil && key != nil && cert != nil {
		certs := append([]*x509.Certificate{cert}, chain...)
		return key, cert, certs, nil
	}

	passwordReader, passwordWriter, err := os.Pipe()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create password pipe for PKCS#12 parsing: %w", err)
	}
	defer passwordReader.Close()

	cmd := exec.Command("openssl", "pkcs12", "-nodes", "-passin", "fd:3")
	cmd.Stdin = bytes.NewReader(data)
	cmd.ExtraFiles = []*os.File{passwordReader}

	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = new(bytes.Buffer)

	if err := cmd.Start(); err != nil {
		_ = passwordWriter.Close()
		return nil, nil, nil, fmt.Errorf("failed to start openssl command for PKCS#12 parsing: %w", err)
	}

	if _, err := io.WriteString(passwordWriter, password+"\n"); err != nil {
		_ = passwordWriter.Close()
		_ = cmd.Wait()
		return nil, nil, nil, fmt.Errorf("failed to provide password to openssl command for PKCS#12 parsing: %w", err)
	}
	if err := passwordWriter.Close(); err != nil {
		_ = cmd.Wait()
		return nil, nil, nil, fmt.Errorf("failed to close password pipe for PKCS#12 parsing: %w", err)
	}

	if err := cmd.Wait(); err != nil {
		if stderr, ok := cmd.Stderr.(*bytes.Buffer); ok && stderr.Len() > 0 {
			return nil, nil, nil, fmt.Errorf("failed to execute openssl command for PKCS#12 parsing: %v: %s", err, stderr.String())
		}
		return nil, nil, nil, fmt.Errorf("failed to execute openssl command for PKCS#12 parsing: %w", err)
	}

	var (
		block *pem.Block
		rest  = out.Bytes()
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
		return nil, nil, nil, errors.New("PKCS#12 data is incomplete: missing certificate or private key")
	}

	return key, certs[0], certs, nil
}
