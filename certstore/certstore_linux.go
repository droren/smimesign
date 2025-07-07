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

	"github.com/miekg/pkcs11"
)

// memStore implements an in-memory certificate store for Linux.
type memStore struct {
	idents []*memIdentity
	p11ctx *pkcs11.Ctx
}

// openStore opens a memory backed certificate store. If the environment
// variable SMIMESIGN_P12 is set, the referenced PKCS#12 file will be loaded
// automatically.
func openStore() (Store, error) {
	s := &memStore{}

	if modulePath := os.Getenv("SMIMESIGN_PKCS11_MODULE"); modulePath != "" {
		pin := os.Getenv("SMIMESIGN_PKCS11_PIN")
		p11ctx := pkcs11.New(modulePath)
		if err := p11ctx.Initialize(); err != nil {
			return nil, fmt.Errorf("failed to initialize PKCS#11 module %q: %w", modulePath, err)
		}

		slots, err := p11ctx.GetSlotList(true)
		if err != nil {
			return nil, fmt.Errorf("failed to get PKCS#11 slot list: %w", err)
		}

		for _, slot := range slots {
			// The PIN is required to view objects on the token
			if err := p11ctx.Login(slot, pin); err != nil {
				// Some tokens don't require a PIN
				if err != pkcs11.CKR_USER_NOT_LOGGED_IN {
					p11ctx.Destroy()
					p11ctx.Finalize()
					return nil, fmt.Errorf("failed to log in to PKCS#11 slot: %w", err)
				}
			}

			session, err := p11ctx.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION)
			if err != nil {
				p11ctx.Destroy()
				p11ctx.Finalize()
				return nil, fmt.Errorf("failed to open PKCS#11 session: %w", err)
			}

			// Find all certificates
			if err := p11ctx.FindObjectsInit(session, []*pkcs11.Attribute{
				pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE),
			}); err != nil {
				p11ctx.Destroy()
				p11ctx.Finalize()
				return nil, fmt.Errorf("failed to initialize PKCS#11 object search: %w", err)
			}
			obj, _, err := p11ctx.FindObjects(session, 100) // Read up to 100 objects
			if err != nil {
				p11ctx.Destroy()
				p11ctx.Finalize()
				return nil, fmt.Errorf("failed to find PKCS#11 objects: %w", err)
			}
			p11ctx.FindObjectsFinal(session)

			for _, o := range obj {
				template := []*pkcs11.Attribute{
					pkcs11.NewAttribute(pkcs11.CKA_VALUE, 0),
				}
				attr, err := p11ctx.GetAttributeValue(session, o, template)
				if err != nil {
					continue // Skip if certificate value cannot be retrieved
				}

				certBytes := attr[0].Value
				cert, err := x509.ParseCertificate(certBytes)
				if err != nil {
					continue // Skip if certificate cannot be parsed
				}

				s.idents = append(s.idents, &memIdentity{
					store: s,
					cert:  cert,
					p11: &p11Identity{
						ctx:     p11ctx,
						session: session,
						cert:    o,
					},
				})
			}
			p11ctx.CloseSession(session)
		}
		s.p11ctx = p11ctx
	}

	if path := os.Getenv("SMIMESIGN_P12"); path != "" {
		password := os.Getenv("SMIMESIGN_P12_PASSWORD")
		data, err := os.ReadFile(path)
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
	if s.p11ctx != nil {
		s.p11ctx.Destroy()
		s.p11ctx.Finalize()
	}
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

// p11Identity holds the information needed to sign with a hardware token.
type p11Identity struct {
	ctx     *pkcs11.Ctx
	session pkcs11.SessionHandle
	cert    pkcs11.ObjectHandle
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

// p11Signer implements crypto.Signer for a hardware token.
type p11Signer struct {
	ctx    *pkcs11.Ctx
	sess   pkcs11.SessionHandle
	priv   pkcs11.ObjectHandle
	pub    crypto.PublicKey
	mech   []*pkcs11.Mechanism
}

func (s *p11Signer) Public() crypto.PublicKey {
	return s.pub
}

func (s *p11Signer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if err := s.ctx.SignInit(s.sess, s.mech, s.priv); err != nil {
		return nil, fmt.Errorf("PKCS#11 signing initialization failed: %w", err)
	}
	return s.ctx.Sign(s.sess, digest)
}

// Signer returns a crypto.Signer that uses the private key on the hardware token.
func (p *p11Identity) Signer(cert *x509.Certificate) (crypto.Signer, error) {
	// Find the private key that corresponds to the certificate
	certID, err := p.ctx.GetAttributeValue(p.session, p.cert, []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_ID, nil)})
	if err != nil {
		return nil, fmt.Errorf("failed to get certificate ID from PKCS#11 token: %w", err)
	}
	if err := p.ctx.FindObjectsInit(p.session, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_ID, certID[0].Value),
	}); err != nil {
		return nil, fmt.Errorf("failed to initialize private key search on PKCS#11 token: %w", err)
	}
	obj, _, err := p.ctx.FindObjects(p.session, 1)
	if err != nil {
		return nil, fmt.Errorf("failed to find private key on PKCS#11 token: %w", err)
	}
	p.ctx.FindObjectsFinal(p.session)

	if len(obj) == 0 {
		return nil, errors.New("no corresponding private key found on PKCS#11 token")
	}
	privKey := obj[0]

	var mech []*pkcs11.Mechanism
	switch cert.PublicKeyAlgorithm {
	case x509.RSA:
		mech = []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)}
	case x509.ECDSA:
		mech = []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil)}
	default:
		return nil, fmt.Errorf("unsupported public key algorithm for PKCS#11 signing: %s", cert.PublicKeyAlgorithm.String())
	}

	return &p11Signer{
		ctx:  p.ctx,
		sess: p.session,
		priv: privKey,
		pub:  cert.PublicKey,
		mech: mech,
	}, nil
}

// parsePKCS12 uses the openssl command to decode PKCS#12 data since the
// standard library does not support all variants used by OpenSSL.
func parsePKCS12(data []byte, password string) (interface{}, *x509.Certificate, []*x509.Certificate, error) {
	passin := fmt.Sprintf("pass:%s", password)
	cmd := exec.Command("openssl", "pkcs12", "-nodes", "-passin", passin)
	cmd.Stdin = bytes.NewReader(data)
	out, err := cmd.Output()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to execute openssl command for PKCS#12 parsing: %w", err)
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