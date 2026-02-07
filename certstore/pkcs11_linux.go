//go:build linux && cgo

package certstore

import (
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/miekg/pkcs11"
)

type pkcs11State struct {
	ctx *pkcs11.Ctx
}

// p11Identity holds the information needed to sign with a hardware token.
type p11Identity struct {
	ctx     *pkcs11.Ctx
	session pkcs11.SessionHandle
	cert    pkcs11.ObjectHandle
}

func initPKCS11(s *memStore) error {
	modulePath := os.Getenv("SMIMESIGN_PKCS11_MODULE")
	if modulePath == "" {
		return nil
	}

	pin := os.Getenv("SMIMESIGN_PKCS11_PIN")
	p11ctx := pkcs11.New(modulePath)
	if err := p11ctx.Initialize(); err != nil {
		return fmt.Errorf("failed to initialize PKCS#11 module %q: %w", modulePath, err)
	}

	slots, err := p11ctx.GetSlotList(true)
	if err != nil {
		p11ctx.Destroy()
		p11ctx.Finalize()
		return fmt.Errorf("failed to get PKCS#11 slot list: %w", err)
	}

	for _, slot := range slots {
		session, err := p11ctx.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION)
		if err != nil {
			p11ctx.Destroy()
			p11ctx.Finalize()
			return fmt.Errorf("failed to open PKCS#11 session for slot %d: %w", slot, err)
		}
		// Defer closing the session for each slot
		defer p11ctx.CloseSession(session)

		// The PIN is required to view objects on the token
		if err := p11ctx.Login(session, pkcs11.CKU_USER, pin); err != nil {
			var pkcs11Error pkcs11.Error
			if errors.As(err, &pkcs11Error) && pkcs11Error == pkcs11.CKR_USER_NOT_LOGGED_IN {
				// Some tokens don't require a PIN, or the user might have already logged in.
				// Continue without returning an error for this specific case.
				fmt.Fprintf(os.Stderr, "Warning: PKCS#11 login for slot %d failed with CKR_USER_NOT_LOGGED_IN. Continuing without PIN for this slot.\n", slot)
			} else {
				p11ctx.Destroy()
				p11ctx.Finalize()
				return fmt.Errorf("failed to log in to PKCS#11 slot %d: %w", slot, err)
			}
		}

		// Find all certificates
		if err := p11ctx.FindObjectsInit(session, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE),
		}); err != nil {
			p11ctx.Destroy()
			p11ctx.Finalize()
			return fmt.Errorf("failed to initialize PKCS#11 object search: %w", err)
		}
		obj, _, err := p11ctx.FindObjects(session, 100) // Read up to 100 objects
		if err != nil {
			p11ctx.Destroy()
			p11ctx.Finalize()
			return fmt.Errorf("failed to find PKCS#11 objects: %w", err)
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

	s.p11 = &pkcs11State{ctx: p11ctx}
	return nil
}

func closePKCS11(s *memStore) {
	if s.p11 == nil || s.p11.ctx == nil {
		return
	}
	s.p11.ctx.Destroy()
	s.p11.ctx.Finalize()
	s.p11 = nil
}

// p11Signer implements crypto.Signer for a hardware token.
type p11Signer struct {
	ctx  *pkcs11.Ctx
	sess pkcs11.SessionHandle
	priv pkcs11.ObjectHandle
	pub  crypto.PublicKey
	mech []*pkcs11.Mechanism
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
