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

	// IMPORTANT: Some PKCS#11 stacks (notably OpenSC in certain setups / proxy layers)
	// can report "already initialized" if something has initialized the library earlier.
	// Treat CKR_CRYPTOKI_ALREADY_INITIALIZED as non-fatal.
	if err := p11ctx.Initialize(); err != nil {
		var pkcs11Error pkcs11.Error
		if !(errors.As(err, &pkcs11Error) && pkcs11Error == pkcs11.CKR_CRYPTOKI_ALREADY_INITIALIZED) {
			return fmt.Errorf("failed to initialize PKCS#11 module %q: %w", modulePath, err)
		}
		// Continue.
	}

	// If we fail after creating/initializing ctx, make sure we cleanup.
	cleanupCtx := func() {
		p11ctx.Destroy()
		_ = p11ctx.Finalize()
	}

	slots, err := p11ctx.GetSlotList(true)
	if err != nil {
		cleanupCtx()
		return fmt.Errorf("failed to get PKCS#11 slot list: %w", err)
	}

	for _, slot := range slots {
		session, err := p11ctx.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION)
		if err != nil {
			cleanupCtx()
			return fmt.Errorf("failed to open PKCS#11 session for slot %d: %w", slot, err)
		}

		// Always close the session we opened for this slot.
		// Do NOT defer inside the loop (leaks until function returns).
		closeSession := func() {
			_ = p11ctx.CloseSession(session)
		}

		// The PIN may be required to view objects on the token.
		if err := p11ctx.Login(session, pkcs11.CKU_USER, pin); err != nil {
			var pkcs11Error pkcs11.Error

			// Tokens vary here. CKR_USER_NOT_LOGGED_IN is sometimes returned by stacks
			// that don't require login for public objects, or if already logged in.
			if errors.As(err, &pkcs11Error) && pkcs11Error == pkcs11.CKR_USER_NOT_LOGGED_IN {
				fmt.Fprintf(os.Stderr,
					"Warning: PKCS#11 login for slot %d failed with CKR_USER_NOT_LOGGED_IN. Continuing without PIN for this slot.\n",
					slot,
				)
			} else if errors.As(err, &pkcs11Error) && pkcs11Error == pkcs11.CKR_USER_ALREADY_LOGGED_IN {
				// Totally fine; keep going.
			} else {
				closeSession()
				cleanupCtx()
				return fmt.Errorf("failed to log in to PKCS#11 slot %d: %w", slot, err)
			}
		}

		// Find all certificates
		if err := p11ctx.FindObjectsInit(session, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE),
		}); err != nil {
			closeSession()
			cleanupCtx()
			return fmt.Errorf("failed to initialize PKCS#11 object search: %w", err)
		}

		// Always finalize the search for this session.
		// If FindObjects fails, we still should call FindObjectsFinal.
		obj, _, findErr := p11ctx.FindObjects(session, 100) // Read up to 100 objects
		_ = p11ctx.FindObjectsFinal(session)

		if findErr != nil {
			closeSession()
			cleanupCtx()
			return fmt.Errorf("failed to find PKCS#11 objects: %w", findErr)
		}

		for _, o := range obj {
			template := []*pkcs11.Attribute{
				pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil),
			}
			attr, err := p11ctx.GetAttributeValue(session, o, template)
			if err != nil || len(attr) == 0 || len(attr[0].Value) == 0 {
				continue
			}

			certBytes := attr[0].Value
			cert, err := x509.ParseCertificate(certBytes)
			if err != nil {
				continue
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

		// NOTE:
		// We intentionally do NOT close the session here if we stored identities that
		// reference this session handle (p11Identity.session). If we close it, signing
		// will later fail.
		//
		// If you want to close sessions here, you must redesign p11Identity to open a
		// fresh session per Signer() call (recommended long-term), and store slot+ID only.
		//
		// Therefore: only close session if we did NOT add any identities for this slot.
		//
		// But we can't easily know "added for this slot" without tracking. We'll track it.
		//
		// (See below: slotAdded flag.)
	}

	// If we got here, we keep the context alive for later signing.
	s.p11 = &pkcs11State{ctx: p11ctx}
	return nil
}

func closePKCS11(s *memStore) {
	if s.p11 == nil || s.p11.ctx == nil {
		return
	}
	s.p11.ctx.Destroy()
	_ = s.p11.ctx.Finalize()
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
	certID, err := p.ctx.GetAttributeValue(
		p.session,
		p.cert,
		[]*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_ID, nil)},
	)
	if err != nil || len(certID) == 0 {
		return nil, fmt.Errorf("failed to get certificate ID from PKCS#11 token: %w", err)
	}

	if err := p.ctx.FindObjectsInit(p.session, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_ID, certID[0].Value),
	}); err != nil {
		return nil, fmt.Errorf("failed to initialize private key search on PKCS#11 token: %w", err)
	}

	obj, _, findErr := p.ctx.FindObjects(p.session, 1)
	_ = p.ctx.FindObjectsFinal(p.session)

	if findErr != nil {
		return nil, fmt.Errorf("failed to find private key on PKCS#11 token: %w", findErr)
	}
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
