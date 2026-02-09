//go:build linux && cgo

package certstore

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"

	"github.com/miekg/pkcs11"
	"golang.org/x/term"
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

	// Explicit opt-in only. If unset, we prompt via pinentry/tty.
	envPin := os.Getenv("SMIMESIGN_PKCS11_PIN")

	p11ctx := pkcs11.New(modulePath)

	// IMPORTANT: Some PKCS#11 stacks can report "already initialized".
	// Treat CKR_CRYPTOKI_ALREADY_INITIALIZED as non-fatal.
	if err := p11ctx.Initialize(); err != nil {
		var pkcs11Error pkcs11.Error
		if !(errors.As(err, &pkcs11Error) && pkcs11Error == pkcs11.CKR_CRYPTOKI_ALREADY_INITIALIZED) {
			return fmt.Errorf("failed to initialize PKCS#11 module %q: %w", modulePath, err)
		}
	}

	cleanupCtx := func() {
		p11ctx.Destroy()
		_ = p11ctx.Finalize()
	}

	slots, err := p11ctx.GetSlotList(true)
	if err != nil {
		cleanupCtx()
		return fmt.Errorf("failed to get PKCS#11 slot list: %w", err)
	}

	// Cache a prompted PIN once per process run (unless env pin is set).
	// This avoids prompting twice if you have multiple slots/tokens.
	pinCache := newPinCache(envPin)

	for _, slot := range slots {
		session, err := p11ctx.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION)
		if err != nil {
			cleanupCtx()
			return fmt.Errorf("failed to open PKCS#11 session for slot %d: %w", slot, err)
		}

		// If this slot yields no identities, we close it.
		// If it yields identities, we keep it open because p11Identity stores session handle.
		addedBefore := len(s.idents)

		// Attempt login if required; prompt only if needed.
		if err := loginWithSmartFallbacks(p11ctx, session, slot, pinCache); err != nil {
			_ = p11ctx.CloseSession(session)
			cleanupCtx()
			return err
		}

		// Find all certificates
		if err := p11ctx.FindObjectsInit(session, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE),
		}); err != nil {
			_ = p11ctx.CloseSession(session)
			cleanupCtx()
			return fmt.Errorf("failed to initialize PKCS#11 object search: %w", err)
		}

		obj, _, findErr := p11ctx.FindObjects(session, 100)
		_ = p11ctx.FindObjectsFinal(session)
		if findErr != nil {
			_ = p11ctx.CloseSession(session)
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

			cert, err := x509.ParseCertificate(attr[0].Value)
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

		// Close session only if it didn't produce identities.
		if len(s.idents) == addedBefore {
			_ = p11ctx.CloseSession(session)
		}
	}

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

// ---------- PIN prompting with Linux-native fallbacks ----------

type pinCache struct {
	// If envPin is set, we always use it (explicit opt-in).
	envPin string

	mu   sync.Mutex
	pin  string
	have bool
}

func newPinCache(envPin string) *pinCache {
	return &pinCache{envPin: envPin}
}

func (c *pinCache) get() (string, bool) {
	if c.envPin != "" {
		return c.envPin, true
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.have {
		return c.pin, true
	}
	return "", false
}

func (c *pinCache) set(pin string) {
	if c.envPin != "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pin = pin
	c.have = true
}

func isPinRelatedError(err error) bool {
	var e pkcs11.Error
	if !errors.As(err, &e) {
		return false
	}
	switch e {
	case pkcs11.CKR_PIN_INCORRECT,
		pkcs11.CKR_PIN_INVALID,
		pkcs11.CKR_PIN_LEN_RANGE,
		pkcs11.CKR_PIN_EXPIRED,
		pkcs11.CKR_PIN_LOCKED,
		pkcs11.CKR_USER_NOT_LOGGED_IN:
		return true
	default:
		return false
	}
}

func isAlreadyLoggedIn(err error) bool {
	var e pkcs11.Error
	return errors.As(err, &e) && e == pkcs11.CKR_USER_ALREADY_LOGGED_IN
}

func loginWithSmartFallbacks(ctx *pkcs11.Ctx, session pkcs11.SessionHandle, slot uint, cache *pinCache) error {
	// First: if we already have a PIN (env or cached), try it.
	if pin, ok := cache.get(); ok {
		if err := ctx.Login(session, pkcs11.CKU_USER, pin); err != nil {
			if isAlreadyLoggedIn(err) {
				return nil
			}
			// If env pin is wrong, fail fast; user explicitly opted into env pin.
			if cache.envPin != "" {
				return fmt.Errorf("failed to log in to PKCS#11 slot %d with SMIMESIGN_PKCS11_PIN: %w", slot, err)
			}
			// Cached pin might be wrong for a different token/slot; drop it and prompt.
			cache.set("") // keep have=true? no, we want to reprompt; easiest is reset manually below.
			cache.mu.Lock()
			cache.have = false
			cache.pin = ""
			cache.mu.Unlock()
		} else {
			return nil
		}
	}

	// Next: try login with empty pin (some tokens allow listing without PIN).
	if err := ctx.Login(session, pkcs11.CKU_USER, ""); err == nil || isAlreadyLoggedIn(err) {
		return nil
	} else if !isPinRelatedError(err) {
		// Non-pin error: might still be ok for public objects; keep your original behavior for CKR_USER_NOT_LOGGED_IN.
		var e pkcs11.Error
		if errors.As(err, &e) && e == pkcs11.CKR_USER_NOT_LOGGED_IN {
			fmt.Fprintf(os.Stderr, "Warning: PKCS#11 login for slot %d failed with CKR_USER_NOT_LOGGED_IN. Continuing without PIN for this slot.\n", slot)
			return nil
		}
		return fmt.Errorf("failed to log in to PKCS#11 slot %d: %w", slot, err)
	}

	// PIN required: prompt using pinentry (preferred), then tty.
	// Allow a couple retries for mistypes.
	const maxTries = 3
	for i := 1; i <= maxTries; i++ {
		pin, err := promptForPIN(fmt.Sprintf("Smartcard PIN (slot %d)", slot))
		if err != nil {
			return fmt.Errorf("failed to prompt for PKCS#11 PIN: %w", err)
		}

		if err := ctx.Login(session, pkcs11.CKU_USER, pin); err != nil {
			if isAlreadyLoggedIn(err) {
				cache.set(pin)
				return nil
			}
			if isPinRelatedError(err) {
				if i < maxTries {
					fmt.Fprintf(os.Stderr, "PIN rejected for slot %d (attempt %d/%d). Try again.\n", slot, i, maxTries)
					continue
				}
			}
			return fmt.Errorf("failed to log in to PKCS#11 slot %d: %w", slot, err)
		}

		cache.set(pin)
		return nil
	}

	return fmt.Errorf("failed to log in to PKCS#11 slot %d: PIN rejected", slot)
}

func promptForPIN(title string) (string, error) {
	// 1) pinentry (best UX; GUI if available, curses otherwise)
	if pin, ok, err := tryPinentry(title); err != nil {
		return "", err
	} else if ok {
		return pin, nil
	}

	// 2) /dev/tty prompt (reliable for CLI)
	if pin, ok, err := tryTTYPrompt(title + ": "); err != nil {
		return "", err
	} else if ok {
		return pin, nil
	}

	// 3) No env fallback here (env handled earlier explicitly).
	return "", errors.New("no available PIN prompt method (pinentry not found and no TTY available)")
}

func tryTTYPrompt(prompt string) (string, bool, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return "", false, nil // no TTY, not fatal here
	}
	defer tty.Close()

	if _, err := fmt.Fprint(tty, prompt); err != nil {
		return "", false, err
	}

	b, err := term.ReadPassword(int(tty.Fd()))
	if _, _ = fmt.Fprintln(tty)
	if err != nil {
		return "", false, err
	}
	return strings.TrimSpace(string(b)), true, nil
}

func tryPinentry(title string) (string, bool, error) {
	path, ok := findPinentry()
	if !ok {
		return "", false, nil
	}

	// pinentry protocol is line-based. We talk over stdin/stdout.
	cmd := exec.Command(path)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return "", false, err
	}

	if err := cmd.Start(); err != nil {
		return "", false, err
	}

	// Helper to send a command line.
	send := func(s string) error {
		_, err := io.WriteString(stdin, s+"\n")
		return err
	}

	// Read pinentry responses.
	rd := bufio.NewScanner(&stdout)

	// pinentry starts with an "OK ..." greeting, but stdout is buffered.
	// We'll just proceed; if it fails, we'll detect non-OK lines later.
	_ = send("OPTION ttyname=/dev/tty") // helps some pinentry variants
	_ = send("SETPROMPT " + escapePinentry("PIN:"))
	_ = send("SETTITLE " + escapePinentry(title))
	_ = send("SETDESC " + escapePinentry("Enter your smartcard PIN."))

	if err := send("GETPIN"); err != nil {
		_ = stdin.Close()
		_ = cmd.Wait()
		return "", false, err
	}

	// Close stdin so pinentry can exit cleanly after BYE.
	defer func() { _ = send("BYE"); _ = stdin.Close() }()

	// Parse responses:
	// - "D <pin>" carries the PIN
	// - "OK" acknowledges
	// - "ERR <code> ..." indicates cancel/failure
	var pin string
	for rd.Scan() {
		line := rd.Text()
		if strings.HasPrefix(line, "D ") {
			pin = strings.TrimSpace(strings.TrimPrefix(line, "D "))
			continue
		}
		if strings.HasPrefix(line, "ERR ") {
			// User likely cancelled, or pinentry couldn't show UI.
			_ = cmd.Wait()
			return "", false, nil
		}
		// Stop after OK following GETPIN exchange if we already got D line.
		if line == "OK" && pin != "" {
			break
		}
	}

	_ = cmd.Wait()

	if pin == "" {
		// If pinentry exists but doesn't give us a PIN, treat as "not usable" and fallback.
		// stderr might contain useful clues for debugging.
		return "", false, nil
	}
	return pin, true, nil
}

func escapePinentry(s string) string {
	// pinentry supports basic text; avoid newlines/tabs.
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\t", " ")
	return s
}

func findPinentry() (string, bool) {
	// Let user override pinentry binary name/path if they want.
	if p := os.Getenv("PINENTRY"); p != "" {
		if lp, err := exec.LookPath(p); err == nil {
			return lp, true
		}
		// If they set it but it's wrong, treat as hard failure (it was explicit).
		return "", false
	}

	// Common names. We do NOT require GUI vars; pinentry-curses works fine in terminals.
	candidates := []string{
		"pinentry",
		"pinentry-gtk-2",
		"pinentry-gnome3",
		"pinentry-qt",
		"pinentry-qt5",
		"pinentry-curses",
		"pinentry-tty",
	}

	for _, c := range candidates {
		if lp, err := exec.LookPath(c); err == nil {
			return lp, true
		}
	}
	return "", false
}

// ---------- Signing implementation ----------

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
