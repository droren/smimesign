//go:build darwin && cgo

package cms

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/github/smimesign/fakeca"
)

// Embedded chains are untrusted input, not additional trust anchors.
func TestDarwinRejectsEmbeddedUntrustedRoot(t *testing.T) {
	root := fakeca.New(fakeca.IsCA)
	leaf := root.Issue()
	sd, err := NewSignedData([]byte("untrusted native chain"))
	if err != nil {
		t.Fatal(err)
	}
	if err := sd.Sign([]*x509.Certificate{leaf.Certificate, root.Certificate}, leaf.PrivateKey); err != nil {
		t.Fatal(err)
	}
	opts := x509.VerifyOptions{KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}
	if _, err := sd.Verify(opts); err == nil {
		t.Fatal("embedded root was promoted to trust anchor")
	}
	// A caller may intentionally add a private CA to the opaque system pool.
	// Such a pool must not compare equal to the unmodified system marker.
	roots, err := x509.SystemCertPool()
	if err != nil {
		t.Fatal(err)
	}
	roots.AddCert(root.Certificate)
	opts.Roots = roots
	if _, err := sd.Verify(opts); err != nil {
		t.Fatalf("explicit additional root ignored: %v", err)
	}
}

// Opt-in integration test: a real detached signature whose signer chains to a
// locally trusted CA. No private keys or machine-specific certificates in git.
func TestDarwinSystemTrustCodeSigning(t *testing.T) {
	dir := os.Getenv("SMIMESIGN_TEST_SIGNED_FIXTURE_DIR")
	if dir == "" {
		t.Skip("set SMIMESIGN_TEST_SIGNED_FIXTURE_DIR for the native trust regression")
	}
	sig, err := os.ReadFile(filepath.Join(dir, "commit-signature.der"))
	if err != nil {
		t.Fatal(err)
	}
	msg, err := os.ReadFile(filepath.Join(dir, "commit-payload.txt"))
	if err != nil {
		t.Fatal(err)
	}
	sd, err := ParseSignedData(sig)
	if err != nil {
		t.Fatal(err)
	}
	roots, err := x509.SystemCertPool()
	if err != nil {
		t.Fatal(err)
	}
	opts := x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}
	chains, err := sd.VerifyDetached(msg, opts)
	if err != nil {
		t.Fatalf("code-signing certificate must not be evaluated as TLS: %v", err)
	}
	if len(chains) != 1 || len(chains[0]) == 0 || len(chains[0][0]) < 2 {
		t.Fatal("missing trusted signer chain")
	}
	if _, err := sd.VerifyDetached(append(msg, 'x'), opts); err == nil {
		t.Fatal("tampered message accepted")
	}
	base := opts
	for _, when := range []time.Time{chains[0][0][0].NotBefore.Add(-time.Hour), chains[0][0][0].NotAfter.Add(time.Hour)} {
		opts.CurrentTime = when
		if _, err := sd.VerifyDetached(msg, opts); err == nil {
			t.Fatal("certificate outside its validity window accepted")
		}
	}
	opts = base
	opts.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping}
	if _, err := sd.VerifyDetached(msg, opts); err == nil {
		t.Fatal("code-signing certificate accepted as timestamp authority")
	}
	opts = base
	opts.Roots = nil
	if _, err := sd.VerifyDetached(msg, opts); err != nil {
		t.Fatalf("nil roots must use native trust: %v", err)
	}
	opts.Roots = x509.NewCertPool()
	if _, err := sd.VerifyDetached(msg, opts); err == nil {
		t.Fatal("explicit empty trust store must not fall back to system trust")
	}
}
