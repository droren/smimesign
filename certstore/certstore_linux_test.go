package certstore

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"os"
	"testing"
)

// TestPKCS11Signer tests the PKCS#11 signer implementation.
// This test requires a PKCS#11 module to be configured via environment variables:
// SMIMESIGN_PKCS11_MODULE and SMIMESIGN_PKCS11_PIN.
// If these are not set, the test will be skipped.
func TestPKCS11Signer(t *testing.T) {
	modulePath := os.Getenv("SMIMESIGN_PKCS11_MODULE")
	pin := os.Getenv("SMIMESIGN_PKCS11_PIN")

	if modulePath == "" || pin == "" {
		t.Skip("SMIMESIGN_PKCS11_MODULE or SMIMESIGN_PKCS11_PIN not set. Skipping PKCS#11 tests.")
	}

	store, err := Open()
	if err != nil {
		t.Fatalf("failed to open certstore: %v", err)
	}
	defer store.Close()

	idents, err := store.Identities()
	if err != nil {
		t.Fatalf("failed to get identities: %v", err)
	}

	if len(idents) == 0 {
		t.Skip("No PKCS#11 identities found. Skipping PKCS#11 tests.")
	}

	// Find a PKCS#11 identity
	var p11Ident Identity
	for _, ident := range idents {
		if mi, ok := ident.(*memIdentity); ok && mi.p11 != nil {
			p11Ident = ident
			break
		}
	}

	if p11Ident == nil {
		t.Skip("No PKCS#11 identity found in the store. Skipping PKCS#11 tests.")
	}

	cert, err := p11Ident.Certificate()
	if err != nil {
		t.Fatalf("failed to get certificate from PKCS#11 identity: %v", err)
	}

	signer, err := p11Ident.Signer()
	if err != nil {
		t.Fatalf("failed to get signer from PKCS#11 identity: %v", err)
	}

	// Test signing with SHA256
	message := []byte("test message")
	digest := crypto.SHA256.New()
	digest.Write(message)
	hashed := digest.Sum(nil)

	sig, err := signer.Sign(rand.Reader, hashed, crypto.SHA256)
	if err != nil {
		t.Fatalf("failed to sign with PKCS#11 signer: %v", err)
	}

	// Verify the signature
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		err = rsa.VerifyPKCS1v15(pub, crypto.SHA256, hashed, sig)
	case *ecdsa.PublicKey:
		err = ecdsa.VerifyASN1(pub, hashed, sig)
	default:
		t.Fatalf("unsupported public key type: %T", pub)
	}

	if err != nil {
		t.Fatalf("signature verification failed: %v", err)
	}
}

// TestPKCS11ListIdentities tests listing PKCS#11 identities.
// This test requires a PKCS#11 module to be configured via environment variables:
// SMIMESIGN_PKCS11_MODULE and SMIMESIGN_PKCS11_PIN.
// If these are not set, the test will be skipped.
func TestPKCS11ListIdentities(t *testing.T) {
	modulePath := os.Getenv("SMIMESIGN_PKCS11_MODULE")
	pin := os.Getenv("SMIMESIGN_PKCS11_PIN")

	if modulePath == "" || pin == "" {
		t.Skip("SMIMESIGN_PKCS11_MODULE or SMIMESIGN_PKCS11_PIN not set. Skipping PKCS#11 tests.")
	}

	store, err := Open()
	if err != nil {
		t.Fatalf("failed to open certstore: %v", err)
	}
	defer store.Close()

	idents, err := store.Identities()
	if err != nil {
		t.Fatalf("failed to get identities: %v", err)
	}

	if len(idents) == 0 {
		t.Skip("No PKCS#11 identities found. Skipping PKCS#11 tests.")
	}

	// Check if at least one PKCS#11 identity is found
	foundPKCS11 := false
	for _, ident := range idents {
		if mi, ok := ident.(*memIdentity); ok && mi.p11 != nil {
			foundPKCS11 = true
			break
		}
	}

	if !foundPKCS11 {
		t.Fatalf("expected to find at least one PKCS#11 identity, but found none")
	}
}
