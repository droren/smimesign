package main

import (
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/github/smimesign/certstore"
	"github.com/github/smimesign/fakeca"
)

func TestVerifyOptsDoesNotTrustLocalCertsByDefault(t *testing.T) {
	defer testSetup(t, "--verify")()

	self := fakeca.New()
	idents = []certstore.Identity{identity{self}}

	opts, mode := verifyOpts()
	if mode != "none" {
		t.Fatalf("expected default revocation mode none, got %q", mode)
	}

	if _, err := self.Certificate.Verify(opts); err == nil {
		t.Fatal("expected self-signed local certificate to remain untrusted by default")
	}
}

func TestVerifyOptsCanTrustLocalCertsExplicitly(t *testing.T) {
	defer testSetup(t, "--verify")()

	self := fakeca.New()
	idents = []certstore.Identity{identity{self}}
	t.Setenv("SMIMESIGN_TRUST_LOCAL_CERTS", "1")

	opts, _ := verifyOpts()
	if _, err := self.Certificate.Verify(opts); err != nil {
		t.Fatalf("expected self-signed local certificate to verify when SMIMESIGN_TRUST_LOCAL_CERTS=1: %v", err)
	}
}

func TestVerifyOptsRestrictsKeyUsageByDefault(t *testing.T) {
	defer testSetup(t, "--verify")()

	opts, _ := verifyOpts()
	if len(opts.KeyUsages) != 1 || opts.KeyUsages[0] != x509.ExtKeyUsageAny {
		t.Fatalf("expected chain verification to use ExtKeyUsageAny and enforce signer policy separately, got %v", opts.KeyUsages)
	}
}

func TestCertAllowedForCommitSigningAcceptsDocumentSigningOID(t *testing.T) {
	cert := fakeca.New().Certificate
	cert.UnknownExtKeyUsage = []asn1.ObjectIdentifier{oidMSDocumentSigning}
	if !certAllowedForCommitSigning(cert) {
		t.Fatal("expected Microsoft document-signing OID to be accepted for commit signing")
	}
}

func TestCertAllowedForCommitSigningRejectsClientAuthOnly(t *testing.T) {
	cert := fakeca.New().Certificate
	cert.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	if certAllowedForCommitSigning(cert) {
		t.Fatal("expected client-auth-only certificate to be rejected for commit signing")
	}
}

func TestVerifyOptsCanAllowAnyEKUExplicitly(t *testing.T) {
	defer testSetup(t, "--verify")()

	t.Setenv("SMIMESIGN_ALLOW_ANY_EKU", "1")
	opts, _ := verifyOpts()
	if len(opts.KeyUsages) != 1 || opts.KeyUsages[0] != x509.ExtKeyUsageAny {
		t.Fatalf("expected ExtKeyUsageAny when explicitly enabled, got %v", opts.KeyUsages)
	}
}

func TestVerifyOptsCanEnableOCSPRevocation(t *testing.T) {
	defer testSetup(t, "--verify")()

	t.Setenv("SMIMESIGN_REVOCATION_CHECK", "ocsp")
	_, mode := verifyOpts()
	if mode != "ocsp" {
		t.Fatalf("expected ocsp revocation mode, got %q", mode)
	}
}

func TestVerifyOptsCanEnableSoftOCSPRevocation(t *testing.T) {
	defer testSetup(t, "--verify")()

	t.Setenv("SMIMESIGN_REVOCATION_CHECK", "ocsp-soft")
	_, mode := verifyOpts()
	if mode != "ocsp-soft" {
		t.Fatalf("expected ocsp-soft revocation mode, got %q", mode)
	}
}

type failingRevocationHTTPClient struct{}

func (failingRevocationHTTPClient) Do(*http.Request) (*http.Response, error) {
	return nil, errors.New("ocsp fetch failed")
}

func TestHandleUntrustedButValidSignatureEnforcesOCSP(t *testing.T) {
	defer testSetup(t, "--verify")()

	prevClient := revocationHTTPClient
	revocationHTTPClient = failingRevocationHTTPClient{}
	defer func() { revocationHTTPClient = prevClient }()

	root := fakeca.New(fakeca.IsCA)
	leaf := root.Issue(fakeca.OCSPServer("https://ocsp.example.invalid"))
	chains := [][][]*x509.Certificate{{{leaf.Certificate, root.Certificate}}}
	trustErr := x509.UnknownAuthorityError{Cert: leaf.Certificate}

	err := handleUntrustedButValidSignature(chains, trustErr, "ocsp")
	if err == nil {
		t.Fatal("expected revocation error for unknown-authority signature when ocsp is enabled")
	}
	if !strings.Contains(err.Error(), "failed revocation check") {
		t.Fatalf("expected revocation failure, got %v", err)
	}
}

func TestHandleUntrustedButValidSignatureWarnsOnSoftOCSP(t *testing.T) {
	defer testSetup(t, "--verify")()

	prevClient := revocationHTTPClient
	revocationHTTPClient = failingRevocationHTTPClient{}
	defer func() { revocationHTTPClient = prevClient }()

	root := fakeca.New(fakeca.IsCA)
	leaf := root.Issue(fakeca.OCSPServer("https://ocsp.example.invalid"))
	chains := [][][]*x509.Certificate{{{leaf.Certificate, root.Certificate}}}
	trustErr := x509.UnknownAuthorityError{Cert: leaf.Certificate}

	err := handleUntrustedButValidSignature(chains, trustErr, "ocsp-soft")
	if err != nil {
		t.Fatalf("expected soft OCSP mode to warn but succeed, got %v", err)
	}
	if !strings.Contains(stderrBuf.String(), "Verification succeeded because revocation mode is set to warn") {
		t.Fatalf("expected soft OCSP warning, got %q", stderrBuf.String())
	}
}
