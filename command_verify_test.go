package main

import (
	"crypto/x509"
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
	if len(opts.KeyUsages) != 2 {
		t.Fatalf("expected two default verification EKUs, got %v", opts.KeyUsages)
	}
	if opts.KeyUsages[0] != x509.ExtKeyUsageEmailProtection || opts.KeyUsages[1] != x509.ExtKeyUsageCodeSigning {
		t.Fatalf("unexpected default verification EKUs: %v", opts.KeyUsages)
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
