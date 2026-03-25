package main

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/github/smimesign/fakeca"
)

func TestNormalizeFingerprintAndMatch(t *testing.T) {
	ca := fakeca.New(fakeca.IsCA)
	cert := ca.Certificate

	hexFpr := certHexFingerprint(cert)

	// With 0x prefix and upper-case input.
	in := "0x" + strings.ToUpper(hexFpr)
	norm := normalizeFingerprint(in)

	// Round-trip back to hex for comparison.
	got := hex.EncodeToString(norm)
	if !strings.EqualFold(got, hexFpr) {
		t.Fatalf("normalizeFingerprint failed: have %s want %s", got, hexFpr)
	}

	if !certHasFingerprint(cert, norm) {
		t.Fatalf("certHasFingerprint returned false for valid SHA-256 fingerprint")
	}

	legacyHexFpr := hex.EncodeToString(certLegacyFingerprint(cert))
	legacyNorm := normalizeFingerprint(legacyHexFpr)
	if !certHasFingerprint(cert, legacyNorm) {
		t.Fatalf("certHasFingerprint returned false for valid legacy SHA-1 fingerprint")
	}
}

func TestCertHasFingerprintRejectsShortSuffix(t *testing.T) {
	cert := fakeca.New(fakeca.IsCA).Certificate
	shortSuffix := certFingerprint(cert)[len(certFingerprint(cert))-4:]
	if certHasFingerprint(cert, shortSuffix) {
		t.Fatalf("certHasFingerprint unexpectedly matched a short suffix")
	}
}

func TestCertHasFingerprintAllowsLongSuffix(t *testing.T) {
	cert := fakeca.New(fakeca.IsCA).Certificate
	longSuffix := certFingerprint(cert)[len(certFingerprint(cert))-8:]
	if !certHasFingerprint(cert, longSuffix) {
		t.Fatalf("certHasFingerprint failed to match a sufficiently long suffix")
	}
}
