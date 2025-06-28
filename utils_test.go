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
        t.Fatalf("certHasFingerprint returned false for valid fingerprint")
    }
}
