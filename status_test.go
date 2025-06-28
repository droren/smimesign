package main

import (
    "bytes"
    "sync"
    "testing"

    "github.com/github/smimesign/fakeca"
    "github.com/stretchr/testify/require"
)

// TestEmitBadSig ensures that emitBadSig correctly formats and writes a status
// line.  The test used to fail to compile because emitBadSig referenced
// cert.Subject.String without invoking it – a mistake that the test will catch
// if it ever re-appears.
func TestEmitBadSig(t *testing.T) {
    // Build a minimal certificate chain using fakeca so we have real *x509.Certificate
    ca := fakeca.New(fakeca.IsCA)
    leaf := ca.Issue()

    // emitBadSig expects the Verify chains shape: [][][*x509.Certificate].
    chains := [][][]*x509.Certificate{{{leaf.Certificate}}}

    // Reset the once guard and capture output.
    _setupStatus = sync.Once{}
    var buf bytes.Buffer
    statusFile = &buf

    emitBadSig(chains)

    out := buf.String()
    // Output should begin with the GNUPG status prefix and contain "BADSIG".
    require.Contains(t, out, "[GNUPG:] BADSIG")

    // And it should include the certificate subject string.
    subj := leaf.Certificate.Subject.String()
    require.Contains(t, out, subj)
    // It should also include the certificate fingerprint.
    fpr := certHexFingerprint(leaf.Certificate)
    require.Contains(t, out, fpr)
}
