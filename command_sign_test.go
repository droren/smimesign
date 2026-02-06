package main

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"testing"

	"github.com/github/smimesign/certstore"
	"github.com/github/smimesign/fakeca"
	cms "github.com/github/smimesign/ietf-cms"
	"github.com/github/smimesign/ietf-cms/protocol"
	"github.com/stretchr/testify/require"
)

func chainContains(chain []*x509.Certificate, want *x509.Certificate) bool {
	for _, cert := range chain {
		if cert.Equal(want) {
			return true
		}
	}
	return false
}

func TestSign(t *testing.T) {
	defer testSetup(t, "--sign", "-u", certHexFingerprint(leaf.Certificate))()

	stdinBuf.WriteString("hello, world!")
	require.NoError(t, commandSign())
	sd, err := cms.ParseSignedData(stdoutBuf.Bytes())
	require.NoError(t, err)

	_, err = sd.Verify(x509.VerifyOptions{Roots: ca.ChainPool()})
	require.NoError(t, err)
}

func TestSignIncludeCertsAIA(t *testing.T) {
	defer testSetup(t, "--sign", "-u", certHexFingerprint(aiaLeaf.Certificate))()

	stdinBuf.WriteString("hello, world!")
	require.NoError(t, commandSign())

	ci, err := protocol.ParseContentInfo(stdoutBuf.Bytes())
	require.NoError(t, err)

	sd, err := ci.SignedDataContent()
	require.NoError(t, err)

	certs, err := sd.X509Certificates()
	require.NoError(t, err)

	require.Equal(t, 2, len(certs))
	require.True(t, chainContains(certs, aiaLeaf.Certificate))
	require.True(t, chainContains(certs, intermediate.Certificate))
}

func TestSignIncludeCertsDefault(t *testing.T) {
	defer testSetup(t, "--sign", "-u", certHexFingerprint(leaf.Certificate))()

	stdinBuf.WriteString("hello, world!")
	require.NoError(t, commandSign())

	ci, err := protocol.ParseContentInfo(stdoutBuf.Bytes())
	require.NoError(t, err)

	sd, err := ci.SignedDataContent()
	require.NoError(t, err)

	certs, err := sd.X509Certificates()
	require.NoError(t, err)

	require.Equal(t, 2, len(certs))
	require.True(t, chainContains(certs, leaf.Certificate))
	require.True(t, chainContains(certs, intermediate.Certificate))
}

func TestSignIncludeCertsMinus3(t *testing.T) {
	defer testSetup(t, "--sign", "--include-certs=-3", "-u", certHexFingerprint(leaf.Certificate))()

	stdinBuf.WriteString("hello, world!")
	require.NoError(t, commandSign())

	ci, err := protocol.ParseContentInfo(stdoutBuf.Bytes())
	require.NoError(t, err)

	sd, err := ci.SignedDataContent()
	require.NoError(t, err)

	certs, err := sd.X509Certificates()
	require.NoError(t, err)

	require.Equal(t, 2, len(certs))
	require.True(t, chainContains(certs, leaf.Certificate))
	require.True(t, chainContains(certs, intermediate.Certificate))
}

func TestSignIncludeCertsMinus2(t *testing.T) {
	defer testSetup(t, "--sign", "--include-certs=-2", "-u", certHexFingerprint(leaf.Certificate))()

	stdinBuf.WriteString("hello, world!")
	require.NoError(t, commandSign())

	ci, err := protocol.ParseContentInfo(stdoutBuf.Bytes())
	require.NoError(t, err)

	sd, err := ci.SignedDataContent()
	require.NoError(t, err)

	certs, err := sd.X509Certificates()
	require.NoError(t, err)

	require.Equal(t, 2, len(certs))
	require.True(t, chainContains(certs, leaf.Certificate))
	require.True(t, chainContains(certs, intermediate.Certificate))
}

func TestSignIncludeCertsMinus1(t *testing.T) {
	defer testSetup(t, "--sign", "--include-certs=-1", "-u", certHexFingerprint(leaf.Certificate))()

	stdinBuf.WriteString("hello, world!")
	require.NoError(t, commandSign())

	ci, err := protocol.ParseContentInfo(stdoutBuf.Bytes())
	require.NoError(t, err)

	sd, err := ci.SignedDataContent()
	require.NoError(t, err)

	certs, err := sd.X509Certificates()
	require.NoError(t, err)

	require.Equal(t, 3, len(certs))
	require.True(t, chainContains(certs, leaf.Certificate))
	require.True(t, chainContains(certs, intermediate.Certificate))
	require.True(t, chainContains(certs, ca.Certificate))
}

func TestSignIncludeCerts0(t *testing.T) {
	defer testSetup(t, "--sign", "--include-certs=0", "-u", certHexFingerprint(leaf.Certificate))()

	stdinBuf.WriteString("hello, world!")
	require.NoError(t, commandSign())

	ci, err := protocol.ParseContentInfo(stdoutBuf.Bytes())
	require.NoError(t, err)

	sd, err := ci.SignedDataContent()
	require.NoError(t, err)

	certs, err := sd.X509Certificates()
	require.NoError(t, err)

	require.Equal(t, 0, len(certs))
}

func TestSignIncludeCerts1(t *testing.T) {
	defer testSetup(t, "--sign", "--include-certs=1", "-u", certHexFingerprint(leaf.Certificate))()

	stdinBuf.WriteString("hello, world!")
	require.NoError(t, commandSign())

	ci, err := protocol.ParseContentInfo(stdoutBuf.Bytes())
	require.NoError(t, err)

	sd, err := ci.SignedDataContent()
	require.NoError(t, err)

	certs, err := sd.X509Certificates()
	require.NoError(t, err)

	require.Equal(t, 1, len(certs))
	require.True(t, chainContains(certs, leaf.Certificate))
}

func TestSignIncludeCerts2(t *testing.T) {
	defer testSetup(t, "--sign", "--include-certs=2", "-u", certHexFingerprint(leaf.Certificate))()

	stdinBuf.WriteString("hello, world!")
	require.NoError(t, commandSign())

	ci, err := protocol.ParseContentInfo(stdoutBuf.Bytes())
	require.NoError(t, err)

	sd, err := ci.SignedDataContent()
	require.NoError(t, err)

	certs, err := sd.X509Certificates()
	require.NoError(t, err)

	require.Equal(t, 2, len(certs))
	require.True(t, chainContains(certs, leaf.Certificate))
	require.True(t, chainContains(certs, intermediate.Certificate))
}

func TestSignIncludeCerts3(t *testing.T) {
	defer testSetup(t, "--sign", "--include-certs=3", "-u", certHexFingerprint(leaf.Certificate))()

	stdinBuf.WriteString("hello, world!")
	require.NoError(t, commandSign())

	ci, err := protocol.ParseContentInfo(stdoutBuf.Bytes())
	require.NoError(t, err)

	sd, err := ci.SignedDataContent()
	require.NoError(t, err)

	certs, err := sd.X509Certificates()
	require.NoError(t, err)

	require.Equal(t, 3, len(certs))
	require.True(t, chainContains(certs, leaf.Certificate))
	require.True(t, chainContains(certs, intermediate.Certificate))
	require.True(t, chainContains(certs, ca.Certificate))
}

func TestSignIncludeCerts4(t *testing.T) {
	defer testSetup(t, "--sign", "--include-certs=4", "-u", certHexFingerprint(leaf.Certificate))()

	stdinBuf.WriteString("hello, world!")
	require.NoError(t, commandSign())

	ci, err := protocol.ParseContentInfo(stdoutBuf.Bytes())
	require.NoError(t, err)

	sd, err := ci.SignedDataContent()
	require.NoError(t, err)

	certs, err := sd.X509Certificates()
	require.NoError(t, err)

	require.Equal(t, 3, len(certs))
	require.True(t, chainContains(certs, leaf.Certificate))
	require.True(t, chainContains(certs, intermediate.Certificate))
	require.True(t, chainContains(certs, ca.Certificate))
}

func TestFindUserIdentityRequiresCertID(t *testing.T) {
	defer testSetup(t, "--sign", "-u", "alice@example.com")()

	identA := intermediate.Issue(fakeca.Subject(pkix.Name{CommonName: "alice@example.com"}))
	identB := intermediate.Issue(fakeca.Subject(pkix.Name{CommonName: "alice@example.com"}))
	idents = []certstore.Identity{identity{identA}, identity{identB}}

	got, err := findUserIdentity()
	require.Error(t, err)
	require.Nil(t, got)
	require.Contains(t, err.Error(), "Use --cert-id")
}

func TestFindUserIdentitySelectsByCertID(t *testing.T) {
	identA := intermediate.Issue(fakeca.Subject(pkix.Name{CommonName: "alice@example.com"}))
	identB := intermediate.Issue(fakeca.Subject(pkix.Name{CommonName: "alice@example.com"}))

	defer testSetup(t, "--sign", "-u", "alice@example.com", "--cert-id", certHexFingerprint(identB.Certificate))()
	idents = []certstore.Identity{identity{identA}, identity{identB}}

	got, err := findUserIdentity()
	require.NoError(t, err)
	require.NotNil(t, got)

	cert, err := got.Certificate()
	require.NoError(t, err)
	require.True(t, cert.Equal(identB.Certificate))
}

func TestFindUserIdentityCertIDNoMatch(t *testing.T) {
	identA := intermediate.Issue(fakeca.Subject(pkix.Name{CommonName: "alice@example.com"}))
	identB := intermediate.Issue(fakeca.Subject(pkix.Name{CommonName: "alice@example.com"}))
	other := intermediate.Issue(fakeca.Subject(pkix.Name{CommonName: "bob@example.com"}))

	defer testSetup(t, "--sign", "-u", "alice@example.com", "--cert-id", certHexFingerprint(other.Certificate))()
	idents = []certstore.Identity{identity{identA}, identity{identB}}

	got, err := findUserIdentity()
	require.Error(t, err)
	require.Nil(t, got)
	require.Contains(t, err.Error(), "does not match any identity")
}

func TestFindUserIdentitySelectsByEnvCertID(t *testing.T) {
	identA := intermediate.Issue(fakeca.Subject(pkix.Name{CommonName: "alice@example.com"}))
	identB := intermediate.Issue(fakeca.Subject(pkix.Name{CommonName: "alice@example.com"}))

	t.Setenv("SMIMESIGN_CERT_ID", certHexFingerprint(identA.Certificate))
	defer testSetup(t, "--sign", "-u", "alice@example.com")()
	idents = []certstore.Identity{identity{identA}, identity{identB}}

	got, err := findUserIdentity()
	require.NoError(t, err)
	require.NotNil(t, got)

	cert, err := got.Certificate()
	require.NoError(t, err)
	require.True(t, cert.Equal(identA.Certificate))
}

func TestDumpCertsFromSignature(t *testing.T) {
	defer testSetup(t, "--dump-certs")()

	sd, err := cms.NewSignedData([]byte("hello"))
	require.NoError(t, err)

	require.NoError(t, sd.Sign([]*x509.Certificate{leaf.Certificate}, leaf.PrivateKey))
	require.NoError(t, sd.SetCertificates([]*x509.Certificate{leaf.Certificate}))

	der, err := sd.ToDER()
	require.NoError(t, err)

	stdinBuf.Write(der)

	require.NoError(t, commandDumpCerts())

	block, _ := pem.Decode(stdoutBuf.Bytes())
	require.NotNil(t, block)

	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	require.True(t, cert.Equal(leaf.Certificate))
}

func TestSignSelfSignedIncluded(t *testing.T) {
	defer testSetup(t, "--sign", "-u", certHexFingerprint(ca.Certificate))()

	// Only use the self-signed certificate as the available identity.
	idents = []certstore.Identity{identity{ca}}

	stdinBuf.WriteString("hello")
	require.NoError(t, commandSign())

	sd, err := cms.ParseSignedData(stdoutBuf.Bytes())
	require.NoError(t, err)

	certs, err := sd.GetCertificates()
	require.NoError(t, err)

	require.Equal(t, 1, len(certs))
	require.True(t, certs[0].Equal(ca.Certificate))

	_, err = sd.Verify(x509.VerifyOptions{Roots: ca.ChainPool()})
	require.NoError(t, err)
}
