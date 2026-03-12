package main

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"

	cms "github.com/github/smimesign/ietf-cms"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	var (
		showAll = flag.Bool("all", false, "display all embedded certificates instead of only the signer certificate")
		pemOnly = flag.Bool("pem", false, "print PEM instead of a human-readable certificate dump")
	)
	flag.Parse()

	rev := "HEAD"
	if flag.NArg() > 1 {
		return errors.New("usage: git-x509-cert [--all] [--pem] [<commit-ish>]")
	}
	if flag.NArg() == 1 {
		rev = flag.Arg(0)
	}

	rawCommit, err := gitOutput("cat-file", "commit", rev)
	if err != nil {
		return fmt.Errorf("failed to read commit %q: %w", rev, err)
	}

	sigPEM, err := extractCommitSignaturePEM(rawCommit)
	if err != nil {
		return fmt.Errorf("failed to extract commit signature from %q: %w", rev, err)
	}

	signerCerts, allCerts, err := parseSignatureCertificates(sigPEM)
	if err != nil {
		return fmt.Errorf("failed to parse signature certificates from %q: %w", rev, err)
	}
	if len(signerCerts) == 0 {
		return fmt.Errorf("no certificates embedded in commit signature for %q", rev)
	}

	selected := signerCerts
	if !*showAll {
		selected = signerCerts[:1]
	} else if len(allCerts) > 0 {
		selected = allCerts
	}

	if *pemOnly {
		for _, cert := range selected {
			if err := pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); err != nil {
				return fmt.Errorf("failed to write PEM certificate: %w", err)
			}
		}
		return nil
	}

	for i, cert := range selected {
		if len(selected) > 1 {
			fmt.Printf("Certificate %d/%d\n", i+1, len(selected))
		}

		if dump, err := platformCertificateDump(cert); err == nil {
			fmt.Print(dump)
		} else {
			fmt.Print(fallbackCertificateDump(cert))
		}

		if i+1 < len(selected) {
			fmt.Println()
		}
	}

	return nil
}

func gitOutput(args ...string) ([]byte, error) {
	cmd := exec.Command("git", args...)
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	return out, nil
}

func extractCommitSignaturePEM(commit []byte) ([]byte, error) {
	lines := strings.Split(string(commit), "\n")
	var sigLines []string
	inSig := false

	for _, line := range lines {
		if line == "" {
			break
		}

		if strings.HasPrefix(line, "gpgsig ") {
			inSig = true
			sigLines = append(sigLines, strings.TrimPrefix(line, "gpgsig "))
			continue
		}

		if inSig {
			if strings.HasPrefix(line, " ") {
				sigLines = append(sigLines, strings.TrimPrefix(line, " "))
				continue
			}
			break
		}
	}

	if len(sigLines) == 0 {
		return nil, errors.New("commit is not signed")
	}

	sig := strings.Join(sigLines, "\n")
	if !strings.HasSuffix(sig, "\n") {
		sig += "\n"
	}
	return []byte(sig), nil
}

func parseSignatureCertificates(sigPEM []byte) ([]*x509.Certificate, []*x509.Certificate, error) {
	block, _ := pem.Decode(sigPEM)
	if block == nil {
		return nil, nil, errors.New("signature is not valid PEM")
	}

	sd, err := cms.ParseSignedData(block.Bytes)
	if err != nil {
		return nil, nil, err
	}

	signerCerts, err := sd.GetSignerCertificates()
	if err != nil {
		return nil, nil, err
	}
	allCerts, err := sd.GetCertificates()
	if err != nil {
		return nil, nil, err
	}

	return signerCerts, allCerts, nil
}

func platformCertificateDump(cert *x509.Certificate) (string, error) {
	tmp, err := os.CreateTemp("", "git-x509-cert-*.pem")
	if err != nil {
		return "", err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	defer tmp.Close()

	if err := pem.Encode(tmp, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); err != nil {
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}

	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("certutil", "-dump", tmpName)
	default:
		cmd = exec.Command("openssl", "x509", "-in", tmpName, "-text", "-noout")
	}
	cmd.Env = os.Environ()

	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func fallbackCertificateDump(cert *x509.Certificate) string {
	var buf bytes.Buffer

	fmt.Fprintf(&buf, "Subject: %s\n", cert.Subject.String())
	fmt.Fprintf(&buf, "Issuer: %s\n", cert.Issuer.String())
	fmt.Fprintf(&buf, "Serial Number: %s\n", cert.SerialNumber.Text(16))
	fmt.Fprintf(&buf, "Not Before: %s\n", cert.NotBefore.UTC().Format("2006-01-02 15:04:05 MST"))
	fmt.Fprintf(&buf, "Not After: %s\n", cert.NotAfter.UTC().Format("2006-01-02 15:04:05 MST"))
	fmt.Fprintf(&buf, "Signature Algorithm: %s\n", cert.SignatureAlgorithm.String())
	fmt.Fprintf(&buf, "Public Key Algorithm: %s\n", cert.PublicKeyAlgorithm.String())
	if len(cert.EmailAddresses) > 0 {
		fmt.Fprintf(&buf, "Email Addresses: %s\n", strings.Join(cert.EmailAddresses, ", "))
	}
	if len(cert.DNSNames) > 0 {
		fmt.Fprintf(&buf, "DNS Names: %s\n", strings.Join(cert.DNSNames, ", "))
	}
	if len(cert.URIs) > 0 {
		var uris []string
		for _, uri := range cert.URIs {
			uris = append(uris, uri.String())
		}
		fmt.Fprintf(&buf, "URIs: %s\n", strings.Join(uris, ", "))
	}
	fmt.Fprintf(&buf, "SHA1 Fingerprint: %X\n", sha1.Sum(cert.Raw))
	fmt.Fprintf(&buf, "SHA256 Fingerprint: %X\n", sha256.Sum256(cert.Raw))
	buf.WriteString("\nPEM:\n")
	_ = pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})

	return buf.String()
}
