package main

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/certifi/gocertifi"
	cms "github.com/github/smimesign/ietf-cms"
	"github.com/pkg/errors"
)

func commandVerify() error {
	sNewSig.emit()

	if len(fileArgs) < 2 {
		return verifyAttached()
	}

	return verifyDetached()
}

func verifyAttached() error {
	var (
		f   io.ReadCloser
		err error
	)

	// Read in signature
	if len(fileArgs) == 1 {
		if f, err = os.Open(fileArgs[0]); err != nil {
			return errors.Wrapf(err, "failed to open signature file (%s)", fileArgs[0])
		}
		defer f.Close()
	} else {
		f = stdin
	}

	buf := new(bytes.Buffer)
	if _, err = io.Copy(buf, f); err != nil {
		return errors.Wrap(err, "failed to read signature")
	}

	// Try decoding as PEM
	var der []byte
	if blk, _ := pem.Decode(buf.Bytes()); blk != nil {
		der = blk.Bytes
	} else {
		der = buf.Bytes()
	}

	// Parse signature
	sd, err := cms.ParseSignedData(der)
	if err != nil {
		return errors.Wrap(err, "failed to parse signature")
	}

	// Verify signature
	opts, revocationMode := verifyOpts()
	chains, err := sd.Verify(opts)
	if err != nil {
		if trustErr, ok := err.(x509.UnknownAuthorityError); ok {
			return verifyAttachedWithUntrustedCert(sd, trustErr, revocationMode)
		}
		if len(chains) > 0 {
			emitBadSig(chains)
		} else {
			sErrSig.emit()
		}

		return errors.Wrap(err, "failed to verify signature")
	}

	if err := verifyRevocation(chains, revocationMode); err != nil {
		if isSoftRevocationMode(revocationMode) {
			return reportTrustedButRevocationWarning(chains, err)
		}
		emitBadSig(chains)
		return errors.Wrap(err, "failed revocation check")
	}

	return reportSuccessfulVerification(chains)
}

func verifyDetached() error {
	var (
		f   io.ReadCloser
		err error
	)

	// Read in signature
	if f, err = os.Open(fileArgs[0]); err != nil {
		return errors.Wrapf(err, "failed to open signature file (%s)", fileArgs[0])
	}
	defer f.Close()

	buf := new(bytes.Buffer)
	if _, err = io.Copy(buf, f); err != nil {
		return errors.Wrap(err, "failed to read signature file")
	}

	// Try decoding as PEM
	var der []byte
	if blk, _ := pem.Decode(buf.Bytes()); blk != nil {
		der = blk.Bytes
	} else {
		der = buf.Bytes()
	}

	// Parse signature
	sd, err := cms.ParseSignedData(der)
	if err != nil {
		return errors.Wrap(err, "failed to parse signature")
	}

	// Read in signed data
	if fileArgs[1] == "-" {
		f = stdin
	} else {
		if f, err = os.Open(fileArgs[1]); err != nil {
			return errors.Wrapf(err, "failed to open message file (%s)", fileArgs[1])
		}
		defer f.Close()
	}

	// Verify signature
	buf.Reset()
	if _, err = io.Copy(buf, f); err != nil {
		return errors.Wrap(err, "failed to read message file")
	}

	opts, revocationMode := verifyOpts()
	chains, err := sd.VerifyDetached(buf.Bytes(), opts)
	if err != nil {
		if trustErr, ok := err.(x509.UnknownAuthorityError); ok {
			return verifyDetachedWithUntrustedCert(sd, buf.Bytes(), trustErr, revocationMode)
		}
		if len(chains) > 0 {
			emitBadSig(chains)
		} else {
			sErrSig.emit()
		}

		return errors.Wrap(err, "failed to verify signature")
	}

	if err := verifyRevocation(chains, revocationMode); err != nil {
		if isSoftRevocationMode(revocationMode) {
			return reportTrustedButRevocationWarning(chains, err)
		}
		emitBadSig(chains)
		return errors.Wrap(err, "failed revocation check")
	}

	return reportSuccessfulVerification(chains)
}

func verifyOpts() (x509.VerifyOptions, string) {
	roots, err := x509.SystemCertPool()
	if err != nil {
		// SystemCertPool isn't implemented for Windows. fall back to mozilla trust
		// store.
		roots, err = gocertifi.CACerts()
		if err != nil {
			// Fall back to an empty store. Verification will likely fail.
			roots = x509.NewCertPool()
		}
	}

	if *trustLocalCerts || envBool("SMIMESIGN_TRUST_LOCAL_CERTS") {
		for _, ident := range idents {
			if cert, err := ident.Certificate(); err == nil {
				roots.AddCert(cert)
			}
		}
	}

	keyUsages := []x509.ExtKeyUsage{
		x509.ExtKeyUsageEmailProtection,
		x509.ExtKeyUsageCodeSigning,
	}
	if *allowAnyEKUFlag || envBool("SMIMESIGN_ALLOW_ANY_EKU") {
		keyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
	}

	revocationMode := strings.TrimSpace(*revocationOpt)
	if envMode := strings.TrimSpace(os.Getenv("SMIMESIGN_REVOCATION_CHECK")); envMode != "" {
		revocationMode = envMode
	}
	switch revocationMode {
	case "ocsp", "ocsp-soft":
	default:
		revocationMode = "none"
	}

	return x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: keyUsages,
	}, revocationMode
}

func reportSuccessfulVerification(chains [][][]*x509.Certificate) error {
	cert := chains[0][0][0]
	fpr := certHexFingerprint(cert)
	subj := cert.Subject.String()

	fmt.Fprintf(stderr, "smimesign: Signature made using certificate ID 0x%s\n", fpr)
	emitGoodSig(chains)
	fmt.Fprintf(stderr, "smimesign: Good signature from \"%s\"\n", subj)
	emitTrustFully()
	return nil
}

func verifyAttachedWithUntrustedCert(sd *cms.SignedData, trustErr x509.UnknownAuthorityError, revocationMode string) error {
	chains, err := sd.VerifySignatureOnly()
	if err != nil {
		sErrSig.emit()
		return errors.Wrap(trustErr, "failed to verify signature")
	}
	return handleUntrustedButValidSignature(chains, trustErr, revocationMode)
}

func verifyDetachedWithUntrustedCert(sd *cms.SignedData, message []byte, trustErr x509.UnknownAuthorityError, revocationMode string) error {
	chains, err := sd.VerifyDetachedSignatureOnly(message)
	if err != nil {
		sErrSig.emit()
		return errors.Wrap(trustErr, "failed to verify signature")
	}
	return handleUntrustedButValidSignature(chains, trustErr, revocationMode)
}

func handleUntrustedButValidSignature(chains [][][]*x509.Certificate, trustErr x509.UnknownAuthorityError, revocationMode string) error {
	if err := verifyRevocation(chains, revocationMode); err != nil {
		if isSoftRevocationMode(revocationMode) {
			return reportUntrustedButValidSignatureWithRevocationWarning(chains, trustErr, err)
		}
		emitBadSig(chains)
		return errors.Wrap(err, "failed revocation check")
	}

	return reportUntrustedButValidSignature(chains, trustErr)
}

func isSoftRevocationMode(mode string) bool {
	return mode == "ocsp-soft"
}

func reportUntrustedButValidSignature(chains [][][]*x509.Certificate, trustErr x509.UnknownAuthorityError) error {
	cert := chains[0][0][0]
	fpr := certHexFingerprint(cert)
	subj := cert.Subject.String()

	fmt.Fprintf(stderr, "smimesign: Signature made using certificate ID 0x%s\n", fpr)
	emitGoodSig(chains)
	fmt.Fprintf(stderr, "smimesign: Good signature from \"%s\"\n", subj)
	emitTrustUndefined("unknown authority")
	fmt.Fprintf(stderr, "smimesign: WARNING: certificate chain is not trusted: %v\n", trustErr)
	fmt.Fprintf(stderr, "smimesign: To trust this signer, install the issuing CA certificate into your system trust store.\n")
	fmt.Fprintf(stderr, "smimesign: On RHEL/Fedora/CentOS, copy the CA PEM to /etc/pki/ca-trust/source/anchors/ and run update-ca-trust.\n")
	fmt.Fprintf(stderr, "smimesign: On Debian/Ubuntu, copy the CA PEM to /usr/local/share/ca-certificates/ and run update-ca-certificates.\n")
	fmt.Fprintf(stderr, "smimesign: Then rerun verification.\n")
	return nil
}

func reportTrustedButRevocationWarning(chains [][][]*x509.Certificate, revocationErr error) error {
	cert := chains[0][0][0]
	fpr := certHexFingerprint(cert)
	subj := cert.Subject.String()

	fmt.Fprintf(stderr, "smimesign: Signature made using certificate ID 0x%s\n", fpr)
	emitGoodSig(chains)
	fmt.Fprintf(stderr, "smimesign: Good signature from \"%s\"\n", subj)
	emitTrustUndefined("revocation-check-failed")
	fmt.Fprintf(stderr, "smimesign: WARNING: certificate chain is trusted, but revocation checking failed: %v\n", revocationErr)
	fmt.Fprintf(stderr, "smimesign: Verification succeeded because revocation mode is set to warn. Use --revocation-check=ocsp to fail closed.\n")
	return nil
}

func reportUntrustedButValidSignatureWithRevocationWarning(chains [][][]*x509.Certificate, trustErr x509.UnknownAuthorityError, revocationErr error) error {
	if err := reportUntrustedButValidSignature(chains, trustErr); err != nil {
		return err
	}
	fmt.Fprintf(stderr, "smimesign: WARNING: revocation checking failed: %v\n", revocationErr)
	fmt.Fprintf(stderr, "smimesign: Verification succeeded because revocation mode is set to warn. Use --revocation-check=ocsp to fail closed.\n")
	return nil
}
