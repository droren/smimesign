package main

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/github/smimesign/certstore"
	cms "github.com/github/smimesign/ietf-cms"
	"github.com/pkg/errors"
)

func commandSign() error {
	userIdent, err := findUserIdentity()
	if err != nil {
		return errors.Wrap(err, "failed to get identity matching specified user-id")
	}
	if userIdent == nil {
		return fmt.Errorf("could not find identity matching specified user-id: %s", *localUserOpt)
	}

	// Git is looking for "\n[GNUPG:] SIG_CREATED ", meaning we need to print a
	// line before SIG_CREATED. BEGIN_SIGNING seems appropraite. GPG emits this,
	// though GPGSM does not.
	sBeginSigning.emit()

	cert, err := userIdent.Certificate()
	if err != nil {
		return errors.Wrap(err, "failed to get idenity certificate")
	}

	signer, err := userIdent.Signer()
	if err != nil {
		return errors.Wrap(err, "failed to get idenity signer")
	}

	var f io.ReadCloser
	if len(fileArgs) == 1 {
		if f, err = os.Open(fileArgs[0]); err != nil {
			return errors.Wrapf(err, "failed to open message file (%s)", fileArgs[0])
		}
		defer f.Close()
	} else {
		f = stdin
	}

	dataBuf := new(bytes.Buffer)
	if _, err = io.Copy(dataBuf, f); err != nil {
		return errors.Wrap(err, "failed to read message from stdin")
	}

	sd, err := cms.NewSignedData(dataBuf.Bytes())
	if err != nil {
		return errors.Wrap(err, "failed to create signed data")
	}
	if err = sd.Sign([]*x509.Certificate{cert}, signer); err != nil {
		return errors.Wrap(err, "failed to sign message")
	}
	if *detachSignFlag {
		sd.Detached()
	}

	if len(*tsaOpt) > 0 {
		if err = sd.AddTimestamps(*tsaOpt); err != nil {
			return errors.Wrap(err, "failed to add timestamp")
		}
	}

	chain, err := userIdent.CertificateChain()
	if err != nil {
		return errors.Wrap(err, "failed to get idenity certificate chain")
	}
	if chain, err = certsForSignature(chain); err != nil {
		return err
	}
	if err = sd.SetCertificates(chain); err != nil {
		return errors.Wrap(err, "failed to set certificates")
	}

	der, err := sd.ToDER()
	if err != nil {
		return errors.Wrap(err, "failed to serialize signature")
	}

	emitSigCreated(cert, *detachSignFlag)

	if *armorFlag {
		err = pem.Encode(stdout, &pem.Block{
			Type:  "SIGNED MESSAGE",
			Bytes: der,
		})
	} else {
		_, err = stdout.Write(der)
	}
	if err != nil {
		return errors.New("failed to write signature")
	}

	return nil
}

type identityMatch struct {
	ident certstore.Identity
	cert  *x509.Certificate
}

// findUserIdentity attempts to find an identity to sign with in the certstore
// by checking available identities against the --local-user argument.
func findUserIdentity() (certstore.Identity, error) {
	var (
		email   string
		fpr     []byte
		certFpr []byte
	)

	if strings.ContainsRune(*localUserOpt, '@') {
		email = normalizeEmail(*localUserOpt)
	} else {
		fpr = normalizeFingerprint(*localUserOpt)
	}

	if len(email) == 0 && len(fpr) == 0 {
		return nil, fmt.Errorf("bad user-id format: %s", *localUserOpt)
	}

	certID := strings.TrimSpace(*certIDOpt)
	if certID == "" {
		certID = strings.TrimSpace(os.Getenv("SMIMESIGN_CERT_ID"))
	}
	if len(certID) > 0 {
		certFpr = normalizeFingerprint(certID)
		if len(certFpr) == 0 {
			return nil, fmt.Errorf("bad cert-id format: %s", certID)
		}
	}

	var matches []identityMatch
	for _, ident := range idents {
		if cert, err := ident.Certificate(); err == nil && (certHasEmail(cert, email) || certHasFingerprint(cert, fpr)) {
			matches = append(matches, identityMatch{ident: ident, cert: cert})
		}
	}

	if len(matches) == 0 {
		return nil, nil
	}

	if len(certFpr) > 0 {
		var filtered []identityMatch
		for _, entry := range matches {
			if certHasFingerprint(entry.cert, certFpr) {
				filtered = append(filtered, entry)
			}
		}
		if len(filtered) == 1 {
			return filtered[0].ident, nil
		}
		list := matches
		if len(filtered) > 0 {
			list = filtered
		}
		return nil, fmt.Errorf("%s: %s", certIDSelectionError(*localUserOpt, certID, filtered), strings.Join(identityInfo(list), ", "))
	}

	if len(matches) > 1 {
		return nil, fmt.Errorf("multiple identities match %q. Use --cert-id to select one: %s", *localUserOpt, strings.Join(identityInfo(matches), ", "))
	}

	return matches[0].ident, nil
}

func certIDSelectionError(userID, certID string, filtered []identityMatch) string {
	if len(filtered) == 0 {
		return fmt.Sprintf("cert-id %q does not match any identity for %q. Available identities", certID, userID)
	}
	return fmt.Sprintf("cert-id %q matches multiple identities for %q (use a longer id). Matching identities", certID, userID)
}

func identityInfo(matches []identityMatch) []string {
	info := make([]string, 0, len(matches))
	for _, entry := range matches {
		if entry.cert == nil {
			continue
		}
		info = append(info, formatIdentity(entry.cert))
	}
	return info
}

func formatIdentity(cert *x509.Certificate) string {
	name := cert.Subject.CommonName
	if name == "" {
		name = cert.Subject.String()
	}
	fpr := certHexFingerprint(cert)
	usage := formatUsages(cert)
	if usage == "" {
		return fmt.Sprintf("%s (%s)", name, fpr)
	}
	return fmt.Sprintf("%s (%s; %s)", name, fpr, usage)
}

func formatUsages(cert *x509.Certificate) string {
	var parts []string
	if cert.KeyUsage != 0 {
		parts = append(parts, fmt.Sprintf("KU=%s", keyUsageStrings(cert.KeyUsage)))
	}
	if len(cert.ExtKeyUsage) > 0 {
		parts = append(parts, fmt.Sprintf("EKU=%s", extKeyUsageStrings(cert.ExtKeyUsage)))
	}
	return strings.Join(parts, ", ")
}

func keyUsageStrings(usage x509.KeyUsage) string {
	var parts []string
	if usage&x509.KeyUsageDigitalSignature != 0 {
		parts = append(parts, "digitalSignature")
	}
	if usage&x509.KeyUsageContentCommitment != 0 {
		parts = append(parts, "contentCommitment")
	}
	if usage&x509.KeyUsageKeyEncipherment != 0 {
		parts = append(parts, "keyEncipherment")
	}
	if usage&x509.KeyUsageDataEncipherment != 0 {
		parts = append(parts, "dataEncipherment")
	}
	if usage&x509.KeyUsageKeyAgreement != 0 {
		parts = append(parts, "keyAgreement")
	}
	if usage&x509.KeyUsageCertSign != 0 {
		parts = append(parts, "certSign")
	}
	if usage&x509.KeyUsageCRLSign != 0 {
		parts = append(parts, "crlSign")
	}
	if usage&x509.KeyUsageEncipherOnly != 0 {
		parts = append(parts, "encipherOnly")
	}
	if usage&x509.KeyUsageDecipherOnly != 0 {
		parts = append(parts, "decipherOnly")
	}
	return strings.Join(parts, "/")
}

func extKeyUsageStrings(usages []x509.ExtKeyUsage) string {
	parts := make([]string, 0, len(usages))
	for _, usage := range usages {
		switch usage {
		case x509.ExtKeyUsageAny:
			parts = append(parts, "any")
		case x509.ExtKeyUsageServerAuth:
			parts = append(parts, "serverAuth")
		case x509.ExtKeyUsageClientAuth:
			parts = append(parts, "clientAuth")
		case x509.ExtKeyUsageCodeSigning:
			parts = append(parts, "codeSigning")
		case x509.ExtKeyUsageEmailProtection:
			parts = append(parts, "emailProtection")
		case x509.ExtKeyUsageTimeStamping:
			parts = append(parts, "timeStamping")
		case x509.ExtKeyUsageOCSPSigning:
			parts = append(parts, "ocspSigning")
		case x509.ExtKeyUsageIPSECEndSystem:
			parts = append(parts, "ipsecEndSystem")
		case x509.ExtKeyUsageIPSECTunnel:
			parts = append(parts, "ipsecTunnel")
		case x509.ExtKeyUsageIPSECUser:
			parts = append(parts, "ipsecUser")
		case x509.ExtKeyUsageMicrosoftServerGatedCrypto:
			parts = append(parts, "msServerGatedCrypto")
		case x509.ExtKeyUsageNetscapeServerGatedCrypto:
			parts = append(parts, "nsServerGatedCrypto")
		case x509.ExtKeyUsageMicrosoftCommercialCodeSigning:
			parts = append(parts, "msCommercialCodeSigning")
		case x509.ExtKeyUsageMicrosoftKernelCodeSigning:
			parts = append(parts, "msKernelCodeSigning")
		default:
			parts = append(parts, fmt.Sprintf("usage(%d)", int(usage)))
		}
	}
	return strings.Join(parts, "/")
}

// certsForSignature determines which certificates to include in the signature
// based on the --include-certs option specified by the user.
func certsForSignature(chain []*x509.Certificate) ([]*x509.Certificate, error) {
	include := *includeCertsOpt

	if include < -3 {
		include = -2 // default
	}
	if include > len(chain) {
		include = len(chain)
	}

	switch include {
	case -3:
		for i := len(chain) - 1; i > 0; i-- {
			issuer, cert := chain[i], chain[i-1]

			// remove issuer when cert has AIA extension
			if bytes.Equal(issuer.RawSubject, cert.RawIssuer) && len(cert.IssuingCertificateURL) > 0 {
				chain = chain[0:i]
			}
		}
		return chainWithoutRoot(chain), nil
	case -2:
		return chainWithoutRoot(chain), nil
	case -1:
		return chain, nil
	default:
		return chain[0:include], nil
	}
}

// Returns the provided certificate chain without a root certificate, when
// present. A single self-signed certificate is kept so that the signature
// continues to embed the signing certificate.
func chainWithoutRoot(chain []*x509.Certificate) []*x509.Certificate {
	if len(chain) == 0 {
		return chain
	}

	lastIdx := len(chain) - 1

	// If there is more than one certificate and the last certificate is
	// self-signed, drop it from the returned chain. When a single
	// self-signed certificate is provided we keep it so the signature still
	// contains the signing certificate.
	if len(chain) > 1 {
		last := chain[lastIdx]

		if bytes.Equal(last.RawIssuer, last.RawSubject) {
			return chain[0:lastIdx]
		}
	}

	return chain
}
