package main

import (
	"bytes"
	"crypto/sha1" // #nosec G505 -- retained for legacy fingerprint compatibility.
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"regexp"
	"strings"
)

// normalizeFingerprint converts a string fingerprint to hex, removing leading
// "0x", if present.
func normalizeFingerprint(sfpr string) []byte {
	if len(sfpr) == 0 {
		return nil
	}

	// Allow both lowercase and uppercase 0x/0X prefixes – match is
	// performed in a case-insensitive manner to better mirror how tooling
	// such as GnuPG treats fingerprint prefixes.
	if len(sfpr) >= 2 && sfpr[0] == '0' {
		if sfpr[1] == 'x' || sfpr[1] == 'X' {
			sfpr = sfpr[2:]
		}
	}

	hfpr, err := hex.DecodeString(sfpr)
	if err != nil {
		return nil
	}

	return hfpr
}

// certHasFingerprint checks if the given certificate has the given fingerprint.
func certHasFingerprint(cert *x509.Certificate, fpr []byte) bool {
	if len(fpr) == 0 {
		return false
	}

	sha256Fpr := certFingerprint(cert)
	sha1Fpr := certLegacyFingerprint(cert)

	switch len(fpr) {
	case len(sha256Fpr):
		return bytes.Equal(sha256Fpr, fpr)
	case len(sha1Fpr):
		return bytes.Equal(sha1Fpr, fpr)
	}

	if len(fpr) < 8 {
		return false
	}

	return bytes.HasSuffix(sha256Fpr, fpr) || bytes.HasSuffix(sha1Fpr, fpr)
}

// certHexFingerprint calculates the default hex SHA256 fingerprint of a certificate.
func certHexFingerprint(cert *x509.Certificate) string {
	return hex.EncodeToString(certFingerprint(cert))
}

// certFingerprint calculates the default SHA256 fingerprint of a certificate.
func certFingerprint(cert *x509.Certificate) []byte {
	if len(cert.Raw) == 0 {
		return nil
	}

	fpr := sha256.Sum256(cert.Raw)
	return fpr[:]
}

// certLegacyFingerprint calculates the legacy SHA1 fingerprint of a certificate.
func certLegacyFingerprint(cert *x509.Certificate) []byte {
	if len(cert.Raw) == 0 {
		return nil
	}

	fpr := sha1.Sum(cert.Raw) // #nosec G401 -- SHA1 is retained for legacy fingerprint matching.
	return fpr[:]
}

// normalizeEmail attempts to extract an email address from a user-id string.
func normalizeEmail(email string) string {
	name, _, email := parseUserID(email)

	if len(email) > 0 {
		return email
	}

	if strings.ContainsRune(name, '@') {
		return name
	}

	return ""
}

var (
	oidEmailAddress      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}
	oidCommonName        = asn1.ObjectIdentifier{2, 5, 4, 3}
	oidMSDocumentSigning = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 12}
)

// certHasEmail checks if a certificate contains the given email address in its
// subject (CN/emailAddress) or SAN fields.
func certHasEmail(cert *x509.Certificate, email string) bool {
	for _, other := range certEmails(cert) {
		if other == email {
			return true
		}
	}

	return false
}

// borrowed from http://emailregex.com/
var emailRegexp = regexp.MustCompile(`(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)`)

// certEmails extracts email addresses from a certificate's subject
// (CN/emailAddress) and SAN extensions.
func certEmails(cert *x509.Certificate) []string {
	// From SAN
	emails := cert.EmailAddresses

	// From CN and emailAddress fields in subject.
	for _, name := range cert.Subject.Names {
		if !name.Type.Equal(oidEmailAddress) && !name.Type.Equal(oidCommonName) {
			continue
		}

		if email, isStr := name.Value.(string); isStr && emailRegexp.MatchString(email) {
			emails = append(emails, email)
		}
	}

	return emails
}

func certAllowedForCommitSigning(cert *x509.Certificate) bool {
	if cert == nil {
		return false
	}

	if len(cert.ExtKeyUsage) == 0 && len(cert.UnknownExtKeyUsage) == 0 {
		return true
	}

	for _, usage := range cert.ExtKeyUsage {
		switch usage {
		case x509.ExtKeyUsageCodeSigning, x509.ExtKeyUsageEmailProtection, x509.ExtKeyUsageMicrosoftCommercialCodeSigning:
			return true
		}
	}

	for _, usage := range cert.UnknownExtKeyUsage {
		if usage.Equal(oidMSDocumentSigning) {
			return true
		}
	}

	return false
}
