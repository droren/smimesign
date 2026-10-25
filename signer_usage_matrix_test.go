package main

import (
	"crypto/x509"
	"testing"
)

func TestCommitSignerUsageMatrix(t *testing.T) {
	for _, tc := range []struct {
		name string
		ku   x509.KeyUsage
		eku  []x509.ExtKeyUsage
		want bool
	}{
		{"code", x509.KeyUsageDigitalSignature, []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}, true},
		{"smime", x509.KeyUsageDigitalSignature, []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection}, true},
		{"combined", x509.KeyUsageDigitalSignature, []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning, x509.ExtKeyUsageEmailProtection}, true},
		{"any", x509.KeyUsageDigitalSignature, []x509.ExtKeyUsage{x509.ExtKeyUsageAny}, true},
		{"no-eku", x509.KeyUsageDigitalSignature, nil, true},
		{"content-commitment", x509.KeyUsageContentCommitment, nil, true},
		{"authentication-only", x509.KeyUsageDigitalSignature, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, false},
		{"server-only", x509.KeyUsageDigitalSignature, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, false},
		{"timestamp-only", x509.KeyUsageDigitalSignature, []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping}, false},
		{"encryption-only", x509.KeyUsageKeyEncipherment, []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection}, false},
		{"ca-only", x509.KeyUsageCertSign, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cert := &x509.Certificate{KeyUsage: tc.ku, ExtKeyUsage: tc.eku}
			if got := certAllowedForCommitSigning(cert); got != tc.want {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
}
