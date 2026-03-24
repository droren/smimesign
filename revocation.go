package main

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/crypto/ocsp"
)

const maxOCSPResponseBytes = 1 << 20

var revocationHTTPClient = &http.Client{Timeout: 15 * time.Second}

func verifyRevocation(chains [][][]*x509.Certificate, mode string) error {
	if mode != "ocsp" {
		return nil
	}

	for _, signerChains := range chains {
		if len(signerChains) == 0 {
			continue
		}
		if err := verifyChainOCSP(signerChains[0]); err != nil {
			return err
		}
	}

	return nil
}

func verifyChainOCSP(chain []*x509.Certificate) error {
	if len(chain) < 2 {
		return fmt.Errorf("ocsp revocation checking requires signer and issuer certificates")
	}

	cert := chain[0]
	issuer := chain[1]

	if len(cert.OCSPServer) == 0 {
		return fmt.Errorf("certificate %q does not advertise an OCSP responder", cert.Subject.String())
	}

	responderURL, err := url.Parse(cert.OCSPServer[0])
	if err != nil {
		return fmt.Errorf("invalid OCSP responder URL %q: %w", cert.OCSPServer[0], err)
	}
	if responderURL.Scheme != "http" && responderURL.Scheme != "https" {
		return fmt.Errorf("unsupported OCSP responder URL scheme %q", responderURL.Scheme)
	}

	reqDER, err := ocsp.CreateRequest(cert, issuer, nil)
	if err != nil {
		return fmt.Errorf("failed to build OCSP request: %w", err)
	}

	httpReq, err := http.NewRequest(http.MethodPost, responderURL.String(), bytes.NewReader(reqDER))
	if err != nil {
		return fmt.Errorf("failed to build OCSP HTTP request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/ocsp-request")
	httpReq.Header.Set("Accept", "application/ocsp-response")

	resp, err := revocationHTTPClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("failed to fetch OCSP response: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("OCSP responder returned HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxOCSPResponseBytes+1))
	if err != nil {
		return fmt.Errorf("failed to read OCSP response: %w", err)
	}
	if len(body) > maxOCSPResponseBytes {
		return fmt.Errorf("OCSP response exceeded limit of %d bytes", maxOCSPResponseBytes)
	}

	ocspResp, err := ocsp.ParseResponseForCert(body, cert, issuer)
	if err != nil {
		return fmt.Errorf("failed to parse OCSP response: %w", err)
	}

	switch ocspResp.Status {
	case ocsp.Good:
		return nil
	case ocsp.Revoked:
		return fmt.Errorf("certificate %q was revoked at %s", cert.Subject.String(), ocspResp.RevokedAt.UTC().Format(time.RFC3339))
	case ocsp.Unknown:
		return fmt.Errorf("OCSP responder returned unknown status for certificate %q", cert.Subject.String())
	default:
		return fmt.Errorf("OCSP responder returned status %d for certificate %q", ocspResp.Status, cert.Subject.String())
	}
}
