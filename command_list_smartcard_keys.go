package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/github/smimesign/certstore"
	"github.com/pkg/errors"
)

func commandListSmartcardKeys() error {
	store, err := certstore.Open()
	if err != nil {
		return errors.Wrap(err, "failed to open certstore")
	}
	defer store.Close()

	idents, err := store.Identities()
	if err != nil {
		return errors.Wrap(err, "failed to list identities")
	}

	for j, ident := range idents {
		if j > 0 {
			fmt.Print("\n")
		}

		cert, err := ident.Certificate()
		if err != nil {
			fmt.Fprintln(os.Stderr, "WARNING:", errors.Wrap(err, "failed to get identity certificate"))
			continue
		}

		fmt.Println("       ID:", certHexFingerprint(cert))
		fmt.Println("      S/N:", cert.SerialNumber.Text(16))
		fmt.Println("Algorithm:", cert.SignatureAlgorithm.String())
		fmt.Println(" Validity:", cert.NotBefore.String(), "-", cert.NotAfter.String())
		fmt.Println("   Issuer:", cert.Issuer.ToRDNSequence().String())
		fmt.Println("  Subject:", cert.Subject.ToRDNSequence().String())
		fmt.Println("   Emails:", strings.Join(certEmails(cert), ", "))
	}

	return nil
}
