package main

import (
	"bytes"
	"encoding/pem"
	"fmt"
	"io"
	"os"

	cms "github.com/github/smimesign/ietf-cms"
	"github.com/pkg/errors"
)

func commandDumpCerts() error {
	var (
		f   io.ReadCloser
		err error
	)

	if len(fileArgs) > 1 {
		return errors.New("dump-certs accepts at most one signature file (use stdin otherwise)")
	}

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

	certs, err := sd.GetCertificates()
	if err != nil {
		return errors.Wrap(err, "failed to read certificates from signature")
	}
	if len(certs) == 0 {
		return errors.New("no certificates found in signature")
	}

	for _, cert := range certs {
		if err := pem.Encode(stdout, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); err != nil {
			return fmt.Errorf("failed to write certificate: %w", err)
		}
	}

	return nil
}
