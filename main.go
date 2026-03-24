//go:generate goversioninfo -file-version=$GIT_VERSION -ver-major=$VERSION_MAJOR -ver-minor=$VERSION_MINOR -ver-patch=$VERSION_PATCH -platform-specific=true windows-installer/versioninfo.json

package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/github/smimesign/certstore"
	"github.com/pborman/getopt/v2"
	"github.com/pkg/errors"
)

var (
	// This can be set at build time by running
	// go build -ldflags "-X main.versionString=$(git describe --tags)"
	versionString = "undefined"

	// default timestamp authority URL. This can be set at build time by running
	// go build -ldflags "-X main.defaultTSA=${https://whatever}"
	defaultTSA = ""

	// Action flags
	helpFlag              = getopt.BoolLong("help", 'h', "print this help message")
	versionFlag           = getopt.BoolLong("version", 'v', "print the version number")
	signFlag              = getopt.BoolLong("sign", 's', "make a signature")
	verifyFlag            = getopt.BoolLong("verify", 0, "verify a signature")
	dumpCertsFlag         = getopt.BoolLong("dump-certs", 0, "dump X.509 certificates embedded in a signature")
	listKeysFlag          = getopt.BoolLong("list-keys", 0, "show keys")
	listSmartcardKeysFlag = getopt.BoolLong("list-smartcard-keys", 0, "show smartcard keys")

	// Option flags
	localUserOpt    = getopt.StringLong("local-user", 'u', "", "use USER-ID to sign", "USER-ID")
	certIDOpt       = getopt.StringLong("cert-id", 0, "", "use certificate ID to disambiguate when multiple identities match (or set SMIMESIGN_CERT_ID)", "ID")
	detachSignFlag  = getopt.BoolLong("detach-sign", 'b', "make a detached signature")
	armorFlag       = getopt.BoolLong("armor", 'a', "create ascii armored output")
	statusFdOpt     = getopt.IntLong("status-fd", 0, -1, "write special status strings to the file descriptor n.", "n")
	keyFormatOpt    = getopt.EnumLong("keyid-format", 0, []string{"long"}, "long", "select  how  to  display key IDs.", "{long}")
	tsaOpt          = getopt.StringLong("timestamp-authority", 't', defaultTSA, "URL of RFC3161 timestamp authority to use for timestamping", "url")
	includeCertsOpt = getopt.IntLong("include-certs", 0, -2, "-3 is the same as -2, but ommits issuer when cert has Authority Information Access extension. -2 includes all certs except root. -1 includes all certs. 0 includes no certs. 1 includes leaf cert. >1 includes n from the leaf. Default -2.", "n")
	allowAnyEKUFlag = getopt.BoolLong("allow-any-eku", 0, "accept any extended key usage during verification")
	trustLocalCerts = getopt.BoolLong("trust-local-certs", 0, "treat local identities as trust anchors during verification")
	revocationOpt   = getopt.EnumLong("revocation-check", 0, []string{"none", "ocsp"}, "none", "perform revocation checking during verification", "{none|ocsp}")

	// Remaining arguments
	fileArgs []string

	idents []certstore.Identity

	// these are changed in tests
	stdin  io.ReadCloser  = os.Stdin
	stdout io.WriteCloser = os.Stdout
	stderr io.WriteCloser = os.Stderr
)

func main() {
	if err := runCommand(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runCommand() error {
	// Parse CLI args
	getopt.HelpColumn = 40
	getopt.SetParameters("[files]")
	getopt.Parse()
	fileArgs = getopt.Args()

	if *helpFlag {
		getopt.Usage()
		return nil
	}

	if *versionFlag {
		fmt.Println(versionString)
		return nil
	}

	if *signFlag {
		if *verifyFlag || *dumpCertsFlag || *listKeysFlag {
			return errors.New("specify --help, --sign, --verify, --dump-certs, or --list-keys")
		} else if len(*localUserOpt) == 0 {
			return errors.New("specify a USER-ID to sign with")
		} else {
			cleanup, err := openIdentities()
			if err != nil {
				return err
			}
			defer cleanup()
			return commandSign()
		}
	}

	if *verifyFlag {
		if *signFlag || *dumpCertsFlag || *listKeysFlag {
			return errors.New("specify --help, --sign, --verify, --dump-certs, or --list-keys")
		} else if len(*localUserOpt) > 0 {
			return errors.New("local-user cannot be specified for verification")
		} else if len(*certIDOpt) > 0 {
			return errors.New("cert-id cannot be specified for verification")
		} else if *detachSignFlag {
			return errors.New("detach-sign cannot be specified for verification")
		} else if *armorFlag {
			return errors.New("armor cannot be specified for verification")
		} else {
			cleanup, err := openIdentities()
			if err != nil {
				return err
			}
			defer cleanup()
			return commandVerify()
		}
	}

	if *dumpCertsFlag {
		if *signFlag || *verifyFlag || *listKeysFlag || *listSmartcardKeysFlag {
			return errors.New("specify --help, --sign, --verify, --dump-certs, --list-keys, or --list-smartcard-keys")
		} else if len(*localUserOpt) > 0 {
			return errors.New("local-user cannot be specified for dump-certs")
		} else if len(*certIDOpt) > 0 {
			return errors.New("cert-id cannot be specified for dump-certs")
		} else if *detachSignFlag {
			return errors.New("detach-sign cannot be specified for dump-certs")
		} else if *armorFlag {
			return errors.New("armor cannot be specified for dump-certs")
		} else {
			return commandDumpCerts()
		}
	}

	if *listKeysFlag {
		if *signFlag || *verifyFlag || *dumpCertsFlag || *listSmartcardKeysFlag {
			return errors.New("specify --help, --sign, --verify, --dump-certs, --list-keys, or --list-smartcard-keys")
		} else if len(*localUserOpt) > 0 {
			return errors.New("local-user cannot be specified for list-keys")
		} else if len(*certIDOpt) > 0 {
			return errors.New("cert-id cannot be specified for list-keys")
		} else if *detachSignFlag {
			return errors.New("detach-sign cannot be specified for list-keys")
		} else if *armorFlag {
			return errors.New("armor cannot be specified for list-keys")
		} else {
			cleanup, err := openIdentities()
			if err != nil {
				return err
			}
			defer cleanup()
			return commandListKeys()
		}
	}

	if *listSmartcardKeysFlag {
		if *signFlag || *verifyFlag || *dumpCertsFlag || *listKeysFlag {
			return errors.New("specify --help, --sign, --verify, --dump-certs, --list-keys, or --list-smartcard-keys")
		} else if len(*localUserOpt) > 0 {
			return errors.New("local-user cannot be specified for list-smartcard-keys")
		} else if len(*certIDOpt) > 0 {
			return errors.New("cert-id cannot be specified for list-smartcard-keys")
		} else if *detachSignFlag {
			return errors.New("detach-sign cannot be specified for list-smartcard-keys")
		} else if *armorFlag {
			return errors.New("armor cannot be specified for list-smartcard-keys")
		} else {
			cleanup, err := openIdentities()
			if err != nil {
				return err
			}
			defer cleanup()
			return commandListSmartcardKeys()
		}
	}

	return errors.New("specify --help, --sign, --verify, --dump-certs, or --list-keys")
}

func envBool(name string) bool {
	value, ok := os.LookupEnv(name)
	if !ok {
		return false
	}

	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func openIdentities() (func(), error) {
	store, err := certstore.Open()
	if err != nil {
		return nil, errors.Wrap(err, "failed to open certificate store")
	}

	openedIdents, err := store.Identities()
	if err != nil {
		store.Close()
		return nil, errors.Wrap(err, "failed to get identities from certificate store")
	}

	idents = openedIdents
	return func() {
		for _, ident := range idents {
			ident.Close()
		}
		store.Close()
	}, nil
}
