package certstore

import "os"

// importPKCS12FromEnv loads a PKCS#12 file specified by SMIMESIGN_P12 and
// SMIMESIGN_P12_PASSWORD. If SMIMESIGN_P12 is unset, the function does
// nothing. The provided importFn should import the certificate data into the
// calling store.
func importPKCS12FromEnv(importFn func([]byte, string) error) error {
	path := os.Getenv("SMIMESIGN_P12")
	if path == "" {
		return nil
	}
	password := os.Getenv("SMIMESIGN_P12_PASSWORD")
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return importFn(data, password)
}
