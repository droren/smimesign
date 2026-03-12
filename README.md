# smimesign

`smimesign` is an S/MIME / X.509 signing tool for Git commits and tags.

This fork is maintained at `droren/smimesign` and adds Linux support beyond the
original `github/smimesign` project, including PKCS#11 smart-card signing.

The current implementation supports:

- Windows certificate store signing
- macOS keychain signing
- Linux PKCS#12 signing
- Linux PKCS#11 smart-card signing
- Git X.509 signing with `gpg.format=x509`
- extraction of embedded signing certificates from Git commits

## What To Use This For

Use `smimesign` when your organization issues X.509 certificates for user
identity and you want Git commits and tags signed with those certificates
instead of OpenPGP keys.

Typical setups:

- Windows workstation with a user certificate in `CurrentUser\My`
- Linux workstation with a YubiKey or CAC exposed through PKCS#11
- Linux or macOS workstation using a PKCS#12 file

## Repository Layout

- `main.go` and `command_*.go`: main CLI
- `certstore/`: OS-specific certificate store access
- `ietf-cms/`: CMS / PKCS#7 signing and verification
- `cmd/git-x509-cert/`: helper for extracting and displaying commit signing certs
- `Makefile`: build and test targets

## Installation

### Windows

Build the binary:

```powershell
git clone https://github.com/droren/smimesign.git
cd smimesign
go build -o smimesign.exe .
```

Put `smimesign.exe` somewhere on `PATH`, for example:

```powershell
New-Item -ItemType Directory -Force $HOME\bin | Out-Null
Copy-Item .\smimesign.exe $HOME\bin\smimesign.exe
$env:Path = "$HOME\bin;$env:Path"
```

`smimesign` on Windows reads identities from the Windows certificate store.
The normal expectation is that the signing certificate is present in the
current user's personal store:

- Store: `Current User`
- Logical store: `Personal` / `My`

To list what `smimesign` can currently use:

```powershell
smimesign.exe --list-keys
```

If multiple certificates match the same Git identity, the current
implementation prefers the most signing-oriented certificate automatically. If
ambiguity still remains, set a persistent certificate fingerprint with
`SMIMESIGN_CERT_ID`.

Example:

```powershell
$env:SMIMESIGN_CERT_ID = "0x0C900B6316B1708E09BF5F0695BA0CBC20DCE99F"
```

To persist it for future PowerShell sessions:

```powershell
setx SMIMESIGN_CERT_ID 0x0C900B6316B1708E09BF5F0695BA0CBC20DCE99F
```

### Linux

Build the binary:

```bash
git clone https://github.com/droren/smimesign.git
cd smimesign
go build -o smimesign .
```

Put it on `PATH`:

```bash
install -m 0755 ./smimesign ~/.local/bin/smimesign
export PATH="$HOME/.local/bin:$PATH"
```

Linux supports two primary identity sources.

#### Linux With PKCS#12

```bash
export SMIMESIGN_P12=/path/to/user.p12
export SMIMESIGN_P12_PASSWORD='your-password'
smimesign --list-keys
```

#### Linux With PKCS#11 Smart Cards

Set the PKCS#11 module path:

```bash
export SMIMESIGN_PKCS11_MODULE=/usr/lib64/pkcs11/opensc-pkcs11.so
smimesign --list-smartcard-keys
```

If your token requires a PIN, you can either:

- export `SMIMESIGN_PKCS11_PIN` for the current shell, or
- use a wrapper script that prompts on `/dev/tty` and then execs `smimesign`

Example wrapper:

```bash
#!/usr/bin/env bash
set -euo pipefail
if [[ -z "${SMIMESIGN_PKCS11_PIN:-}" ]]; then
  printf 'YubiKey PIN: ' > /dev/tty
  IFS= read -r -s SMIMESIGN_PKCS11_PIN < /dev/tty
  printf '\n' > /dev/tty
  export SMIMESIGN_PKCS11_PIN
fi
exec /path/to/smimesign "$@"
```

When multiple certificates match the same identity, `smimesign` prefers a
signing-capable certificate automatically. To pin one explicitly, set
`SMIMESIGN_CERT_ID`:

```bash
export SMIMESIGN_CERT_ID=0x0C900B6316B1708E09BF5F0695BA0CBC20DCE99F
```

### macOS

macOS uses the system keychain. Build and install like any other Go binary:

```bash
git clone https://github.com/droren/smimesign.git
cd smimesign
go build -o smimesign .
```

List available identities:

```bash
./smimesign --list-keys
```

## Configure Git To Use X.509 Signing By Default

For Git 2.19 and newer, configure `smimesign` as the global X.509 signing
program:

### Windows

```powershell
git config --global gpg.x509.program smimesign.exe
git config --global gpg.format x509
git config --global commit.gpgsign true
git config --global tag.gpgSign true
git config --global log.showSignature true
git config --global user.name "Alex Example"
git config --global user.email alex.example@example.invalid
git config --global user.signingkey alex.example@example.invalid
```

### Linux and macOS

```bash
git config --global gpg.x509.program smimesign
git config --global gpg.format x509
git config --global commit.gpgsign true
git config --global tag.gpgSign true
git config --global log.showSignature true
git config --global user.name "Alex Example"
git config --global user.email alex.example@example.invalid
git config --global user.signingkey alex.example@example.invalid
```

After configuration, validate with:

```bash
git commit -S -m "x509 signing test"
git log --show-signature -1
```

## Choosing The Right Signing Certificate

When more than one certificate matches the same Git user identity, the current
implementation does this:

1. If `SMIMESIGN_CERT_ID` is set, that fingerprint wins.
2. Otherwise, `smimesign` prefers the most signing-oriented certificate.
3. If the choice is still ambiguous, signing fails with guidance to set
   `SMIMESIGN_CERT_ID`.

In practice, this means a certificate with `KU=contentCommitment` is preferred
over a client-authentication certificate with `EKU=clientAuth`.

Recommended practice:

- set `user.signingkey` to the Git email address present in the certificate
- set `SMIMESIGN_CERT_ID` if your environment has multiple matching certs

## Common Commands

List identities from the OS store or PKCS#12:

```bash
smimesign --list-keys
```

List smart-card identities on Linux:

```bash
smimesign --list-smartcard-keys
```

Create and verify a detached signature:

```bash
smimesign --sign -u user@example.com -b file.txt > file.txt.sig
smimesign --verify file.txt.sig file.txt
```

Extract certificates from an existing CMS signature:

```bash
smimesign --dump-certs file.txt.sig > certs.pem
```

## Validating The Certificate Used For A Git Commit

There are two supported ways to inspect the signing certificate embedded in a
Git commit.

### Option 1: Use The Cross-Platform Helper Tool

Build it once:

```bash
make build-tools
```

This creates `build/tools/git-x509-cert`.

Show the signer certificate from `HEAD` in human-readable form:

```bash
build/tools/git-x509-cert
```

Show a specific commit:

```bash
build/tools/git-x509-cert 6f274166f5db657127bfd29a07a49e46db03500d
```

Show all embedded certificates:

```bash
build/tools/git-x509-cert --all HEAD
```

Export the signer certificate as PEM:

```bash
build/tools/git-x509-cert --pem HEAD > signer.pem
```

The helper uses:

- `certutil -dump` on Windows
- `openssl x509 -text -noout` on Linux
- `openssl x509 -text -noout` on macOS

If those tools are unavailable, it falls back to a built-in certificate summary
plus PEM output.

This helper extracts and displays the certificate embedded in the commit
signature. It does not by itself establish that the commit is trusted. Pair it
with `git log --show-signature` or `git verify-commit` when you need both
certificate inspection and signature verification.

### Option 2: Extract PEM And Inspect It Yourself

Export the signing certificate from a commit:

```bash
build/tools/git-x509-cert --pem <commit-sha> > signer.pem
```

View it on Linux or macOS:

```bash
openssl x509 -in signer.pem -text -noout
```

View it on Windows:

```powershell
certutil -dump .\signer.pem
```

You can also inspect the commit signature at a higher level with:

```bash
git log --show-signature -1 <commit-sha>
```

## Trust Warnings

If the cryptographic signature is valid but the issuing CA is not trusted on
the local machine, `smimesign --verify` reports:

- a good signature
- a trust warning
- exit status `0`

This is intentional. It distinguishes:

- "the signature bytes are valid"
- "this workstation trusts the issuing CA"

### Install Your CA To Resolve Unknown Authority Warnings

#### Windows

Import the issuing CA into the appropriate Windows trust store, typically
`Trusted Root Certification Authorities` or `Intermediate Certification
Authorities` depending on what you are installing.

Example:

```powershell
certutil -addstore Root company-root-ca.cer
certutil -addstore CA company-issuing-ca.cer
```

#### Linux

RHEL / Fedora / CentOS:

```bash
sudo cp company-ca.pem /etc/pki/ca-trust/source/anchors/
sudo update-ca-trust
```

Debian / Ubuntu:

```bash
sudo cp company-ca.pem /usr/local/share/ca-certificates/company-ca.crt
sudo update-ca-certificates
```

#### macOS

```bash
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain company-root-ca.cer
```

After trust is installed, rerun:

```bash
git log --show-signature -1
```

## Troubleshooting

### Windows: "multiple identities match"

Current behavior:

- `smimesign` tries to prefer the most signing-oriented certificate
- if still ambiguous, it tells you to set `SMIMESIGN_CERT_ID`

Recommended fix:

```powershell
smimesign.exe --list-keys
$env:SMIMESIGN_CERT_ID = "0xYOUR_FINGERPRINT"
git commit -S -m "retry"
```

### Windows: Git cannot find `smimesign.exe`

Check:

```powershell
Get-Command smimesign.exe
git config --global --get gpg.x509.program
```

### Linux: No smart-card identities found

Check the PKCS#11 module and token visibility:

```bash
pkcs11-tool --module "$SMIMESIGN_PKCS11_MODULE" -L
smimesign --list-smartcard-keys
```

If the token is visible with `pkcs11-tool` but not in `smimesign`, verify the
module path and any PKCS#11 forwarding environment required by your setup.

### Linux: PIN entry problems

If Git signs non-interactively, use a wrapper script that prompts on `/dev/tty`
and exports `SMIMESIGN_PKCS11_PIN` only for that process.

### Verify shows "certificate signed by unknown authority"

The signature is valid, but your system does not trust the issuing CA yet.
Install the relevant CA certificate into the system trust store and rerun the
verification command.

### Git commit succeeds but `git log --show-signature` still looks wrong

Check:

```bash
git config --global --get gpg.format
git config --global --get gpg.x509.program
git config --global --get log.showSignature
```

Expected:

- `gpg.format = x509`
- `gpg.x509.program = smimesign` or `smimesign.exe`
- `log.showSignature = true`

## Building

Build the main binary:

```bash
go build .
```

Build platform targets:

```bash
make build-linux
make build-windows
make build-darwin
make build-tools
make build-all
```

`make build-windows` and `make build-darwin` require cgo cross-toolchains.
The Makefile now checks explicitly for those tools and fails early with a clear
message. Override the compiler commands if your environment uses different
tool names:

```bash
make build-windows WINDOWS_CC_AMD64=x86_64-w64-mingw32-gcc
make build-darwin DARWIN_CC_AMD64=o64-clang DARWIN_CC_ARM64=oa64-clang
```

## Tests

Run the minimal safe subset:

```bash
make test-min
```

Run the full suite:

```bash
make test-all
```

On macOS or other constrained environments, you may want:

```bash
export GODEBUG=x509usefallbackroots=1
```

## Contributing

PKI environments vary widely. Contributions that improve compatibility with
enterprise Windows, Linux PKCS#11, smart cards, and certificate-chain handling
are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).
