# X.509 Git signing: native macOS trust and hosting services

## macOS verification

Darwin builds with CGO use Security.framework `SecPolicyCreateBasicX509` for
system-trust CMS chain validation. Go's standard Darwin verifier applies TLS
policy even when `ExtKeyUsageAny` is requested. TLS lifetime/EKU rules are not
appropriate for code-signing or S/MIME certificates.

After native trust succeeds, the chain is checked again with Go's verifier,
using only the anchor accepted by macOS. Explicit caller root pools remain
explicit: an empty pool cannot silently fall back to system trust. Native
network certificate fetching is disabled; include intermediates in signatures
or install them locally. Revocation remains controlled by smimesign's existing
`--revocation-check` policy; this change does not enable revocation by default.

The commit signer policy accepts Code Signing, Email Protection, Microsoft
Commercial Code Signing, Microsoft Document Signing, anyExtendedKeyUsage, or
an absent EKU restriction. When Key Usage is specified it must permit digital
signature or content commitment. Authentication-only, TLS-server-only,
timestamp-only and encryption-only certificates are not commit signers.
The existing explicit `--allow-any-eku` override remains an unsafe escape hatch;
do not enable it to solve a trust-chain problem.

The CLI retains its existing distinction between a cryptographically valid
signature and a trusted signer: an unknown CA can produce `GOODSIG` together
with `TRUST_UNDEFINED`. Automation requiring trust must inspect trust status,
not only the exit code. This fix does not change that contract.

### Reproduce the native regression

A detached CMS DER signature named `commit-signature.der` and its exact bytes
named `commit-payload.txt` may be placed in a private fixture directory. Its
signer must chain to a CA already trusted in the macOS keychain:

```sh
SMIMESIGN_TEST_SIGNED_FIXTURE_DIR=/path/to/fixture go test ./ietf-cms -run TestDarwin -v
go test ./...
go test -race ./...
```

The opt-in test also checks tampering, validity windows, timestamp EKU,
nil/system roots, and explicit empty roots. Normal tests reject a generated
untrusted root without modifying any keychain. No personal certificates or
private keys are committed as test fixtures.

## Select the signer explicitly

Use the full ID printed by the installed build:

```sh
smimesign --list-keys
git config --global user.signingkey FULL_CERTIFICATE_ID
git config --global gpg.format x509
git config --global gpg.x509.program /absolute/path/to/smimesign
```

Per-repository `user.signingkey` overrides the global setting. Alternatively use
`--cert-id` or `SMIMESIGN_CERT_ID` with email selection. Update the pinned ID
when renewing a certificate. Prove which certificate signed a commit by
extracting it with `git-x509-cert --pem HEAD` and comparing DER with a live
export from the intended hardware slot; labels and email alone are not proof.

## Hosting compatibility is not client-side verification

A local `Good signature` is not a promise of a hosting provider's Verified badge.
CMS bytes are portable, but server support, trust, email and certificate policy
must all agree. Do not disable verification or add serverAuth to a signing
certificate to try to obtain a badge.

| Service | Requirements / limitations |
| --- | --- |
| GitHub | S/MIME supported; certificate must chain to GitHub's trusted public CA store. A private internal CA is not made trusted by installing it on the developer's Mac. |
| GitLab Self-Managed / Dedicated | Configure the instance's CA trust, verified account email and complete signature chain. GitLab documents digitalSignature KU and emailProtection EKU when EKU is present; AKI, SKI and CRL distribution points are also required. CodeSigning-only certificates are not sufficient. |
| GitLab.com | The documented X.509 workflow is not offered with a custom CA/Verified badge. |
| Gitea | Upstream S/MIME support request #14278 remains open at this investigation. Do not promise X.509 Verified badges; verify the deployed version's capabilities. SSH/OpenPGP are alternatives, not interchangeable encodings of an X.509 signature. |

For a private CA, a separate Git/S/MIME certificate profile can include
`digitalSignature`, `codeSigning,emailProtection`, AKI, SKI, a maintained CRL
endpoint and verified email SANs. Issue only after reviewing the CA profile and
server configuration; never silently replace an occupied hardware key slot.
Changing a certificate cannot rewrite existing signed commits or make an
internal root publicly trusted.

Sources:
- https://docs.github.com/en/authentication/managing-commit-signature-verification/about-commit-signature-verification
- https://docs.gitlab.com/user/project/repository/signed_commits/x509/
- https://github.com/go-gitea/gitea/issues/14278
- https://raw.githubusercontent.com/golang/go/go1.25.8/src/crypto/x509/root_darwin.go
