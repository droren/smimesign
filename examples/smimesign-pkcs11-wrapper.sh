#!/usr/bin/env bash
set -euo pipefail

# Example wrapper for Git + smimesign when the signing certificate is reachable
# through PKCS#11, including forwarded p11-kit setups.

REAL_SMIMESIGN="${REAL_SMIMESIGN:-$HOME/bin/smimesign-real}"
PKCS11_MODULE_DEFAULT="${PKCS11_MODULE_DEFAULT:-${REMOTE_PKCS11_MODULE:-/usr/lib64/pkcs11/p11-kit-client.so}}"
CERT_ID_DEFAULT="${CERT_ID_DEFAULT:-}"

needs_pin=0
needs_pkcs11=0

for arg in "$@"; do
  case "$arg" in
    --sign|--list-smartcard-keys)
      needs_pin=1
      needs_pkcs11=1
      ;;
    --list-keys)
      needs_pkcs11=1
      ;;
    -[!-]*)
      short_flags="${arg#-}"
      if [[ "$short_flags" == *s* ]]; then
        needs_pin=1
        needs_pkcs11=1
      fi
      ;;
  esac
done

if [[ $needs_pkcs11 -eq 1 ]]; then
  export SMIMESIGN_PKCS11_MODULE="${SMIMESIGN_PKCS11_MODULE:-$PKCS11_MODULE_DEFAULT}"
  if [[ -n "$CERT_ID_DEFAULT" ]]; then
    export SMIMESIGN_CERT_ID="${SMIMESIGN_CERT_ID:-$CERT_ID_DEFAULT}"
  fi
fi

if [[ $needs_pin -eq 1 && -z "${SMIMESIGN_PKCS11_PIN:-}" && -r /dev/tty && -w /dev/tty ]]; then
  printf 'YubiKey PIN: ' > /dev/tty
  IFS= read -r -s SMIMESIGN_PKCS11_PIN < /dev/tty
  printf '\n' > /dev/tty
  export SMIMESIGN_PKCS11_PIN
fi

exec "$REAL_SMIMESIGN" "$@"
