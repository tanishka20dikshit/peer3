#!/usr/bin/env bash
set -euo pipefail

# You will execute this script under server/src/scripts
# Based on the script's own location, locate the server module root directory
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MODULE_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"   # .../server
KEYS_RES="$MODULE_DIR/resources/config/keys"

mkdir -p "$KEYS_RES"

PRIV_PEM="server_private.pem"                  # Private key (PKCS#8, BEGIN PRIVATE KEY)
PUB_PEM="server_public.pem"                    # Public key (PEM/SPKI)
PUB_DER="server_public.der"                    # Public key (DER/SPKI)
PUB_B64U_TXT="server_public_spki.base64url.txt"

echo "==> Module dir: $MODULE_DIR"
echo "==> Output dir: $KEYS_RES"
echo "==> Generating RSA-4096 private key (PKCS#8)…"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 \
  -out "$KEYS_RES/$PRIV_PEM"

echo "==> Deriving public key (PEM/SPKI)…"
openssl pkey -in "$KEYS_RES/$PRIV_PEM" -pubout \
  -out "$KEYS_RES/$PUB_PEM"

echo "==> Deriving public key (DER/SPKI)…"
openssl pkey -in "$KEYS_RES/$PRIV_PEM" -pubout -outform DER \
  -out "$KEYS_RES/$PUB_DER"

echo "==> Computing base64url(SPKI DER) for pinning…"
# Compatible with macOS (no -w) and Linux (with -w0)
if base64 --help 2>&1 | grep -q -- "-w"; then
  B64_STD="$(base64 -w0 < "$KEYS_RES/$PUB_DER")"
else
  B64_STD="$(base64 < "$KEYS_RES/$PUB_DER" | tr -d '\n')"
fi
B64_URL="${B64_STD//+/-}"; B64_URL="${B64_URL//\//_}"; B64_URL="${B64_URL//=}"
printf "%s\n" "$B64_URL" > "$KEYS_RES/$PUB_B64U_TXT"

# Tighten permissions (optional)
chmod 600 "$KEYS_RES/$PRIV_PEM" || true
chmod 644 "$KEYS_RES/$PUB_PEM" "$KEYS_RES/$PUB_DER" "$KEYS_RES/$PUB_B64U_TXT" || true

echo
echo "Done. Keys are in: $KEYS_RES"
echo "Pinned pubkey (base64url):"
echo "$B64_URL"
