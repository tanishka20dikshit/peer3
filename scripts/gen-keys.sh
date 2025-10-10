#!/usr/bin/env bash
set -euo pipefail

# ------------------------------------------------------------------------------
# gen-keys.sh  —  generate RSA-4096 keypairs for "server" and/or "introducer"
# Layout assumption: this script lives in <repo>/scripts, alongside:
#   <repo>/server, <repo>/introducer
# Output dir per module: <module>/src/main/resources/config/keys
#
# Usage:
#   ./gen-keys.sh                    # both modules
#   ./gen-keys.sh --module server    # only server
#   ./gen-keys.sh --module introducer
#   ./gen-keys.sh --force            # overwrite existing files
# ------------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"   # <-- fix: repo root is one level up

FORCE=0
MODULE="both"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --force) FORCE=1; shift ;;
    --module)
      MODULE="${2:-both}"; shift 2 ;;
    -h|--help)
      echo "Usage: $0 [--module server|introducer|both] [--force]"
      exit 0 ;;
    *) shift ;;
  esac
done

have() { command -v "$1" >/dev/null 2>&1; }
have openssl || { echo "ERROR: openssl not found"; exit 1; }
have base64  || { echo "ERROR: base64 not found"; exit 1; }

# choose resource dir: always under src/main/resources/config/keys (create if missing)
res_dir() {
  local module_dir="$1"
  echo "$module_dir/src/main/resources/config/keys"
}

# cross-platform base64url (no padding, single line)
to_b64u() {
  if base64 --help 2>&1 | grep -q -- "-w"; then
    base64 -w0
  else
    base64 | tr -d '\n'
  fi | sed -e 's/+/-/g' -e 's/\//_/g' -e 's/=//g'
}

gen_for_module() {
  local name="$1"                                # server | introducer
  local module_dir="$REPO_ROOT/$name"
  if [[ ! -d "$module_dir" ]]; then
    echo "WARN: module directory not found: $module_dir (skipping $name)"
    return 0
  fi

  local out_dir; out_dir="$(res_dir "$module_dir")"
  mkdir -p "$out_dir"

  local PRIV_PEM="${name}_private.pem"
  local PUB_PEM="${name}_public.pem"
  local PUB_DER="${name}_public.der"
  local PUB_B64U_TXT="${name}_public_spki.base64url.txt"

  echo "==> Module: $name"
  echo "==> Output: $out_dir"

  if [[ $FORCE -eq 0 && -f "$out_dir/$PRIV_PEM" && -f "$out_dir/$PUB_B64U_TXT" ]]; then
    echo "==> Keys already exist, skipping (use --force to overwrite)."
    echo "Pinned pubkey (base64url): $(cat "$out_dir/$PUB_B64U_TXT")"
    echo
    return 0
  fi

  echo "==> Generating RSA-4096 private key (PKCS#8)…"
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 \
    -out "$out_dir/$PRIV_PEM"

  echo "==> Deriving public key (PEM/SPKI)…"
  openssl pkey -in "$out_dir/$PRIV_PEM" -pubout \
    -out "$out_dir/$PUB_PEM"

  echo "==> Deriving public key (DER/SPKI)…"
  openssl pkey -in "$out_dir/$PRIV_PEM" -pubout -outform DER \
    -out "$out_dir/$PUB_DER"

  echo "==> Computing base64url(SPKI DER)…"
  local B64_URL
  B64_URL="$(to_b64u < "$out_dir/$PUB_DER")"
  printf "%s\n" "$B64_URL" > "$out_dir/$PUB_B64U_TXT"

  chmod 600 "$out_dir/$PRIV_PEM" || true
  chmod 644 "$out_dir/$PUB_PEM" "$out_dir/$PUB_DER" "$out_dir/$PUB_B64U_TXT" || true

  echo "Done: $out_dir/$PRIV_PEM"
  echo "Pinned pubkey (base64url):"
  echo "$B64_URL"
  echo
}

case "$MODULE" in
  server)      gen_for_module server ;;
  introducer)  gen_for_module introducer ;;
  both|*)      gen_for_module server; gen_for_module introducer ;;
esac

echo "All done."
