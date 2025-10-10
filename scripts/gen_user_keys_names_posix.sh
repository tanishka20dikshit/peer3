#!/bin/sh
# Portable generator: works with /bin/sh (no associative arrays).

set -eu

# --- anchor to script dir ---
DIR="$(cd "$(dirname "$0")" && pwd)"
KEY_DIR="$DIR/config/keys/users_by_name"
DATA_DIR="$DIR/data"
OUT_JSON="$DATA_DIR/user-keys.json"

# Names only (case-sensitive; "Allen" intentionally capitalized)
NAMES="alice bob charlie david ella"

mkdir -p "$KEY_DIR" "$DATA_DIR"

# base64url helper (reads stdin)
b64url() {
  openssl base64 -A | tr '+/' '-_' | tr -d '='
}

# start JSON
printf '{\n  "users": {\n' > "$OUT_JSON"
first=1

for name in $NAMES; do
  s_priv="$KEY_DIR/${name}_sign_private.pem"
  s_pub="$KEY_DIR/${name}_sign_public.pem"
  e_priv="$KEY_DIR/${name}_enc_private.pem"
  e_pub="$KEY_DIR/${name}_enc_public.pem"

  # generate signing keypair
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out "$s_priv"
  openssl rsa -pubout -in "$s_priv" -out "$s_pub"

  # generate encryption keypair
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out "$e_priv"
  openssl rsa -pubout -in "$e_priv" -out "$e_pub"

  # export SPKI DER -> base64url
  sign_b64="$(openssl pkey -in "$s_pub" -pubin -outform DER | b64url)"
  enc_b64="$(openssl pkey -in "$e_pub" -pubin -outform DER | b64url)"

  # append JSON entry
  if [ "$first" -eq 1 ]; then
    first=0
  else
    printf ',\n' >> "$OUT_JSON"
  fi

  printf '    "%s": {\n' "$name" >> "$OUT_JSON"
  printf '      "sign_pub": "%s",\n' "$sign_b64" >> "$OUT_JSON"
  printf '      "enc_pub": "%s",\n' "$enc_b64" >> "$OUT_JSON"
  printf '      "state": "active"\n' >> "$OUT_JSON"
  printf '    }' >> "$OUT_JSON"
done

printf '\n  }\n}\n' >> "$OUT_JSON"

echo "✅ Keys: $KEY_DIR"
echo "✅ JSON: $OUT_JSON"