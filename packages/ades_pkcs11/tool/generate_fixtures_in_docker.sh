#!/usr/bin/env bash
# Regenerates fixtures/tier1/signatures/ours/softhsm-rsa2048-qsign.{p7m,p7s}:
# signed through ades_pkcs11 on a SoftHSM2 token, inside the Linux test
# container (nothing is installed on the host). Afterwards regenerate the
# tier-1 constants and the DSS goldens:
#   dart run tool/fixtures/generate_dart_constants.dart
#   dart run tool/dss_oracle/run.dart
#
#   packages/ades_pkcs11/tool/generate_fixtures_in_docker.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
IMAGE="${IMAGE:-ades-pkcs11-test}"
OUT="$ROOT/fixtures/tier1/signatures/ours"
mkdir -p "$OUT"

docker build -q -t "$IMAGE" -f "$ROOT/packages/ades_pkcs11/tool/Dockerfile" \
  "$ROOT/packages/ades_pkcs11/tool" >/dev/null

docker run --rm -v "$ROOT":/src:ro -v "$OUT":/out "$IMAGE" bash -euc '
  mkdir -p /work /tmp/softhsm/tokens
  tar -C /src --exclude=.dart_tool --exclude=.git --exclude=build -cf - . \
    | tar -C /work -xf -
  cat > /tmp/softhsm/softhsm2.conf <<EOF
directories.tokendir = /tmp/softhsm/tokens
objectstore.backend = file
log.level = ERROR
EOF
  export SOFTHSM2_CONF=/tmp/softhsm/softhsm2.conf
  export ADES_PKCS11_MODULE="$(find /usr/lib -name libsofthsm2.so | head -n1)"
  cd /work
  dart pub get >/dev/null
  dart run packages/ades_pkcs11/tool/generate_softhsm_fixtures.dart /out
'
