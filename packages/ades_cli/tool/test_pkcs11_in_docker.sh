#!/usr/bin/env bash
# Runs the ades_cli `--pkcs11` tests against SoftHSM2 in a Linux container
# (same image and approach as packages/ades_pkcs11/tool/test_in_docker.sh).
#
#   packages/ades_cli/tool/test_pkcs11_in_docker.sh [extra `dart test` args]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
IMAGE="${IMAGE:-ades-pkcs11-test}"

docker build -q -t "$IMAGE" -f "$ROOT/packages/ades_pkcs11/tool/Dockerfile" \
  "$ROOT/packages/ades_pkcs11/tool" >/dev/null

docker run --rm -v "$ROOT":/src:ro -e ADES_PKCS11_REQUIRED=1 "$IMAGE" bash -euc '
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
  echo "module: $ADES_PKCS11_MODULE"
  cd /work
  dart pub get >/dev/null
  cd packages/ades_cli
  dart test -p vm test/pkcs11_cli_test.dart "$@"
' bash "$@"
