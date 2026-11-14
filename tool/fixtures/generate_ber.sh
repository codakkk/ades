#!/usr/bin/env bash
# BER-variant tier-1 fixtures (ticket 11), made with OpenSSL 3 only (ADR-0010).
#
#   tool/fixtures/generate_ber.sh        # standalone: adds signatures/ber/ and content/ber-chunked.txt
#
# `openssl cms -sign -stream` writes the outer structures with indefinite lengths and the
# encapsulated content as a constructed OCTET STRING of segments, like Italian signing tools
# do. Called at the end of generate.sh; standalone use leaves every other fixture untouched
# (regenerating those churns all signatures). Requires the PKI from generate.sh.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
. "$here/common.sh"
F="${FIXTURES_DIR:-$here/../../fixtures/tier1}"
F="$(cd "$F" && pwd)"
R="$F/pki/rsa2048"
mkdir -p "$F/signatures/ber"

# Larger than OpenSSL's streaming buffer, so the content becomes several segments.
set +o pipefail  # yes dies of SIGPIPE when head is done
yes 'ades tier-1 BER chunking line, deterministic filler' | head -c 20000 >"$F/content/ber-chunked.txt"
set -o pipefail

ber_sign() { # <content> <out>
  "$OPENSSL" cms -sign -stream -binary -nodetach -in "$1" -signer "$R/leaf-qsign.pem" \
    -inkey "$R/leaf-qsign.key" -md sha256 -cades -nosmimecap -certfile "$R/intermediate.pem" \
    -outform DER -out "$2"
}
ber_sign "$F/content/hello.txt" "$F/signatures/ber/rsa2048-qsign-indef.p7m"
ber_sign "$F/content/ber-chunked.txt" "$F/signatures/ber/rsa2048-qsign-indef-chunked.p7m"
echo "BER fixtures written to $F/signatures/ber"
