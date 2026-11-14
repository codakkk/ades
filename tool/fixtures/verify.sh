#!/usr/bin/env bash
# Independent check of the tier-1 fixtures using OpenSSL 3 only (never our Dart code).
# Positive fixtures must verify; negative fixtures must fail for the expected reason.
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
. "$here/common.sh"
F="${FIXTURES_DIR:-$here/../../fixtures/tier1}"
fails=0
ok()  { echo "ok   $*"; }
bad() { echo "FAIL $*"; fails=$((fails+1)); }

# verify_cms <name> <pass|fail> <err-regex> <root> <file> <content-or-empty> [extra openssl args...]
verify_cms() {
  local name=$1 expect=$2 want=$3 root=$4 file=$5 content=$6
  shift 6
  local args=(-verify -inform DER -in "$file" -CAfile "$root" -binary -out /dev/null "$@")
  [ -n "$content" ] && args+=(-content "$content")
  local err rc
  err=$("$OPENSSL" cms "${args[@]}" 2>&1); rc=$?
  if [ "$expect" = pass ]; then
    if [ $rc -eq 0 ]; then ok "$name"; else bad "$name should verify: $err"; fi
  else
    if [ $rc -ne 0 ] && grep -qiE -- "$want" <<<"$err"; then ok "$name fails ($want)"
    else bad "$name should fail with '$want' (rc=$rc): $err"; fi
  fi
}

C="$F/content/hello.txt"
ANY=(-purpose any)
for k in rsa2048 p256; do
  R="$F/pki/$k/root.pem"
  for leaf in qsign auth; do
    P="$F/signatures/positive/$k-$leaf"
    verify_cms "$k $leaf p7m" pass "" "$R" "$P.p7m" "" "${ANY[@]}"
    verify_cms "$k $leaf p7s" pass "" "$R" "$P.p7s" "$C" "${ANY[@]}"
    dump=$("$OPENSSL" asn1parse -inform DER -in "$P.p7m")
    if grep -q signingCertificateV2 <<<"$dump"; then ok "$k $leaf has signingCertificateV2"; else bad "$k $leaf lacks signingCertificateV2"; fi
    if grep -q sha256 <<<"$dump"; then ok "$k $leaf uses sha256"; else bad "$k $leaf not sha256"; fi
  done
  if "$OPENSSL" verify -CAfile "$R" -untrusted "$F/pki/$k/intermediate.pem" "$F/pki/$k/leaf-qsign.pem" >/dev/null 2>&1; then ok "$k chain verifies"; else bad "$k chain does not verify"; fi
  qs=$("$OPENSSL" x509 -in "$F/pki/$k/leaf-qsign.pem" -noout -text)
  au=$("$OPENSSL" x509 -in "$F/pki/$k/leaf-auth.pem" -noout -text)
  if grep -q 'Non Repudiation' <<<"$qs" && ! grep -q 'Digital Signature' <<<"$qs"; then ok "$k qsign KU=nonRepudiation"; else bad "$k qsign KU"; fi
  if grep -q 'Digital Signature' <<<"$au" && ! grep -q 'Non Repudiation' <<<"$au"; then ok "$k auth KU=digitalSignature"; else bad "$k auth KU"; fi
  hex=$("$OPENSSL" x509 -in "$F/pki/$k/leaf-qsign.pem" -outform DER | xxd -p | tr -d '\n')
  if grep -q 'qcStatements' <<<"$qs"; then ok "$k qsign has QCStatements"; else bad "$k qsign has no QCStatements extension"; fi
  # OID 0.4.0.1862.1.{1 QcCompliance, 4 QcSSCD, 5 QcPDS, 6 QcType} and 1.6.1 (esign)
  for tail in 0101 0104 0105 0106 010601; do
    len=$(printf '%02x' $(( ${#tail} / 2 + 4 )))
    if grep -q "06${len}04008e46${tail}" <<<"$hex"; then :; else bad "$k qsign QCStatement OID 0.4.0.1862.1.$tail missing"; fi
  done
  if grep -q 'Policy: 0.4.0.194112.1.2' <<<"$qs"; then ok "$k qsign QCP-n-qscd policy"; else bad "$k qsign policy"; fi
  if grep -q 'TINIT-' <<<"$qs"; then ok "$k fake codice fiscale"; else bad "$k codice fiscale"; fi
done

N="$F/signatures/negative"; R="$F/pki/rsa2048/root.pem"
verify_cms "tampered enveloping content" fail "CMS_SignerInfo_verify_content" "$R" "$N/rsa2048-tampered-content.p7m" "" "${ANY[@]}"
verify_cms "tampered detached content" fail "CMS_SignerInfo_verify_content" "$R" "$F/signatures/positive/rsa2048-qsign.p7s" "$F/content/hello-tampered.txt" "${ANY[@]}"
verify_cms "wrong messageDigest attr" fail "CMS_SignerInfo_verify_content" "$R" "$N/rsa2048-wrong-message-digest.p7m" "" "${ANY[@]}"
# OpenSSL signs/verifies the attribute bytes as transmitted, so it accepts the unsorted SET OF.
# A strict DER validator must reject it (see the fixture README); OpenSSL leniency is expected.
verify_cms "non-DER signed attrs (OpenSSL is lenient)" pass "" "$R" "$N/rsa2048-non-der-signed-attrs.p7m" "" "${ANY[@]}"
verify_cms "expired leaf" fail "expired" "$R" "$N/rsa2048-expired-leaf.p7m" "" "${ANY[@]}"
verify_cms "expired leaf (ok with -no_check_time)" pass "" "$R" "$N/rsa2048-expired-leaf.p7m" "" "${ANY[@]}" -no_check_time
verify_cms "leaf without signing KU" fail "purpose" "$R" "$N/rsa2048-no-signing-key-usage.p7m" "" -purpose smimesign
verify_cms "untrusted root" fail "unable to get issuer|self.signed|unable to get local issuer" "$R" "$N/rsa2048-untrusted-root.p7m" "" "${ANY[@]}"
verify_cms "untrusted root (ok with its own root)" pass "" "$F/pki/untrusted-rsa2048/root.pem" "$N/rsa2048-untrusted-root.p7m" "" "${ANY[@]}"
verify_cms "missing intermediate" fail "unable to get local issuer" "$R" "$N/rsa2048-missing-intermediate.p7m" "" "${ANY[@]}"
verify_cms "missing intermediate (ok with -certfile)" pass "" "$R" "$N/rsa2048-missing-intermediate.p7m" "" "${ANY[@]}" -certfile "$F/pki/rsa2048/intermediate.pem"
# CA-flag and path-length violations (ticket 05): OpenSSL must reject them for that reason only.
verify_cms "issuer is not a CA" fail "invalid CA certificate|unsuitable certificate purpose|invalid purpose" "$R" "$N/rsa2048-issuer-not-ca.p7m" "" "${ANY[@]}"
verify_cms "path length exceeded" fail "path length constraint exceeded" "$R" "$N/rsa2048-path-length-exceeded.p7m" "" "${ANY[@]}"

# BER variants (ticket 11): indefinite-length outer structures from `cms -sign -stream`.
B="$F/signatures/ber"
for f in rsa2048-qsign-indef rsa2048-qsign-indef-chunked; do
  verify_cms "BER $f" pass "" "$R" "$B/$f.p7m" "" "${ANY[@]}"
  if "$OPENSSL" asn1parse -inform DER -in "$B/$f.p7m" | sed -n 1p | grep -q 'l=inf'; then ok "BER $f is indefinite-length"; else bad "BER $f is not indefinite-length"; fi
done
if "$OPENSSL" asn1parse -inform DER -in "$B/rsa2048-qsign-indef-chunked.p7m" | grep -c 'prim: OCTET STRING' | grep -qv '^1$'; then ok "BER chunked content has several segments"; else bad "BER chunked content is a single segment"; fi

if [ $fails -eq 0 ]; then echo "ALL OK"; else echo "$fails failure(s)"; exit 1; fi
