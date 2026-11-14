#!/usr/bin/env bash
# Regenerates the tier-1 fixtures with OpenSSL 3 (never our Dart code, ADR-0010).
#
#   tool/fixtures/generate.sh              # regenerate into fixtures/tier1 (keeps committed keys)
#   NEW_KEYS=1 tool/fixtures/generate.sh   # also mint new private keys
#   FIXTURES_DIR=/tmp/x tool/fixtures/generate.sh
#
# Determinism: private keys are committed and reused, serials and validity dates are fixed,
# RSA PKCS#1 v1.5 signatures are deterministic, so RSA certificates regenerate byte for byte.
# NOT deterministic: ECDSA signatures (P-256 certificates), the CMS signingTime attribute
# (every .p7m/.p7s) and PKCS#12 salts. Review such diffs as expected churn.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
. "$here/common.sh"
F="${FIXTURES_DIR:-$here/../../fixtures/tier1}"
mkdir -p "$F"; F="$(cd "$F" && pwd)"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

CA_NB=20200101000000Z   # CA and leaf validity: far enough in the future (UTCTime maximum is 2049)
NB=20240101000000Z
NA=20491231235959Z
POLICY_OID=1.3.6.1.4.1.99999.1.1   # fake policy arc, not a real CA's
P12_PASSWORD=test

# --- key and certificate helpers -------------------------------------------------------
mkkey() { # <rsa|ec> <path>
  [ -f "$2" ] && [ -z "${NEW_KEYS:-}" ] && return 0
  if [ "$1" = rsa ]; then
    "$OPENSSL" genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$2" 2>/dev/null
  else
    "$OPENSSL" genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$2"
  fi
}

# issue <dir> <name> <subj> <serial> <notBefore> <notAfter> <profile> <issuer-name|self>
issue() {
  local d=$1 n=$2 subj=$3 serial=$4 nb=$5 na=$6 profile=$7 issuer=$8
  local ext="$TMP/$n.ext"; profile_ext "$profile" >"$ext"
  "$OPENSSL" req -new -key "$d/$n.key" -subj "$subj" -sha256 -out "$TMP/$n.csr"
  local signargs
  if [ "$issuer" = self ]; then signargs=(-signkey "$d/$n.key")
  else signargs=(-CA "$d/$issuer.pem" -CAkey "$d/$issuer.key"); fi
  "$OPENSSL" x509 -req -in "$TMP/$n.csr" "${signargs[@]}" -sha256 -set_serial "$serial" \
    -not_before "$nb" -not_after "$na" -extfile "$ext" -out "$d/$n.pem" 2>/dev/null
  "$OPENSSL" x509 -in "$d/$n.pem" -outform DER -out "$d/$n.der"
}

profile_ext() {
  case "$1" in
  root) cat <<EOF
basicConstraints = critical,CA:TRUE,pathlen:1
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
EOF
  ;;
  intermediate) cat <<EOF
basicConstraints = critical,CA:TRUE,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
EOF
  ;;
  # CNS authentication credential: digitalSignature only, client authentication.
  auth) cat <<EOF
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
certificatePolicies = $POLICY_OID
EOF
  ;;
  # CNS qualified signing credential: nonRepudiation only, QC policy + QCStatements.
  qsign|qsign-expired|qsign-deep) cat <<EOF
basicConstraints = critical,CA:FALSE
keyUsage = critical,nonRepudiation
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
certificatePolicies = $POLICY_OID,0.4.0.194112.1.2
1.3.6.1.5.5.7.1.3 = ASN1:SEQUENCE:qcStatements

[qcStatements]
qcCompliance = SEQUENCE:qcCompliance
qcSSCD = SEQUENCE:qcSSCD
qcPDS = SEQUENCE:qcPDS
qcType = SEQUENCE:qcType

[qcCompliance]
id = OID:0.4.0.1862.1.1

[qcSSCD]
id = OID:0.4.0.1862.1.4

[qcPDS]
id = OID:0.4.0.1862.1.5
locations = SEQUENCE:pdsLocations

[pdsLocations]
loc1 = SEQUENCE:pdsLocation

[pdsLocation]
url = IA5STRING:https://fixtures.invalid/pds-en.pdf
lang = PRINTABLESTRING:en

[qcType]
id = OID:0.4.0.1862.1.6
types = SEQUENCE:qcTypes

[qcTypes]
esign = OID:0.4.0.1862.1.6.1
EOF
  ;;
  # Negative: certificate that must not sign (encipherment only).
  noku) cat <<EOF
basicConstraints = critical,CA:FALSE
keyUsage = critical,keyEncipherment
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
certificatePolicies = $POLICY_OID
EOF
  ;;
  # Negative: a CA issued below the pathlen:0 intermediate (violates its path length).
  subca) cat <<EOF
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
EOF
  ;;
  esac
}

# Fake identity. TINIT-<16 char codice fiscale> uses a deliberately invalid pattern (city Z000).
person() { # <suffix>
  echo "/C=IT/O=ADES Test Fixtures/serialNumber=TINIT-TSTSRN80A01Z000X/SN=TESTSURNAME/GN=TESTGIVEN/CN=TESTSURNAME TESTGIVEN $1"
}

# hierarchy <dir> <rsa|ec> <label> <serial-base> <with-leaves: full|qsign>
hierarchy() {
  local d=$1 alg=$2 label=$3 s=$4 mode=$5
  mkdir -p "$d"
  for n in root intermediate leaf-qsign; do mkkey "$alg" "$d/$n.key"; done
  issue "$d" root "/C=IT/O=ADES Test Fixtures/CN=ADES Test Root CA $label" $((s+1)) $CA_NB $NA root self
  issue "$d" intermediate "/C=IT/O=ADES Test Fixtures/CN=ADES Test Intermediate CA $label" $((s+2)) $CA_NB $NA intermediate root
  issue "$d" leaf-qsign "$(person "(qualified signing)")" $((s+3)) $NB $NA qsign intermediate
  if [ "$mode" = full ]; then
    mkkey "$alg" "$d/leaf-auth.key"
    issue "$d" leaf-auth "$(person "(authentication)")" $((s+4)) $NB $NA auth intermediate
  fi
  for n in leaf-qsign leaf-auth; do
    [ -f "$d/$n.pem" ] || continue
    "$OPENSSL" pkcs12 -export -inkey "$d/$n.key" -in "$d/$n.pem" -certfile "$d/intermediate.pem" \
      -name "$n" -passout "pass:$P12_PASSWORD" -out "$d/$n.p12"
  done
}

# --- PKI ------------------------------------------------------------------------------
PKI="$F/pki"
hierarchy "$PKI/rsa2048" rsa "RSA-2048" 1000 full
hierarchy "$PKI/p256" ec "P-256" 2000 full
hierarchy "$PKI/untrusted-rsa2048" rsa "Untrusted RSA-2048" 3000 qsign

# RSA-only negative leaves, issued by the trusted RSA intermediate.
R="$PKI/rsa2048"
for n in leaf-qsign-expired leaf-noku; do mkkey rsa "$R/$n.key"; done
issue "$R" leaf-qsign-expired "$(person "(expired)")" 1010 20200101000000Z 20210101000000Z qsign-expired intermediate
issue "$R" leaf-noku "$(person "(no signing key usage)")" 1011 $NB $NA noku intermediate

# Path-validation negatives (ticket 05).
#  leaf-under-leaf: signed by leaf-auth, which is not a CA (CA:FALSE, no keyCertSign).
#  sub-ca: CA issued by the pathlen:0 intermediate; leaf-under-sub-ca below it breaks the path length.
for n in leaf-under-leaf sub-ca leaf-under-sub-ca; do mkkey rsa "$R/$n.key"; done
issue "$R" leaf-under-leaf "$(person "(issued by a non-CA)")" 1012 $NB $NA qsign leaf-auth
issue "$R" sub-ca "/C=IT/O=ADES Test Fixtures/CN=ADES Test Sub CA RSA-2048" 1013 $CA_NB $NA subca intermediate
issue "$R" leaf-under-sub-ca "$(person "(path length violation)")" 1014 $NB $NA qsign-deep sub-ca

# --- content --------------------------------------------------------------------------
mkdir -p "$F/content" "$F/signatures/positive" "$F/signatures/negative"
printf 'ades tier-1 fixture content\n' >"$F/content/hello.txt"
printf 'ades tier-1 fixture content!\n' >"$F/content/hello-tampered.txt"
C="$F/content/hello.txt"

# --- signatures -----------------------------------------------------------------------
# cms_sign <out> <detached|enveloping> <dir> <leaf-name> <certfile-or-none>
cms_sign() {
  local out=$1 mode=$2 d=$3 leaf=$4 certfile=$5
  local args=(-sign -binary -in "$C" -signer "$d/$leaf.pem" -inkey "$d/$leaf.key" -md sha256
              -cades -nosmimecap -outform DER -out "$out")
  [ "$certfile" != none ] && args+=(-certfile "$certfile")
  [ "$mode" = enveloping ] && args+=(-nodetach)
  "$OPENSSL" cms "${args[@]}"
}

for k in rsa2048 p256; do
  d="$PKI/$k"
  for leaf in qsign auth; do
    cms_sign "$F/signatures/positive/$k-$leaf.p7m" enveloping "$d" "leaf-$leaf" "$d/intermediate.pem"
    cms_sign "$F/signatures/positive/$k-$leaf.p7s" detached "$d" "leaf-$leaf" "$d/intermediate.pem"
  done
done

N="$F/signatures/negative"
MUT="python3 -I $here/mutate_cms.py"
good="$F/signatures/positive/rsa2048-qsign.p7m"
$MUT tamper-content "$good" "$N/rsa2048-tampered-content.p7m"
$MUT wrong-digest "$good" "$N/rsa2048-wrong-message-digest.p7m" "$R/leaf-qsign.key" "$OPENSSL"
$MUT non-der-attrs "$good" "$N/rsa2048-non-der-signed-attrs.p7m" "$R/leaf-qsign.key" "$OPENSSL"
cms_sign "$N/rsa2048-expired-leaf.p7m" enveloping "$R" leaf-qsign-expired "$R/intermediate.pem"
cms_sign "$N/rsa2048-no-signing-key-usage.p7m" enveloping "$R" leaf-noku "$R/intermediate.pem"
U="$PKI/untrusted-rsa2048"
cms_sign "$N/rsa2048-untrusted-root.p7m" enveloping "$U" leaf-qsign "$U/intermediate.pem"
cms_sign "$N/rsa2048-missing-intermediate.p7m" enveloping "$R" leaf-qsign none
cat "$R/leaf-auth.pem" "$R/intermediate.pem" >"$TMP/chain-nonca.pem"
cms_sign "$N/rsa2048-issuer-not-ca.p7m" enveloping "$R" leaf-under-leaf "$TMP/chain-nonca.pem"
cat "$R/sub-ca.pem" "$R/intermediate.pem" >"$TMP/chain-subca.pem"
cms_sign "$N/rsa2048-path-length-exceeded.p7m" enveloping "$R" leaf-under-sub-ca "$TMP/chain-subca.pem"

FIXTURES_DIR="$F" "$here/generate_ber.sh"

echo "fixtures written to $F"
