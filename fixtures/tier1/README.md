# Tier-1 fixtures (public, synthetic)

Made by OpenSSL 3 from our own test CAs, never by our Dart code (ADR-0010). All identities are fake: subject `TESTSURNAME TESTGIVEN`, codice fiscale `TINIT-TSTSRN80A01Z000X` (invalid pattern on purpose). The private keys are committed test keys and protect nothing. The policy OID `1.3.6.1.4.1.99999.1.1` is a fake arc.

Regenerate: `tool/fixtures/generate.sh`. Check independently with OpenSSL: `tool/fixtures/verify.sh`. Details of what is and is not deterministic are in the header of `generate.sh`.

## `pki/<hierarchy>/`

Hierarchies `rsa2048` (RSA-2048, sha256WithRSA) and `p256` (ECDSA P-256, ecdsa-with-SHA256), plus `untrusted-rsa2048` (a second, unrelated RSA root). Each has `root`, `intermediate`, `leaf-qsign` and, except for the untrusted one, `leaf-auth`, as `.pem`, `.der`, `.key` (PKCS#8, unencrypted) and, for leaves, `.p12` (password `test`, includes the intermediate).

| Certificate | Profile |
|---|---|
| root | CA, pathlen 1, keyCertSign+cRLSign, valid 2020-01-01 to 2049-12-31 |
| intermediate | CA, pathlen 0, keyCertSign+cRLSign, same validity |
| leaf-auth | copies CNS authentication: keyUsage digitalSignature only, EKU clientAuth, policy |
| leaf-qsign | copies CNS qualified signing: keyUsage nonRepudiation only, policies incl. QCP-n-qscd `0.4.0.194112.1.2`, QCStatements QcCompliance, QcSSCD, QcPDS, QcType=esign |
| rsa2048 only: leaf-qsign-expired | qsign profile, valid 2020-01-01 to 2021-01-01 |
| rsa2048 only: leaf-noku | keyUsage keyEncipherment only |
| rsa2048 only: leaf-under-leaf | qsign profile, issued by leaf-auth (a non-CA) |
| rsa2048 only: sub-ca, leaf-under-sub-ca | sub-ca is a CA issued by the pathlen-0 intermediate; leaf-under-sub-ca (qsign profile) is issued by sub-ca |

Leaves are valid 2024-01-01 to 2049-12-31 (UTCTime maximum), except the expired one.

## `content/`

`hello.txt` is the signed document. `hello-tampered.txt` differs by one added byte.

## `signatures/positive/` (all CAdES-B-B: contentType, messageDigest, signingTime, signingCertificateV2, SHA-256; embedded certificates are leaf + intermediate, no root)

`{rsa2048,p256}-{qsign,auth}.p7m` (enveloping) and `.p7s` (detached, content `content/hello.txt`). They exercise the happy path for both key types and both credential profiles. Trust anchor: the hierarchy's `root.pem`.

## `signatures/negative/` (all RSA-2048, enveloping unless noted; trust anchor `pki/rsa2048/root.pem`)

| File | Exercises | Expected from a validator |
|---|---|---|
| `rsa2048-tampered-content.p7m` | one embedded content byte flipped | message digest mismatch (TOTAL-FAILED, HASH_FAILURE) |
| (`positive/rsa2048-qsign.p7s` + `content/hello-tampered.txt`) | detached content tampered | same |
| `rsa2048-wrong-message-digest.p7m` | messageDigest attribute altered, then re-signed so the signature is valid | digest mismatch with a valid signature value |
| `rsa2048-non-der-signed-attrs.p7m` | signed attributes `SET OF` in non-DER order, signed as transmitted | strict DER reject; note OpenSSL accepts it |
| `rsa2048-expired-leaf.p7m` | leaf expired in 2021, valid chain | certificate expired at validation time |
| `rsa2048-no-signing-key-usage.p7m` | leaf has keyEncipherment only | wrong key usage, no signing KU |
| `rsa2048-untrusted-root.p7m` | chain to `untrusted-rsa2048` root | untrusted anchor (trusted only with `pki/untrusted-rsa2048/root.pem`) |
| `rsa2048-missing-intermediate.p7m` | only the leaf is embedded | path cannot be built unless the intermediate is supplied |
| `rsa2048-issuer-not-ca.p7m` | leaf-under-leaf, embedded leaf-auth + intermediate | CA flag violation (issuer is not a CA) |
| `rsa2048-path-length-exceeded.p7m` | leaf-under-sub-ca, embedded sub-ca + intermediate | path length constraint of the intermediate exceeded |

The wrong-digest and non-DER files are derived from `positive/rsa2048-qsign.p7m` by `tool/fixtures/mutate_cms.py` (byte patching, re-signing through `openssl dgst`).

## `signatures/ber/` (ticket 11; RSA-2048 qsign leaf, trust anchor `pki/rsa2048/root.pem`)

Made by `tool/fixtures/generate_ber.sh` (also run at the end of `generate.sh`) with `openssl cms -sign -stream`: indefinite-length outer structures and the content as a constructed OCTET STRING of segments, like legacy Italian signing tools. The signed attributes are DER (OpenSSL always writes them so).

| File | Exercises | Expected from a validator |
|---|---|---|
| `rsa2048-qsign-indef.p7m` | content `content/hello.txt`, one segment | same verdict as the DER `positive/rsa2048-qsign.p7m`, plus warnings (indefinite length, constructed OCTET STRING) |
| `rsa2048-qsign-indef-chunked.p7m` | content `content/ber-chunked.txt` (20000 bytes), several segments | same, over the segmented content |

## DSS oracle goldens

Signed by our code (ticket 08/10) with tier-1 keys: `signatures/ours/` (`tool`: `dart run packages/ades_soft/tool/generate_signed_fixtures.dart`). DSS goldens: `*.dss.json`, `*.dss-norev.json` next to each fixture (including `signatures/ber/`); manifest `oracle-cases.json`; `known-divergences.json`. See `tool/dss_oracle/README.md`.
