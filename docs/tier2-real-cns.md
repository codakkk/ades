# Tier-2 procedure: real CNS card (MVP exit)

Exit criterion (ADR-0010, spec): a real CNS signature gets TOTAL-PASSED from DSS **and** our validator agrees. This is run by hand by a person holding a card. Nothing from the run is committed: a CNS signature carries name, surname and codice fiscale (personal data).

## What you need

- A CNS (Carta Nazionale dei Servizi) card, its reader and its PIN. A card with a qualified signing credential (non-repudiation) and an authentication credential is the target; test both.
- The card's vendor middleware (its PKCS#11 library) installed. Note its file path, vendor and **version**.
- The CA certificate that issued the card's certificates (the "CNS CA" or the issuing sub-CA), as a DER or PEM file. Take it from the issuer's published CA list (AgID trusted list, or the CA's website); do not export it from the signature. Use the **issuing** CA as the trust anchor for both tools: the card holds only the leaf and `ades sign` does not embed a chain, so a root-only anchor would make both tools report a missing intermediate.
- Docker (for the DSS harness) and Dart.

## Private working directory

Everything lives outside the repo, or under `tier2-private/` (git-ignored). Example:

```
export T2=$HOME/ades-tier2-private
mkdir -p $T2/pki $T2/content
cp /path/to/cns-issuing-ca.der $T2/pki/cns-ca.der   # openssl x509 -outform der if you have a PEM
printf 'tier-2 test document\n' > $T2/content/doc.txt
```

Use a throwaway document, never a real one.

## 1. Sign with the card

From the repo root:

```
dart run packages/ades_cli/bin/ades.dart sign $T2/content/doc.txt \
  --pkcs11 /path/to/middleware-library -o $T2/doc-qsign.p7m
```

- The tool lists every credential found on the card (number, label, token, key usage) and asks which to use. Skip the question with `--pkcs11-credential <number|label>`.
- `--pkcs11 auto` probes the known CNS middleware locations. Those paths were written from memory (ticket 14) and are unverified: if `auto` finds nothing, or finds the wrong library, pass the path. **If you had to pass the path, record the real location so the known list can be fixed.**
- The PIN is asked through the hidden prompt. A wrong PIN counts against the card's retry counter: after one failure, stop and check the reader and card rather than retrying. Never script the PIN.

Repeat for the other credential (`-o $T2/doc-auth.p7m`) and with `--detached` (`doc.txt.p7s`) if desired. Note which credential signed each file.

Expected today: the qualified credential signs. If a CNS generation refuses (unsupported mechanism, ECDSA card, certificate visible only after login, always-authenticate keys) see "Known gaps" below and record the exact error.

## 2. Validate with our validator

Use the same anchor, a validation time of now, and revocation ignored (we are offline and no real revocation data is fetched in the MVP):

```
dart run packages/ades_cli/bin/ades.dart validate $T2/doc-qsign.p7m \
  -t $T2/pki/cns-ca.der --ignore-revocation \
  --report-json $T2/ours-qsign.json
```

Expect `Indication: TOTAL-PASSED`, exit code 0. For a detached signature add `-d $T2/content/doc.txt`.

## 3. Validate with DSS (pinned oracle, offline)

The harness takes a fixtures directory with an `oracle-cases.json` (same format as `fixtures/tier1/oracle-cases.json`, paths relative to that directory). Write `$T2/oracle-cases.json`:

```
{
  "validationTime": "2026-11-10T12:00:00Z",
  "cases": [
    {"id":"cns-qsign","signature":"doc-qsign.p7m","anchor":"pki/cns-ca.der",
     "golden":"out/doc-qsign.dss-norev.json","policy":"no-revocation"}
  ]
}
```

Set `validationTime` to the current time in UTC (it must be after the signature was made and inside the certificates' validity), and add one case per signature file (`"content":"content/doc.txt"` for detached). Then:

```
dart run tool/dss_oracle/run.dart --fixtures $T2
```

Docker runs DSS 6.5.1 with `--network none` using the `no-revocation` policy (revocation data and acceptable-revocation checks IGNORE, our `--ignore-revocation`). The result lands in `$T2/out/*.json`. Expect `"indication": "TOTAL-PASSED"`.

Run the `default` policy too (change `policy`) and record what DSS says. It is expected to be INDETERMINATE (no revocation data offline); that is the same as our validator without `--ignore-revocation` (INDETERMINATE / TRY_LATER) and is not a failure.

## 4. Compare

Per signature compare ours with DSS:

- final indication and sub-indication (both TOTAL-PASSED);
- signing time (DSS `signingTime` vs the `Claimed signing time` we print);
- scope (both FULL).

Optionally compare blocks: `$T2/ours-qsign.json` (our detailed report) against `$T2/out/doc-qsign.dss-norev.json` (`blocks.FC|ISC|VCI|XCV|CV|SAV`). Known benign differences to DSS are in `fixtures/tier1/known-divergences.json`; anything not listed there is a finding to investigate.

If DSS passes and we do not (or the reverse), that is a bug in one of them: keep the signature private, get a diagnostic with `ades validate ... --diagnostic-json $T2/diag.json`, and reproduce it with a **synthetic** tier-1 fixture before filing anything public.

## 5. Record the result

Private (stays in `$T2`, never committed): the signatures, the DSS and our JSON output, screenshots, the certificate and anything with the holder's name or codice fiscale.

Public (no personal data): add one aggregate line to the roadmap map issue (M1 exit) and as a comment on the real-CNS MVP exit issue, containing only:

- date, DSS version, repo commit;
- card generation / issuer family and chip or card model if printed on the card (not the serial number);
- middleware vendor, library file name and **version**, and OS;
- credentials tried (qualified / authentication), algorithm (RSA size or EC curve);
- per credential: DSS indication, our indication, agree yes/no;
- any divergence or error text with all names, serials and the codice fiscale removed.

Then tick the last two boxes of the real-CNS MVP exit issue and close it.

## Known gaps to expect on real cards

From ticket 13/14 (not verifiable without hardware):

- RSA PKCS#1 v1.5 only (CKM_RSA_PKCS). ECDSA-only cards fail with a clear error; implementing CKM_ECDSA is the fix.
- The certificate must be readable without login. If listing shows no credentials with a card inserted, middleware may require login first.
- Keys flagged always-authenticate (re-login per signature) are not handled.
- The signature has no chain embedded; validation needs the issuing CA as anchor (above). Embedding the chain is a later feature.
- Known middleware paths are unverified; fix `knownCnsMiddleware` in `packages/ades_pkcs11/lib/src/discovery.dart` with what you find.
