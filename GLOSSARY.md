# ades

Dart libraries for creating and validating AdES signatures (CAdES, PAdES, XAdES, JAdES, ASiC) under eIDAS and the ETSI EN 319 1xx family.

## Actors and keys

**Signer**:
The natural or legal person who signs, as ETSI and eIDAS use the term. Never the software component that produces the signature value.
_Avoid_: Signer (for the key abstraction), signatory

**Signing credential**:
A private key the library cannot access directly, together with its certificate (and optionally its chain), that can produce signature values on request.
_Avoid_: Signer, signing key, token, device

**Signing vehicle**:
The transport that provides signing credentials: a smartcard/HSM over PKCS#11, a remote service over CSC, and so on. Each one lives in its own package, outside the core.
_Avoid_: Backend, provider, driver

## Signature creation

**DTBS** (Data To Be Signed):
The exact bytes the signature value covers: the DER-encoded CMS signed attributes, the canonicalized `ds:SignedInfo`, or the JWS signing input. Never the document itself.
_Avoid_: payload, tbs, data

**DTBSR** (DTBS Representation):
The hash of the DTBS under the chosen digest algorithm, as handed to a signing credential that signs digests.
_Avoid_: hash to sign, digest (unqualified)

**Signature draft**:
The immutable result of the first phase of signing: chosen parameters, frozen signing time, document digest and DTBS. A signature value completes it into a signature.
_Avoid_: pending signature, signing session, context

**Signature value**:
The raw output of the asymmetric signing operation over the DTBS. Only a part of a signature.
_Avoid_: signature (when the raw value is meant)

## Certificates and cards

**CNS** (Carta Nazionale dei Servizi):
The Italian smartcard for public-administration services. It may carry both an authentication credential and a separate qualified signing credential. These are distinct signing credentials with different legal value.
_Avoid_: "the CNS key" (ambiguous between the two)

## Validation

**Diagnostic data**:
The complete, serializable set of facts gathered about a signed document (certificates, revocation data, timestamps, digest and cryptographic check results, signature scope), before any judgement is made.
_Avoid_: raw report, evidence

**Validation policy**:
The configurable set of constraints (each with a level: fail, warn, inform, ignore) and algorithm expiry dates that turns diagnostic data into indications.
_Avoid_: rules, config, constraints file

**Validation time**:
The point in time for which validity is asked. Defaults to now and can be set in the past.
_Avoid_: check date, current time

**Best-signature-time**:
The earliest time the signature is proven to have existed, from signature timestamps or other proof of existence. It is the time against which revocation and certificate validity are judged.
_Avoid_: signing time (that is the signer's unproven claim)

**Proof of existence (POE)**:
Evidence that an object (signature, certificate, revocation data) existed at a given time, typically from a timestamp covering it.
_Avoid_: proof of time, timestamp evidence

**Indication**:
The main outcome of a validation: TOTAL-PASSED, TOTAL-FAILED or INDETERMINATE, as defined by EN 319 102-1. Always paired with a sub-indication when not passed.
_Avoid_: status, result, valid/invalid

**Signature scope**:
What a signature actually covers: the documents, byte ranges or XML node set it protects. Every validation outcome states it.
_Avoid_: signed content, coverage

## Trust and qualification

**Trusted list (TL)**:
A national, signed list of qualified trust service providers and the status history of their services, published under eIDAS Article 22. Italy's is published by AgID.
_Avoid_: TSL (legacy name), AgID list, certificatori list

**LOTL** (List Of Trusted Lists):
The EC-signed list that points to every national trusted list and the certificates that sign them.
_Avoid_: EU list, master list

**Pivot LOTL**:
A historical LOTL version that announces a change of LOTL signing keys and is signed by the previous keys, forming a verifiable chain from the keys published in the Official Journal.
_Avoid_: LOTL backup

**Trust anchor**:
A certificate or public key accepted as trusted without further proof, either derived from a trusted list or supplied directly by the caller (custom trust anchor).
_Avoid_: root (a trust anchor need not be self-signed), CA store

**Qualification**:
The legal grade of a signature or seal under eIDAS (QESig, QESeal, AdESig-QC, AdESeal-QC, AdESig, AdESeal, NA). It is derived only from trusted-list data at certificate issuance time and best-signature-time.
_Avoid_: legal value, QES flag

## PDF

**Signed revision**:
The prefix of a PDF file, ending at an `%%EOF`, that a PAdES signature's byte range covers. Later incremental updates are outside it.
_Avoid_: signed version, original document
