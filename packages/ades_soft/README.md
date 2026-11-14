# ades_soft

Signing credentials backed by in-memory RSA keys, loaded from PKCS#12 or PEM,
for the `ades` core.

```dart
final credential = SoftSigningCredential.fromPkcs12(
  File('me.p12').readAsBytesSync(),
  password: 'secret',
);
final draft = await Cades.prepareEnveloping(document: doc, credential: credential);
final value = await credential.sign(await draft.signRequest());
final p7m = await Cades.complete(draft: draft, value: value, document: doc);
```

## Security warning

**This package is not hardened against side channels.** Signing uses
`pointycastle` RSA, which gives no guarantee of blinding or constant-time
arithmetic, and the private key sits in ordinary Dart heap memory. Use it for
tests and low-risk server-side seals only. Keys that must stay secret
(qualified signature keys, CNS cards) belong in hardware: use `ades_pkcs11`.
The `ades` core never touches private keys (ADR-0005); all key handling is
here.

## Supported inputs

- PKCS#12 (DER): password MAC verified; PBES2 (PBKDF2 with HMAC-SHA1/256/384/512,
  AES-128/192/256-CBC or 3DES) and legacy `pbeWithSHAAnd3-KeyTripleDES-CBC`.
  RC2-encrypted files (old OpenSSL `-legacy`) and BER-encoded files are not
  supported yet.
- PEM: `PRIVATE KEY`, `RSA PRIVATE KEY`, `ENCRYPTED PRIVATE KEY` (PKCS#8,
  password); certificates as `CERTIFICATE` blocks.
- RSA keys only (ECDSA arrives with ticket 10).

Loaders throw `SoftKeyLoadException` with a `SoftKeyLoadFailure` reason
(`malformed`, `wrongPassword`, `unsupported`, `incomplete`).
