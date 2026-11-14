# ades

Pure-Dart library for creating and validating AdES (Advanced Electronic Signatures), with a focus on Italian signatures (`.p7m`, CNS smart cards). It uses EU DSS as its validation reference.

> **Status: early MVP (`0.0.1`), not production-ready.** The API will change. Nothing is published on pub.dev yet.

## What works today

- CAdES-B-B signing and validation, enveloping (`.p7m`) and detached (`.p7s`)
- SHA-256, RSA PKCS#1 v1.5, and ECDSA P-256
- Validation against a custom trust anchor, with DSS-compatible diagnostic data and reports. Revocation is not checked yet, so its status is INDETERMINATE.
- Streaming of large BER/DER files

The roadmap goes up to 1.0: CAdES + PAdES from B-B to B-LTA with trusted-list qualification ([ADR-0003](docs/adr/0003-scope-1-0.md)).

## Packages

| Package | Purpose |
|---|---|
| [`packages/ades`](packages/ades) | Pure-Dart core. No `dart:io`, no native code, and it never touches private keys. |
| [`packages/ades_soft`](packages/ades_soft) | In-memory credentials (PKCS#12/PEM). Not hardened against side channels: use it for tests only. |
| [`packages/ades_pkcs11`](packages/ades_pkcs11) | Smart cards and HSMs through PKCS#11 (`dart:ffi`). |
| [`packages/ades_cli`](packages/ades_cli) | `ades sign` / `ades validate` command line. |
| [`examples/cns_signer_flutter`](examples/cns_signer_flutter) | Flutter desktop example that signs with a CNS card. |

## Development

```sh
dart pub get
(cd packages/ades && dart test)
dart run ades_cli:ades --help
```

Design decisions are recorded in [`docs/adr/`](docs/adr) and the vocabulary in [`GLOSSARY.md`](GLOSSARY.md). Test fixtures are synthetic, with fake identities ([`fixtures/tier1/README.md`](fixtures/tier1/README.md)). The private keys in `fixtures/` are committed test keys and protect nothing.

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md). Report vulnerabilities privately, as described in [SECURITY.md](SECURITY.md).

## License

[Apache-2.0](LICENSE)
