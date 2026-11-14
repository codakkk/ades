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

## AI usage

AI tools help with the development of `ades`: code, tests, reviews and documentation. The maintainer sets the design and architecture (see [`docs/adr/`](docs/adr)), reviews every generated change, and is responsible for everything that ships. Correctness is never taken on trust: signatures are checked against EU DSS as an independent oracle, and fixtures are made by OpenSSL, not by our own code.

You are welcome to use AI tools when you contribute. You must understand, review and test what you submit, be able to explain your decisions, and respond to review feedback yourself. The same standards apply however a contribution was produced. Agents should start from [`AGENTS.md`](AGENTS.md), which holds the project's hard rules. Claude Code also reads it through `CLAUDE.md`.

Submit only work you can stand behind. AI-generated code, test results and claims must be verified before they become part of a contribution.

## Contributing

Contributions are welcome. `ades` has a single maintainer, who reviews and merges every pull request. Please **open an issue first** for anything beyond a small fix, so we can agree on the approach before you write code.

Areas where help is especially useful:

- **Real smart cards**: testing `ades_pkcs11` with Italian CNS/CIE cards and their middleware on macOS, Windows and Linux. Report only aggregate results, never personal data.
- **DSS comparison**: finding cases where our verdict differs from EU DSS, reproduced with synthetic fixtures.
- **Security review**: the ASN.1/CMS parsers and the validation logic. Report findings privately, as described in [SECURITY.md](SECURITY.md).

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup, checks and pull request rules, and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) for how we work together.

## License

Licensed under the [Apache License 2.0](LICENSE). See [NOTICE](NOTICE) for attribution and third-party notices.
