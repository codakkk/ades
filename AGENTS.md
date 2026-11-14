# ades repository instructions

These instructions apply to every coding agent working in this repository. They hold on any machine and contain nothing private.

## Read first

- [`GLOSSARY.md`](GLOSSARY.md): use its terms in code, issues and PRs, and avoid the synonyms it rules out.
- [`docs/adr/`](docs/adr): the binding decisions. If a change contradicts an ADR, say so explicitly and do not override it silently.
- [`CONTRIBUTING.md`](CONTRIBUTING.md): setup, checks and PR rules.

## Hard rules

- **The core (`packages/ades`) is pure Dart.** No `dart:io` (ADR-0002, checked in CI by `tool/check_no_dart_io.dart`), no native code, no network code (ADR-0011). Flutter is never a dependency of a published package.
- **The core never touches private keys** (ADR-0005). Key handling lives in `ades_soft` and `ades_pkcs11`.
- **New runtime dependencies** follow ADR-0001.
- **No personal data, ever** (ADR-0010). Never commit or paste real signatures, real certificates, names or codice fiscale into code, fixtures, issues or PRs. Reproduce problems with the synthetic tier-1 fixtures (`fixtures/tier1/`). The private keys there are public test keys on purpose.
- **Reference fixtures are made by OpenSSL, never by our own Dart code** (ADR-0010). Regenerate them with `tool/fixtures/generate.sh`. Only `fixtures/tier1/signatures/ours/` holds our own output, checked against DSS goldens.
- **EU DSS is a black-box oracle only** (ADR-0003). Never port its code.
- **Validation never throws** on malformed input: it returns an indication with a reason. The nightly fuzzers enforce this.

## Checks before every commit

```sh
dart pub get
dart format --output=none --set-exit-if-changed .
dart analyze --fatal-infos
dart test test
(cd packages/ades && dart test)
```

Run the tests of every package you touch. After you change a `@JsonSerializable` class, regenerate it with `dart run build_runner build` in that package.

## Issue tracker and workflow

- Issues, specs and the roadmap live in GitHub Issues: see [`docs/agents/issue-tracker.md`](docs/agents/issue-tracker.md) and [`docs/agents/triage-labels.md`](docs/agents/triage-labels.md).
- How skills use the glossary and ADRs: [`docs/agents/domain.md`](docs/agents/domain.md).
- Every change reaches `main` through a pull request that the maintainer reviews. Keep each PR to one change and describe what you verified and how.
