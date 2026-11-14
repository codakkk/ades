# Contributing

Thanks for your interest. This project has a single maintainer, and every change goes through a pull request that the maintainer reviews and merges.

## Before you start

- **Open an issue first** for anything bigger than a small fix, so we can agree on the approach before you write code. The scope is deliberately narrow ([ADR-0003](docs/adr/0003-scope-1-0.md)), so a PR outside it may be declined however good the code is.
- Read the relevant ADRs in [`docs/adr/`](docs/adr). The most important hard rules:
  - the core (`packages/ades`) uses no `dart:io` and no native code (ADR-0002)
  - the core never touches private keys (ADR-0005)
  - new runtime dependencies must follow the dependency policy (ADR-0001)
- **Never commit real signatures, real certificates, or personal data** (ADR-0010). Use or extend the synthetic fixtures in `fixtures/tier1/`.

## Pull requests

CI must pass. Locally:

```sh
dart pub get
dart format --output=none --set-exit-if-changed .
dart analyze --fatal-infos
dart test test
(cd packages/ades && dart test)
```

Keep each PR focused on one change and add tests for new behaviour.

## License

By submitting a contribution, you agree it is licensed under [Apache-2.0](LICENSE), as section 5 of the license describes.

## Security issues

Do not use issues or PRs for vulnerabilities. See [SECURITY.md](SECURITY.md).
