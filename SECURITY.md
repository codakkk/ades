# Security policy

`ades` creates and validates digital signatures, so a bug can make a forged or tampered signature look valid.

## Reporting a vulnerability

**Do not open a public issue.** Report it privately through GitHub: on the **Security** tab, choose **Report a vulnerability**.

Please include:

- the affected package and commit
- a minimal input that reproduces the problem, such as a `.p7m`/`.p7s` file or certificate chain made with test keys. **Never send real signatures or personal data.**
- the expected and actual result

This is a single-maintainer project, so replies are best-effort. You will get an acknowledgement, and a fix is coordinated with you before anything is disclosed.

## Supported versions

Pre-1.0: only the latest commit on `main` is supported.

## Out of scope

- Private keys under `fixtures/`: they are public test keys on purpose.
- Side-channel attacks on `ades_soft`: the package is documented as not hardened against them.
