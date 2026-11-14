# CNS signer (Flutter desktop example)

Sample app: pick a file, find the smart-card middleware, list the card's
credentials (authentication and qualified-signature certificates), enter the
PIN in a Flutter dialog, write an enveloping CAdES-B-B `<file>.p7m`.

It is **not published** and **not a member of the root pub workspace**: the
workspace (`dart pub get` at the repo root) stays free of Flutter, so no
published package depends on it. The app reaches `ades` and `ades_pkcs11`
by path (see `pubspec.yaml`).

```sh
cd examples/cns_signer_flutter
flutter pub get
flutter test
flutter run -d macos      # or linux, windows
```

## How it stays responsive

- `ades_pkcs11` runs every PKCS#11 call (login, sign) on its own worker
  isolate; the PIN dialog runs on the UI isolate.
- `lib/signing_service.dart` reads and hashes the file on a short-lived
  isolate (phase 1) and assembles/writes the `.p7m` on another (phase 2).
  Only the small DTBS digest is signed on the calling isolate. The file is
  held in memory on those helper isolates; true streaming comes with the
  streaming BER work (ticket 11, not merged when this was written).

## Middleware discovery

`discoverPkcs11Modules()` (in `ades_pkcs11`) checks the known Bit4id, Incard,
IDEMIA/Oberthur, Athena, Thales and OpenSC locations for the current OS and
reports which libraries were found, which exist but failed to load (with the
reason) and which are simply not installed. Pass `candidates:` to add your own
paths; `includeKnown: false` to use only yours. The in-app "Read card" output
shows this report. The built-in list is best-effort (vendor paths change);
override it if your vendor installs elsewhere.

## macOS: entitlements, hardened runtime, notarization

The entitlement files are in `macos/Runner/`.

| Entitlement | Why |
|---|---|
| `com.apple.security.app-sandbox` = **false** | A sandboxed app can only `dlopen` libraries inside its bundle and cannot read arbitrary user files or reach the vendor's daemon/PC-SC resources. Vendor middleware lives in `/Library/...` or `/usr/local/lib`, so the sandbox must be off (or you bundle the library, below). |
| `com.apple.security.cs.disable-library-validation` | With the hardened runtime (required for notarization) the process may only load libraries signed by Apple or by the same Team ID. A vendor's `libbit4ipki.dylib` is signed by the vendor (or not at all), so loading it fails without this entitlement. |
| `com.apple.security.smartcard` | Grants access to smart cards through CryptoTokenKit / PC/SC. Add it for middleware that talks to the reader via the system stack. |

Implications:

- **Notarization** (Developer ID, outside the Mac App Store) works with these
  entitlements: notarization requires the hardened runtime, and
  `disable-library-validation` is an allowed exception. The user still needs
  the vendor middleware installed. Sign with `codesign --options runtime
  --entitlements Release.entitlements`.
- **Mac App Store** requires the sandbox, which conflicts with loading
  system-wide vendor middleware. Plan on Developer ID distribution. A
  sandboxed variant would have to bundle a redistributable PKCS#11 library
  (e.g. OpenSC, if the vendor licence and card support allow) inside the app
  and re-sign it with your Team ID, which then makes
  `disable-library-validation` unnecessary; this example does not do that.
- Without `disable-library-validation`, `Pkcs11ModuleLoadException` /
  a "failed to load" entry in the discovery report is what you will see.

## Platform limits

CNS signing through PKCS#11 is **desktop only** (Windows, macOS, Linux).
Android, iOS and the web are not supported: there is no vendor middleware
to load and no `dart:ffi` on the web. Mobile signing is planned through
CIE/NFC (`ades_cie`, `ades_cie_flutter`) and remote signing (`ades_csc`).

## Not verified

No real CNS card or vendor middleware was available when this was written:
the app is tested with a fake credential source (widget tests), the isolate
signer with a software key, and discovery/signing against SoftHSM2
(`packages/ades_pkcs11/tool/test_in_docker.sh`). Vendor library names/paths
are from memory of vendor documentation, not checked against installs.
