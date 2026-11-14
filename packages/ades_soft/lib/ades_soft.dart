/// In-memory signing credentials (PKCS#12 / PEM) for `ades`.
///
/// Not hardened against side channels: see the README and ADR-0005.
library;

export 'src/key_material.dart' show SoftKeyLoadException, SoftKeyLoadFailure;
export 'src/soft_credential.dart' show SoftSigningCredential;
