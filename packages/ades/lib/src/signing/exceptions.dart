/// Errors thrown while creating a signature.
///
/// Validation never throws for bad input (it reports); creation does,
/// because a creation failure is the caller's to handle. The hierarchy is
/// sealed so that a `switch` over it is exhaustive. Each public creation
/// method documents the subtypes it throws.
sealed class AdesException implements Exception {
  const AdesException(this.message);

  final String message;

  @override
  String toString() => '$runtimeType: $message';
}

/// The signing certificate is not a parsable X.509 certificate.
final class InvalidCertificateException extends AdesException {
  const InvalidCertificateException(super.message);
}

/// The signing key is weaker than policy allows (RSA below 2048 bits).
final class WeakKeyException extends AdesException {
  const WeakKeyException(super.message);
}

/// The digest algorithm is weaker than policy allows (SHA-1).
final class WeakDigestException extends AdesException {
  const WeakDigestException(super.message);
}

/// The signing credential cannot produce the requested signature algorithm
/// (or its key does not fit it). Raised before the credential is asked to
/// sign, so no PIN prompt is triggered for a doomed operation.
final class UnsupportedCredentialAlgorithmException extends AdesException {
  const UnsupportedCredentialAlgorithmException(super.message);
}

/// A signature draft could not be read back (wrong format or version, bad
/// base64, or fields that do not match its data to be signed).
final class InvalidDraftException extends AdesException {
  const InvalidDraftException(super.message);
}

/// The signature value or the document handed to completion does not match
/// the signature draft.
final class DraftMismatchException extends AdesException {
  const DraftMismatchException(super.message);
}

/// A signing credential failed while signing. [cause] is what it threw.
/// (Raised by the one-call sign of ticket 10 and by signing vehicles.)
final class SigningFailedException extends AdesException {
  const SigningFailedException(super.message, {this.cause});

  final Object? cause;
}
