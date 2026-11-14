/// Main outcome of validating a signature (ETSI EN 319 102-1 clause 5.1.3).
enum Indication {
  totalPassed('TOTAL-PASSED'),
  totalFailed('TOTAL-FAILED'),
  indeterminate('INDETERMINATE');

  const Indication(this.etsi);

  /// The name used by the standard and by DSS.
  final String etsi;
}

/// Outcome of one building block (EN 319 102-1 clause 5.2: PASSED, FAILED or
/// INDETERMINATE).
enum BlockIndication {
  passed('PASSED'),
  failed('FAILED'),
  indeterminate('INDETERMINATE');

  const BlockIndication(this.etsi);

  final String etsi;
}

/// Sub-indications of EN 319 102-1 (clause 5.1.3 and Annex B of the basic
/// process), closed: details live in [MessageCode]-tagged messages instead.
enum SubIndication {
  formatFailure('FORMAT_FAILURE'),
  hashFailure('HASH_FAILURE'),
  sigCryptoFailure('SIG_CRYPTO_FAILURE'),
  revoked('REVOKED'),
  sigConstraintsFailure('SIG_CONSTRAINTS_FAILURE'),
  chainConstraintsFailure('CHAIN_CONSTRAINTS_FAILURE'),
  certificateChainGeneralFailure('CERTIFICATE_CHAIN_GENERAL_FAILURE'),
  cryptoConstraintsFailure('CRYPTO_CONSTRAINTS_FAILURE'),
  expired('EXPIRED'),
  notYetValid('NOT_YET_VALID'),
  policyProcessingError('POLICY_PROCESSING_ERROR'),
  signaturePolicyNotAvailable('SIGNATURE_POLICY_NOT_AVAILABLE'),
  timestampOrderFailure('TIMESTAMP_ORDER_FAILURE'),
  noSigningCertificateFound('NO_SIGNING_CERTIFICATE_FOUND'),
  noCertificateChainFound('NO_CERTIFICATE_CHAIN_FOUND'),
  revokedNoPoe('REVOKED_NO_POE'),
  revokedCaNoPoe('REVOKED_CA_NO_POE'),
  outOfBoundsNoPoe('OUT_OF_BOUNDS_NO_POE'),
  outOfBoundsNotRevoked('OUT_OF_BOUNDS_NOT_REVOKED'),
  cryptoConstraintsFailureNoPoe('CRYPTO_CONSTRAINTS_FAILURE_NO_POE'),
  noPoe('NO_POE'),
  tryLater('TRY_LATER'),
  signedDataNotFound('SIGNED_DATA_NOT_FOUND'),
  generic('GENERIC');

  const SubIndication(this.etsi);

  final String etsi;
}

/// The validation building blocks of the basic process, each tagged with
/// the clause of ETSI EN 319 102-1 that defines it.
enum BuildingBlock {
  formatChecking('FC', 'Format Checking', '5.2.2'),
  identificationOfSigningCertificate(
    'ISC',
    'Identification of the Signing Certificate',
    '5.2.3',
  ),
  validationContextInitialization(
    'VCI',
    'Validation Context Initialization',
    '5.2.4',
  ),
  x509CertificateValidation('XCV', 'X.509 Certificate Validation', '5.2.6'),
  cryptographicVerification('CV', 'Cryptographic Verification', '5.2.7'),
  signatureAcceptanceValidation(
    'SAV',
    'Signature Acceptance Validation',
    '5.2.8',
  );

  const BuildingBlock(this.abbreviation, this.title, this.clause);

  final String abbreviation;
  final String title;

  /// Clause number in EN 319 102-1.
  final String clause;
}

/// Machine-readable reason attached to a [ValidationMessage].
enum MessageCode {
  malformedInput,
  missingContentType,
  missingMessageDigest,
  duplicateAttribute,
  contentTypeMismatch,
  missingSigningCertificate,
  signingCertificateNotFound,
  signingCertificateUnparseable,
  signingCertificateReferenceMismatch,
  signingCertificateReferenceMatches,
  contentNotAvailable,
  messageDigestMatches,
  messageDigestMismatch,
  signedAttributesNotDer,
  signatureValid,
  signatureInvalid,
  unsupportedAlgorithm,
  signerIsTrustAnchor,
  noCertificateChain,
  revocationNotChecked,
  issuerSerialMismatch,
  certDigestMissing,
  signingTimeMissing,
  signingTimeOutOfCertRange,
  certificateChainBuilt,
  certificateExpired,
  certificateNotYetValid,
  signerKeyUsageNotSigning,
  issuerNotCa,
  issuerKeyUsageNotCertSign,
  pathLengthExceeded,
  cryptographyNotAcceptable,
  cryptographyExpired,
  noTrustedChainForCryptography,
}

/// How a [ValidationMessage] relates to the outcome, set by the constraint
/// level in the validation policy.
enum MessageSeverity {
  /// Neutral fact, or a constraint at level inform that was not satisfied.
  info,

  /// A constraint at level warn that was not satisfied.
  warning,

  /// A constraint at level fail that was not satisfied.
  error,
}

/// A typed detail attached to a building block result.
final class ValidationMessage {
  const ValidationMessage(
    this.code,
    this.text, {
    this.severity = MessageSeverity.info,
  });

  final MessageCode code;

  /// Human-readable explanation (English); do not parse it.
  final String text;
  final MessageSeverity severity;

  @override
  String toString() => '${code.name}: $text';
}
