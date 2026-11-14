import 'dart:convert';

import 'package:json_annotation/json_annotation.dart';

part 'policy.g.dart';

/// What decide does when a constraint is not satisfied (DSS `Level`).
enum ConstraintLevel {
  /// The building block fails (or is indeterminate, as the constraint says).
  fail,

  /// A warning message is reported; the outcome is unchanged.
  warn,

  /// An informational message is reported; the outcome is unchanged.
  inform,

  /// The constraint is not evaluated.
  ignore,
}

/// A policy JSON document that cannot be read.
final class PolicyFormatException implements FormatException {
  const PolicyFormatException(this.message, {this.key});

  @override
  final String message;

  /// The offending JSON key, when the problem is tied to one.
  final String? key;

  @override
  dynamic get source => null;

  @override
  int? get offset => null;

  @override
  String toString() => key == null
      ? 'PolicyFormatException: $message'
      : 'PolicyFormatException: "$key": $message';
}

/// The validation policy: one [ConstraintLevel] per constraint (ADR-0007).
///
/// The default-constructed policy equals DSS's default policy
/// (`constraint.xml`, release [dssVersion]); each constraint documents its
/// DSS element. JSON keys are the field names; missing keys keep the DSS
/// default.
@JsonSerializable(checked: true, disallowUnrecognizedKeys: true)
final class ValidationPolicy {
  const ValidationPolicy({
    this.referenceDataExistence = ConstraintLevel.fail,
    this.referenceDataIntact = ConstraintLevel.fail,
    this.signatureIntact = ConstraintLevel.fail,
    this.prospectiveCertificateChain = ConstraintLevel.fail,
    this.signingCertificateNotExpired = ConstraintLevel.fail,
    this.revocationDataAvailable = ConstraintLevel.fail,
    this.signingCertificatePresent = ConstraintLevel.warn,
    this.certDigestPresent = ConstraintLevel.fail,
    this.certDigestMatch = ConstraintLevel.fail,
    this.issuerSerialMatch = ConstraintLevel.warn,
    this.signingTime = ConstraintLevel.fail,
    this.signingTimeInCertRange = ConstraintLevel.fail,
    this.caCertificateNotExpired = ConstraintLevel.fail,
    this.caCertificateCa = ConstraintLevel.fail,
    this.caCertificateMaxPathLength = ConstraintLevel.fail,
    this.caCertificateKeyUsage = ConstraintLevel.fail,
    this.cryptographic = ConstraintLevel.fail,
    this.algorithmExpiration = ConstraintLevel.fail,
  });

  /// Reads a policy from decoded JSON. Throws [PolicyFormatException].
  factory ValidationPolicy.fromJson(Map<String, dynamic> json) {
    try {
      return _$ValidationPolicyFromJson(json);
    } on CheckedFromJsonException catch (e) {
      throw PolicyFormatException(e.message ?? 'invalid value', key: e.key);
    }
  }

  /// Reads a policy from JSON text. Throws [PolicyFormatException].
  factory ValidationPolicy.fromJsonString(String text) {
    final Object? decoded;
    try {
      decoded = jsonDecode(text);
    } on FormatException catch (e) {
      throw PolicyFormatException('not valid JSON: ${e.message}');
    }
    if (decoded is! Map<String, dynamic>) {
      throw const PolicyFormatException('a policy must be a JSON object');
    }
    return ValidationPolicy.fromJson(decoded);
  }

  Map<String, dynamic> toJson() => _$ValidationPolicyToJson(this);

  String toJsonString() => jsonEncode(toJson());

  /// The DSS release whose `constraint.xml` supplies the defaults.
  static const String dssVersion = '6.5.1';

  /// SignatureConstraints/BasicSignatureConstraints/ReferenceDataExistence:
  /// the signed content is available (CV).
  @JsonKey(defaultValue: ConstraintLevel.fail)
  final ConstraintLevel referenceDataExistence;

  /// .../BasicSignatureConstraints/ReferenceDataIntact: the content digest
  /// equals the messageDigest attribute (CV).
  @JsonKey(defaultValue: ConstraintLevel.fail)
  final ConstraintLevel referenceDataIntact;

  /// .../BasicSignatureConstraints/SignatureIntact: the signature value
  /// verifies (CV).
  @JsonKey(defaultValue: ConstraintLevel.fail)
  final ConstraintLevel signatureIntact;

  /// .../BasicSignatureConstraints/ProspectiveCertificateChain: a chain to a
  /// trust anchor exists (XCV).
  @JsonKey(defaultValue: ConstraintLevel.fail)
  final ConstraintLevel prospectiveCertificateChain;

  /// .../BasicSignatureConstraints/SigningCertificate/NotExpired: the signing
  /// certificate is valid at the validation time (XCV).
  @JsonKey(defaultValue: ConstraintLevel.fail)
  final ConstraintLevel signingCertificateNotExpired;

  /// .../SigningCertificate/RevocationDataAvailable: revocation data for the
  /// signing certificate was found (XCV). DSS applies the same level to each
  /// CACertificate/RevocationDataAvailable; so does decide. Never satisfied in
  /// this slice (no revocation data is collected yet).
  @JsonKey(defaultValue: ConstraintLevel.fail)
  final ConstraintLevel revocationDataAvailable;

  /// SignatureConstraints/SignedAttributes/SigningCertificatePresent (ISC).
  @JsonKey(defaultValue: ConstraintLevel.warn)
  final ConstraintLevel signingCertificatePresent;

  /// .../SignedAttributes/CertDigestPresent (ISC).
  @JsonKey(defaultValue: ConstraintLevel.fail)
  final ConstraintLevel certDigestPresent;

  /// .../SignedAttributes/CertDigestMatch (ISC).
  @JsonKey(defaultValue: ConstraintLevel.fail)
  final ConstraintLevel certDigestMatch;

  /// .../SignedAttributes/IssuerSerialMatch (ISC).
  @JsonKey(defaultValue: ConstraintLevel.warn)
  final ConstraintLevel issuerSerialMatch;

  /// .../SignedAttributes/SigningTime: a signing-time attribute is present
  /// (SAV).
  @JsonKey(defaultValue: ConstraintLevel.fail)
  final ConstraintLevel signingTime;

  /// .../SignedAttributes/SigningTimeInCertRange: the claimed signing time is
  /// inside the signing certificate's validity (SAV).
  @JsonKey(defaultValue: ConstraintLevel.fail)
  final ConstraintLevel signingTimeInCertRange;

  /// .../BasicSignatureConstraints/CACertificate/NotExpired: every CA
  /// certificate of the chain (trust anchors excepted) is valid at the
  /// validation time (XCV).
  @JsonKey(defaultValue: ConstraintLevel.fail)
  final ConstraintLevel caCertificateNotExpired;

  /// .../CACertificate/CA: each issuer is a CA (basicConstraints) (XCV).
  @JsonKey(defaultValue: ConstraintLevel.fail)
  final ConstraintLevel caCertificateCa;

  /// .../CACertificate/MaxPathLength: the path length constraint holds (XCV).
  @JsonKey(defaultValue: ConstraintLevel.fail)
  final ConstraintLevel caCertificateMaxPathLength;

  /// .../CACertificate/KeyUsage: each CA's key usage allows keyCertSign (XCV).
  @JsonKey(defaultValue: ConstraintLevel.fail)
  final ConstraintLevel caCertificateKeyUsage;

  /// Cryptographic (inherited by every `<Cryptographic />` below
  /// SignatureConstraints): the algorithms and key sizes of the signature and
  /// of each certificate in the path must be acceptable (XCV, SAV). The
  /// acceptable algorithms and minimum key sizes are DSS's own (RSA from 786
  /// bits, ECDSA from 160 bits, SHA-1 and up).
  @JsonKey(defaultValue: ConstraintLevel.fail)
  final ConstraintLevel cryptographic;

  /// Cryptographic/AlgoExpirationDate: no algorithm or key size has passed
  /// its expiry date (DSS's table, ETSI TS 119 312) at the validation time.
  /// As in DSS, an expiry that falls after the policy update date
  /// (2026-02-01) is only a warning, whatever this level says.
  @JsonKey(defaultValue: ConstraintLevel.fail)
  final ConstraintLevel algorithmExpiration;
}
