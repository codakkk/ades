import 'dart:typed_data';

import 'package:json_annotation/json_annotation.dart';

import '../crypto/algorithms.dart';
import '../x509/certificate.dart' show BasicConstraints, KeyUsageFlag;
import 'indication.dart';
import 'json_converters.dart';
import 'warning.dart';

part 'diagnostic_data.g.dart';

/// What a signature covers (GLOSSARY: signature scope).
enum SignatureScopeKind {
  /// The content encapsulated inside the CMS SignedData (enveloping `.p7m`).
  envelopedContent,

  /// A document supplied by the caller for a detached signature (`.p7s`).
  detachedDocument,
}

@JsonSerializable()
final class SignatureScope {
  const SignatureScope({
    required this.kind,
    required this.name,
    required this.description,
    this.length,
    this.digestAlgorithm,
    this.digest,
  });

  factory SignatureScope.fromJson(Map<String, dynamic> json) =>
      _$SignatureScopeFromJson(json);

  Map<String, dynamic> toJson() => _$SignatureScopeToJson(this);

  final SignatureScopeKind kind;
  final String name;
  final String description;

  /// Size in bytes of the covered content, when known.
  final int? length;

  /// Digest of the covered content, as computed by collect.
  final DigestAlgorithm? digestAlgorithm;
  @NullableBytesConverter()
  final Uint8List? digest;
}

/// Key algorithm of a certificate's public key, for cryptographic policy.
enum PublicKeyAlgorithm { rsa, ecdsa, unsupported }

/// Facts about one certificate found in the signature.
@JsonSerializable()
final class CertificateDiagnostic {
  const CertificateDiagnostic({
    required this.id,
    required this.der,
    required this.subject,
    required this.issuer,
    required this.serialNumber,
    required this.notBefore,
    required this.notAfter,
    required this.trustAnchor,
    required this.keyUsage,
    required this.basicConstraints,
    required this.signatureAlgorithmOid,
    required this.publicKeyAlgorithm,
    required this.publicKeySize,
  });

  factory CertificateDiagnostic.fromJson(Map<String, dynamic> json) =>
      _$CertificateDiagnosticFromJson(json);

  Map<String, dynamic> toJson() => _$CertificateDiagnosticToJson(this);

  /// Stable id within this diagnostic data, e.g. `C-0`.
  final String id;
  @BytesConverter()
  final Uint8List der;
  final String subject;
  final String issuer;

  /// Serial number in hexadecimal.
  final String serialNumber;
  final DateTime notBefore;
  final DateTime notAfter;

  /// True when it is byte-identical to a caller-supplied trust anchor.
  final bool trustAnchor;

  /// keyUsage bits; null when the extension is absent.
  @KeyUsageConverter()
  final Set<KeyUsageFlag>? keyUsage;

  /// Null when the extension is absent.
  @BasicConstraintsConverter()
  final BasicConstraints? basicConstraints;

  /// OID of the algorithm its issuer signed it with.
  final String signatureAlgorithmOid;

  /// Algorithm of its public key.
  final PublicKeyAlgorithm publicKeyAlgorithm;

  /// Size of its public key in bits (RSA modulus, EC curve field); null for
  /// an unsupported key type.
  final int? publicKeySize;
}

/// The signing certificate reference signed attribute
/// (ESS signing-certificate or signing-certificate-v2).
@JsonSerializable()
final class SigningCertificateReference {
  const SigningCertificateReference({
    required this.version,
    required this.hashAlgorithm,
    required this.certHash,
    required this.issuerSerialMatches,
  });

  factory SigningCertificateReference.fromJson(Map<String, dynamic> json) =>
      _$SigningCertificateReferenceFromJson(json);

  Map<String, dynamic> toJson() => _$SigningCertificateReferenceToJson(this);

  /// 1 for ESS signing-certificate (SHA-1), 2 for signing-certificate-v2.
  final int version;
  final DigestAlgorithm? hashAlgorithm;
  @BytesConverter()
  final Uint8List certHash;

  /// Null when the reference carries no issuerSerial.
  final bool? issuerSerialMatches;
}

/// Result of the cryptographic signature check, as computed in collect.
enum SignatureCheckStatus {
  /// The signature value verifies over the DTBS.
  verified,

  /// The signature value does not verify.
  invalid,

  /// The algorithm or key type is not supported by the crypto provider.
  unsupported,
}

/// Facts about one signature (one CMS SignerInfo).
@JsonSerializable()
final class SignatureDiagnostic {
  const SignatureDiagnostic({
    required this.index,
    required this.formatIssues,
    required this.digestAlgorithmOid,
    required this.signatureAlgorithmOid,
    required this.signedAttributesPresent,
    required this.signedAttributesDer,
    required this.signingTime,
    required this.signingCertificateReference,
    required this.signingCertificateId,
    required this.signingCertificateReferenceMatches,
    required this.contentAvailable,
    required this.messageDigestMatches,
    required this.signatureCheck,
    required this.scope,
    required this.certificateChain,
  });

  factory SignatureDiagnostic.fromJson(Map<String, dynamic> json) =>
      _$SignatureDiagnosticFromJson(json);

  Map<String, dynamic> toJson() => _$SignatureDiagnosticToJson(this);

  /// Position among the signatures of the document.
  final int index;

  /// Structural problems with the signed attributes, checked by FC.
  final List<MessageCode> formatIssues;
  final String digestAlgorithmOid;
  final String signatureAlgorithmOid;
  final bool signedAttributesPresent;

  /// Whether the signed attributes SET OF is in DER order (ADR-0004).
  final bool signedAttributesDer;
  final DateTime? signingTime;

  /// Null when no signing-certificate attribute is present.
  final SigningCertificateReference? signingCertificateReference;

  /// Id of the certificate the signer identifier points to, if found.
  final String? signingCertificateId;

  /// Whether the signing certificate matches its signed reference; null when
  /// there is nothing to compare.
  final bool? signingCertificateReferenceMatches;

  /// False for a detached signature without its document.
  final bool contentAvailable;

  /// messageDigest attribute equals the digest of the content; null when it
  /// could not be compared.
  final bool? messageDigestMatches;

  /// Null when the check could not run (no content, no signing certificate).
  final SignatureCheckStatus? signatureCheck;
  final SignatureScope? scope;

  /// Ids (into [DiagnosticData.certificates]) of the certification path
  /// from the signing certificate (first) to a trust anchor (last), built
  /// from the embedded certificates and the caller's pool. Null when no
  /// path to a trust anchor exists.
  final List<String>? certificateChain;
}

/// Everything collect learned about a signed document, before any judgement.
///
/// Serializes to JSON (bytes as base64, times as ISO 8601 UTC) so any
/// validation can be reproduced from one file (ADR-0007).
///
/// Extension points: revocation and timestamp
/// facts (later tickets), per-certificate chain facts (ticket 05).
@JsonSerializable()
final class DiagnosticData {
  const DiagnosticData({
    required this.formatFailure,
    required this.certificates,
    required this.signatures,
    this.warnings = const [],
  });

  factory DiagnosticData.fromJson(Map<String, dynamic> json) =>
      _$DiagnosticDataFromJson(json);

  Map<String, dynamic> toJson() => _$DiagnosticDataToJson(this);

  /// Set when the input could not be read as a CAdES signature at all.
  final String? formatFailure;
  final List<CertificateDiagnostic> certificates;
  final List<SignatureDiagnostic> signatures;

  /// Non-DER forms found outside the signed attributes; they never change an
  /// indication (ADR-0004).
  final List<ValidationWarning> warnings;
}
