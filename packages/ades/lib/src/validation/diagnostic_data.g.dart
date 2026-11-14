// GENERATED CODE - DO NOT MODIFY BY HAND

part of 'diagnostic_data.dart';

// **************************************************************************
// JsonSerializableGenerator
// **************************************************************************

SignatureScope _$SignatureScopeFromJson(Map<String, dynamic> json) =>
    SignatureScope(
      kind: $enumDecode(_$SignatureScopeKindEnumMap, json['kind']),
      name: json['name'] as String,
      description: json['description'] as String,
      length: (json['length'] as num?)?.toInt(),
      digestAlgorithm: $enumDecodeNullable(
        _$DigestAlgorithmEnumMap,
        json['digestAlgorithm'],
      ),
      digest: const NullableBytesConverter().fromJson(
        json['digest'] as String?,
      ),
    );

Map<String, dynamic> _$SignatureScopeToJson(SignatureScope instance) =>
    <String, dynamic>{
      'kind': _$SignatureScopeKindEnumMap[instance.kind]!,
      'name': instance.name,
      'description': instance.description,
      'length': instance.length,
      'digestAlgorithm': _$DigestAlgorithmEnumMap[instance.digestAlgorithm],
      'digest': const NullableBytesConverter().toJson(instance.digest),
    };

const _$SignatureScopeKindEnumMap = {
  SignatureScopeKind.envelopedContent: 'envelopedContent',
  SignatureScopeKind.detachedDocument: 'detachedDocument',
};

const _$DigestAlgorithmEnumMap = {
  DigestAlgorithm.sha1: 'sha1',
  DigestAlgorithm.sha256: 'sha256',
  DigestAlgorithm.sha384: 'sha384',
  DigestAlgorithm.sha512: 'sha512',
};

CertificateDiagnostic _$CertificateDiagnosticFromJson(
  Map<String, dynamic> json,
) => CertificateDiagnostic(
  id: json['id'] as String,
  der: const BytesConverter().fromJson(json['der'] as String),
  subject: json['subject'] as String,
  issuer: json['issuer'] as String,
  serialNumber: json['serialNumber'] as String,
  notBefore: DateTime.parse(json['notBefore'] as String),
  notAfter: DateTime.parse(json['notAfter'] as String),
  trustAnchor: json['trustAnchor'] as bool,
  keyUsage: const KeyUsageConverter().fromJson(json['keyUsage'] as List?),
  basicConstraints: const BasicConstraintsConverter().fromJson(
    json['basicConstraints'] as Map<String, dynamic>?,
  ),
  signatureAlgorithmOid: json['signatureAlgorithmOid'] as String,
  publicKeyAlgorithm: $enumDecode(
    _$PublicKeyAlgorithmEnumMap,
    json['publicKeyAlgorithm'],
  ),
  publicKeySize: (json['publicKeySize'] as num?)?.toInt(),
);

Map<String, dynamic> _$CertificateDiagnosticToJson(
  CertificateDiagnostic instance,
) => <String, dynamic>{
  'id': instance.id,
  'der': const BytesConverter().toJson(instance.der),
  'subject': instance.subject,
  'issuer': instance.issuer,
  'serialNumber': instance.serialNumber,
  'notBefore': instance.notBefore.toIso8601String(),
  'notAfter': instance.notAfter.toIso8601String(),
  'trustAnchor': instance.trustAnchor,
  'keyUsage': const KeyUsageConverter().toJson(instance.keyUsage),
  'basicConstraints': const BasicConstraintsConverter().toJson(
    instance.basicConstraints,
  ),
  'signatureAlgorithmOid': instance.signatureAlgorithmOid,
  'publicKeyAlgorithm':
      _$PublicKeyAlgorithmEnumMap[instance.publicKeyAlgorithm]!,
  'publicKeySize': instance.publicKeySize,
};

const _$PublicKeyAlgorithmEnumMap = {
  PublicKeyAlgorithm.rsa: 'rsa',
  PublicKeyAlgorithm.ecdsa: 'ecdsa',
  PublicKeyAlgorithm.unsupported: 'unsupported',
};

SigningCertificateReference _$SigningCertificateReferenceFromJson(
  Map<String, dynamic> json,
) => SigningCertificateReference(
  version: (json['version'] as num).toInt(),
  hashAlgorithm: $enumDecodeNullable(
    _$DigestAlgorithmEnumMap,
    json['hashAlgorithm'],
  ),
  certHash: const BytesConverter().fromJson(json['certHash'] as String),
  issuerSerialMatches: json['issuerSerialMatches'] as bool?,
);

Map<String, dynamic> _$SigningCertificateReferenceToJson(
  SigningCertificateReference instance,
) => <String, dynamic>{
  'version': instance.version,
  'hashAlgorithm': _$DigestAlgorithmEnumMap[instance.hashAlgorithm],
  'certHash': const BytesConverter().toJson(instance.certHash),
  'issuerSerialMatches': instance.issuerSerialMatches,
};

SignatureDiagnostic _$SignatureDiagnosticFromJson(Map<String, dynamic> json) =>
    SignatureDiagnostic(
      index: (json['index'] as num).toInt(),
      formatIssues: (json['formatIssues'] as List<dynamic>)
          .map((e) => $enumDecode(_$MessageCodeEnumMap, e))
          .toList(),
      digestAlgorithmOid: json['digestAlgorithmOid'] as String,
      signatureAlgorithmOid: json['signatureAlgorithmOid'] as String,
      signedAttributesPresent: json['signedAttributesPresent'] as bool,
      signedAttributesDer: json['signedAttributesDer'] as bool,
      signingTime: json['signingTime'] == null
          ? null
          : DateTime.parse(json['signingTime'] as String),
      signingCertificateReference: json['signingCertificateReference'] == null
          ? null
          : SigningCertificateReference.fromJson(
              json['signingCertificateReference'] as Map<String, dynamic>,
            ),
      signingCertificateId: json['signingCertificateId'] as String?,
      signingCertificateReferenceMatches:
          json['signingCertificateReferenceMatches'] as bool?,
      contentAvailable: json['contentAvailable'] as bool,
      messageDigestMatches: json['messageDigestMatches'] as bool?,
      signatureCheck: $enumDecodeNullable(
        _$SignatureCheckStatusEnumMap,
        json['signatureCheck'],
      ),
      scope: json['scope'] == null
          ? null
          : SignatureScope.fromJson(json['scope'] as Map<String, dynamic>),
      certificateChain: (json['certificateChain'] as List<dynamic>?)
          ?.map((e) => e as String)
          .toList(),
    );

Map<String, dynamic> _$SignatureDiagnosticToJson(
  SignatureDiagnostic instance,
) => <String, dynamic>{
  'index': instance.index,
  'formatIssues': instance.formatIssues
      .map((e) => _$MessageCodeEnumMap[e]!)
      .toList(),
  'digestAlgorithmOid': instance.digestAlgorithmOid,
  'signatureAlgorithmOid': instance.signatureAlgorithmOid,
  'signedAttributesPresent': instance.signedAttributesPresent,
  'signedAttributesDer': instance.signedAttributesDer,
  'signingTime': instance.signingTime?.toIso8601String(),
  'signingCertificateReference': instance.signingCertificateReference,
  'signingCertificateId': instance.signingCertificateId,
  'signingCertificateReferenceMatches':
      instance.signingCertificateReferenceMatches,
  'contentAvailable': instance.contentAvailable,
  'messageDigestMatches': instance.messageDigestMatches,
  'signatureCheck': _$SignatureCheckStatusEnumMap[instance.signatureCheck],
  'scope': instance.scope,
  'certificateChain': instance.certificateChain,
};

const _$MessageCodeEnumMap = {
  MessageCode.malformedInput: 'malformedInput',
  MessageCode.missingContentType: 'missingContentType',
  MessageCode.missingMessageDigest: 'missingMessageDigest',
  MessageCode.duplicateAttribute: 'duplicateAttribute',
  MessageCode.contentTypeMismatch: 'contentTypeMismatch',
  MessageCode.missingSigningCertificate: 'missingSigningCertificate',
  MessageCode.signingCertificateNotFound: 'signingCertificateNotFound',
  MessageCode.signingCertificateUnparseable: 'signingCertificateUnparseable',
  MessageCode.signingCertificateReferenceMismatch:
      'signingCertificateReferenceMismatch',
  MessageCode.signingCertificateReferenceMatches:
      'signingCertificateReferenceMatches',
  MessageCode.contentNotAvailable: 'contentNotAvailable',
  MessageCode.messageDigestMatches: 'messageDigestMatches',
  MessageCode.messageDigestMismatch: 'messageDigestMismatch',
  MessageCode.signedAttributesNotDer: 'signedAttributesNotDer',
  MessageCode.signatureValid: 'signatureValid',
  MessageCode.signatureInvalid: 'signatureInvalid',
  MessageCode.unsupportedAlgorithm: 'unsupportedAlgorithm',
  MessageCode.signerIsTrustAnchor: 'signerIsTrustAnchor',
  MessageCode.noCertificateChain: 'noCertificateChain',
  MessageCode.revocationNotChecked: 'revocationNotChecked',
  MessageCode.issuerSerialMismatch: 'issuerSerialMismatch',
  MessageCode.certDigestMissing: 'certDigestMissing',
  MessageCode.signingTimeMissing: 'signingTimeMissing',
  MessageCode.signingTimeOutOfCertRange: 'signingTimeOutOfCertRange',
  MessageCode.certificateChainBuilt: 'certificateChainBuilt',
  MessageCode.certificateExpired: 'certificateExpired',
  MessageCode.certificateNotYetValid: 'certificateNotYetValid',
  MessageCode.signerKeyUsageNotSigning: 'signerKeyUsageNotSigning',
  MessageCode.issuerNotCa: 'issuerNotCa',
  MessageCode.issuerKeyUsageNotCertSign: 'issuerKeyUsageNotCertSign',
  MessageCode.pathLengthExceeded: 'pathLengthExceeded',
  MessageCode.cryptographyNotAcceptable: 'cryptographyNotAcceptable',
  MessageCode.cryptographyExpired: 'cryptographyExpired',
  MessageCode.noTrustedChainForCryptography: 'noTrustedChainForCryptography',
};

const _$SignatureCheckStatusEnumMap = {
  SignatureCheckStatus.verified: 'verified',
  SignatureCheckStatus.invalid: 'invalid',
  SignatureCheckStatus.unsupported: 'unsupported',
};

DiagnosticData _$DiagnosticDataFromJson(Map<String, dynamic> json) =>
    DiagnosticData(
      formatFailure: json['formatFailure'] as String?,
      certificates: (json['certificates'] as List<dynamic>)
          .map((e) => CertificateDiagnostic.fromJson(e as Map<String, dynamic>))
          .toList(),
      signatures: (json['signatures'] as List<dynamic>)
          .map((e) => SignatureDiagnostic.fromJson(e as Map<String, dynamic>))
          .toList(),
      warnings:
          (json['warnings'] as List<dynamic>?)
              ?.map(
                (e) => ValidationWarning.fromJson(e as Map<String, dynamic>),
              )
              .toList() ??
          const [],
    );

Map<String, dynamic> _$DiagnosticDataToJson(DiagnosticData instance) =>
    <String, dynamic>{
      'formatFailure': instance.formatFailure,
      'certificates': instance.certificates,
      'signatures': instance.signatures,
      'warnings': instance.warnings,
    };
