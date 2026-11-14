// GENERATED CODE - DO NOT MODIFY BY HAND

part of 'policy.dart';

// **************************************************************************
// JsonSerializableGenerator
// **************************************************************************

ValidationPolicy _$ValidationPolicyFromJson(Map<String, dynamic> json) =>
    $checkedCreate('ValidationPolicy', json, ($checkedConvert) {
      $checkKeys(
        json,
        allowedKeys: const [
          'referenceDataExistence',
          'referenceDataIntact',
          'signatureIntact',
          'prospectiveCertificateChain',
          'signingCertificateNotExpired',
          'revocationDataAvailable',
          'signingCertificatePresent',
          'certDigestPresent',
          'certDigestMatch',
          'issuerSerialMatch',
          'signingTime',
          'signingTimeInCertRange',
          'caCertificateNotExpired',
          'caCertificateCa',
          'caCertificateMaxPathLength',
          'caCertificateKeyUsage',
          'cryptographic',
          'algorithmExpiration',
        ],
      );
      final val = ValidationPolicy(
        referenceDataExistence: $checkedConvert(
          'referenceDataExistence',
          (v) =>
              $enumDecodeNullable(_$ConstraintLevelEnumMap, v) ??
              ConstraintLevel.fail,
        ),
        referenceDataIntact: $checkedConvert(
          'referenceDataIntact',
          (v) =>
              $enumDecodeNullable(_$ConstraintLevelEnumMap, v) ??
              ConstraintLevel.fail,
        ),
        signatureIntact: $checkedConvert(
          'signatureIntact',
          (v) =>
              $enumDecodeNullable(_$ConstraintLevelEnumMap, v) ??
              ConstraintLevel.fail,
        ),
        prospectiveCertificateChain: $checkedConvert(
          'prospectiveCertificateChain',
          (v) =>
              $enumDecodeNullable(_$ConstraintLevelEnumMap, v) ??
              ConstraintLevel.fail,
        ),
        signingCertificateNotExpired: $checkedConvert(
          'signingCertificateNotExpired',
          (v) =>
              $enumDecodeNullable(_$ConstraintLevelEnumMap, v) ??
              ConstraintLevel.fail,
        ),
        revocationDataAvailable: $checkedConvert(
          'revocationDataAvailable',
          (v) =>
              $enumDecodeNullable(_$ConstraintLevelEnumMap, v) ??
              ConstraintLevel.fail,
        ),
        signingCertificatePresent: $checkedConvert(
          'signingCertificatePresent',
          (v) =>
              $enumDecodeNullable(_$ConstraintLevelEnumMap, v) ??
              ConstraintLevel.warn,
        ),
        certDigestPresent: $checkedConvert(
          'certDigestPresent',
          (v) =>
              $enumDecodeNullable(_$ConstraintLevelEnumMap, v) ??
              ConstraintLevel.fail,
        ),
        certDigestMatch: $checkedConvert(
          'certDigestMatch',
          (v) =>
              $enumDecodeNullable(_$ConstraintLevelEnumMap, v) ??
              ConstraintLevel.fail,
        ),
        issuerSerialMatch: $checkedConvert(
          'issuerSerialMatch',
          (v) =>
              $enumDecodeNullable(_$ConstraintLevelEnumMap, v) ??
              ConstraintLevel.warn,
        ),
        signingTime: $checkedConvert(
          'signingTime',
          (v) =>
              $enumDecodeNullable(_$ConstraintLevelEnumMap, v) ??
              ConstraintLevel.fail,
        ),
        signingTimeInCertRange: $checkedConvert(
          'signingTimeInCertRange',
          (v) =>
              $enumDecodeNullable(_$ConstraintLevelEnumMap, v) ??
              ConstraintLevel.fail,
        ),
        caCertificateNotExpired: $checkedConvert(
          'caCertificateNotExpired',
          (v) =>
              $enumDecodeNullable(_$ConstraintLevelEnumMap, v) ??
              ConstraintLevel.fail,
        ),
        caCertificateCa: $checkedConvert(
          'caCertificateCa',
          (v) =>
              $enumDecodeNullable(_$ConstraintLevelEnumMap, v) ??
              ConstraintLevel.fail,
        ),
        caCertificateMaxPathLength: $checkedConvert(
          'caCertificateMaxPathLength',
          (v) =>
              $enumDecodeNullable(_$ConstraintLevelEnumMap, v) ??
              ConstraintLevel.fail,
        ),
        caCertificateKeyUsage: $checkedConvert(
          'caCertificateKeyUsage',
          (v) =>
              $enumDecodeNullable(_$ConstraintLevelEnumMap, v) ??
              ConstraintLevel.fail,
        ),
        cryptographic: $checkedConvert(
          'cryptographic',
          (v) =>
              $enumDecodeNullable(_$ConstraintLevelEnumMap, v) ??
              ConstraintLevel.fail,
        ),
        algorithmExpiration: $checkedConvert(
          'algorithmExpiration',
          (v) =>
              $enumDecodeNullable(_$ConstraintLevelEnumMap, v) ??
              ConstraintLevel.fail,
        ),
      );
      return val;
    });

Map<String, dynamic> _$ValidationPolicyToJson(
  ValidationPolicy instance,
) => <String, dynamic>{
  'referenceDataExistence':
      _$ConstraintLevelEnumMap[instance.referenceDataExistence]!,
  'referenceDataIntact':
      _$ConstraintLevelEnumMap[instance.referenceDataIntact]!,
  'signatureIntact': _$ConstraintLevelEnumMap[instance.signatureIntact]!,
  'prospectiveCertificateChain':
      _$ConstraintLevelEnumMap[instance.prospectiveCertificateChain]!,
  'signingCertificateNotExpired':
      _$ConstraintLevelEnumMap[instance.signingCertificateNotExpired]!,
  'revocationDataAvailable':
      _$ConstraintLevelEnumMap[instance.revocationDataAvailable]!,
  'signingCertificatePresent':
      _$ConstraintLevelEnumMap[instance.signingCertificatePresent]!,
  'certDigestPresent': _$ConstraintLevelEnumMap[instance.certDigestPresent]!,
  'certDigestMatch': _$ConstraintLevelEnumMap[instance.certDigestMatch]!,
  'issuerSerialMatch': _$ConstraintLevelEnumMap[instance.issuerSerialMatch]!,
  'signingTime': _$ConstraintLevelEnumMap[instance.signingTime]!,
  'signingTimeInCertRange':
      _$ConstraintLevelEnumMap[instance.signingTimeInCertRange]!,
  'caCertificateNotExpired':
      _$ConstraintLevelEnumMap[instance.caCertificateNotExpired]!,
  'caCertificateCa': _$ConstraintLevelEnumMap[instance.caCertificateCa]!,
  'caCertificateMaxPathLength':
      _$ConstraintLevelEnumMap[instance.caCertificateMaxPathLength]!,
  'caCertificateKeyUsage':
      _$ConstraintLevelEnumMap[instance.caCertificateKeyUsage]!,
  'cryptographic': _$ConstraintLevelEnumMap[instance.cryptographic]!,
  'algorithmExpiration':
      _$ConstraintLevelEnumMap[instance.algorithmExpiration]!,
};

const _$ConstraintLevelEnumMap = {
  ConstraintLevel.fail: 'fail',
  ConstraintLevel.warn: 'warn',
  ConstraintLevel.inform: 'inform',
  ConstraintLevel.ignore: 'ignore',
};
