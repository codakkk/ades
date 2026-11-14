import 'package:ades/ades.dart';

/// Hand-written diagnostic data (no parsing involved) for seam 2 tests: one
/// healthy signature whose signing certificate is a trust anchor valid from
/// 2024-01-01 to 2049-12-31, issued by an anchor CA (C-1). Tests mutate the JSON, then decide.
Map<String, dynamic> goldenBase() => {
  'formatFailure': null,
  'certificates': [
    {
      'id': 'C-0',
      'der': 'AAEC',
      'subject': 'CN=Golden Signer',
      'issuer': 'CN=Golden CA',
      'serialNumber': '01',
      'notBefore': '2024-01-01T00:00:00.000Z',
      'notAfter': '2049-12-31T23:59:59.000Z',
      'trustAnchor': false,
      'keyUsage': ['nonRepudiation'],
      'basicConstraints': null,
      'signatureAlgorithmOid': '1.2.840.113549.1.1.11',
      'publicKeyAlgorithm': 'rsa',
      'publicKeySize': 2048,
    },
    {
      'id': 'C-1',
      'der': 'AwQF',
      'subject': 'CN=Golden CA',
      'issuer': 'CN=Golden CA',
      'serialNumber': '02',
      'notBefore': '2020-01-01T00:00:00.000Z',
      'notAfter': '2049-12-31T23:59:59.000Z',
      'trustAnchor': true,
      'keyUsage': ['keyCertSign', 'cRlSign'],
      'basicConstraints': {'isCa': true, 'pathLenConstraint': 0},
      'signatureAlgorithmOid': '1.2.840.113549.1.1.11',
      'publicKeyAlgorithm': 'rsa',
      'publicKeySize': 2048,
    },
  ],
  'signatures': [
    {
      'index': 0,
      'formatIssues': <String>[],
      'digestAlgorithmOid': '2.16.840.1.101.3.4.2.1',
      'signatureAlgorithmOid': '1.2.840.113549.1.1.11',
      'signedAttributesPresent': true,
      'signedAttributesDer': true,
      'signingTime': '2026-01-01T12:00:00.000Z',
      'signingCertificateReference': {
        'version': 2,
        'hashAlgorithm': 'sha256',
        'certHash': 'AAEC',
        'issuerSerialMatches': null,
      },
      'signingCertificateId': 'C-0',
      'certificateChain': ['C-0', 'C-1'],
      'signingCertificateReferenceMatches': true,
      'contentAvailable': true,
      'messageDigestMatches': true,
      'signatureCheck': 'verified',
      'scope': null,
    },
  ],
};

/// The signature, signer certificate (C-0) and CA certificate (C-1) of
/// [goldenBase], mutated by [edit].
DiagnosticData golden(
  void Function(
    Map<String, dynamic> signature,
    Map<String, dynamic> cert,
    Map<String, dynamic> ca,
  )?
  edit,
) {
  final m = goldenBase();
  final sig = (m['signatures'] as List<Object?>).first as Map<String, dynamic>;
  final cert =
      (m['certificates'] as List<Object?>).first as Map<String, dynamic>;
  final ca = (m['certificates'] as List<Object?>).last as Map<String, dynamic>;
  edit?.call(sig, cert, ca);
  return DiagnosticData.fromJson(m);
}
