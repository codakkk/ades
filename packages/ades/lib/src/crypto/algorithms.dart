import 'dart:typed_data';

import '../asn1/asn1.dart';

/// Digest algorithms the validator can compute (verification side).
///
/// Creation will restrict itself to [sha256] (ticket 08); older algorithms
/// are listed so that existing signatures can be read and judged by policy.
enum DigestAlgorithm {
  sha1('1.3.14.3.2.26', 'SHA-1'),
  sha256('2.16.840.1.101.3.4.2.1', 'SHA-256'),
  sha384('2.16.840.1.101.3.4.2.2', 'SHA-384'),
  sha512('2.16.840.1.101.3.4.2.3', 'SHA-512');

  const DigestAlgorithm(this.oid, this.displayName);

  final String oid;
  final String displayName;

  /// The DER `DigestInfo` (RFC 8017 9.2) wrapping [hash], the form RSA
  /// PKCS#1 v1.5 signs.
  Uint8List digestInfo(Uint8List hash) => Asn1Element.sequence([
    Asn1Element.sequence([Asn1Element.oid(oid), Asn1Element.nullValue()]),
    Asn1Element.octetString(hash),
  ]).encode();

  /// The algorithm with this OID, or null when it is not known.
  static DigestAlgorithm? fromOid(String oid) {
    for (final a in values) {
      if (a.oid == oid) return a;
    }
    return null;
  }
}

/// The mathematical family of a signature algorithm.
///
/// Extension point: RSA-PSS and others later.
enum SignatureScheme {
  rsaPkcs1v15,

  /// ECDSA; the signature value is a DER `Ecdsa-Sig-Value` (RFC 3279).
  ecdsa,
}

/// A signature algorithm: a [scheme] applied over a [digest].
final class SignatureAlgorithm {
  const SignatureAlgorithm(this.scheme, this.digest);

  static const rsaPkcs1v15Sha256 = SignatureAlgorithm(
    SignatureScheme.rsaPkcs1v15,
    DigestAlgorithm.sha256,
  );

  final SignatureScheme scheme;
  final DigestAlgorithm digest;

  /// Signature algorithm OIDs (certificates and CMS) that fix both scheme
  /// and digest, mapped to the algorithm they name.
  static const _byOid = <String, SignatureAlgorithm>{
    '1.2.840.113549.1.1.5': SignatureAlgorithm(
      SignatureScheme.rsaPkcs1v15,
      DigestAlgorithm.sha1,
    ),
    '1.2.840.113549.1.1.11': SignatureAlgorithm(
      SignatureScheme.rsaPkcs1v15,
      DigestAlgorithm.sha256,
    ),
    '1.2.840.113549.1.1.12': SignatureAlgorithm(
      SignatureScheme.rsaPkcs1v15,
      DigestAlgorithm.sha384,
    ),
    '1.2.840.113549.1.1.13': SignatureAlgorithm(
      SignatureScheme.rsaPkcs1v15,
      DigestAlgorithm.sha512,
    ),
    '1.2.840.10045.4.1': SignatureAlgorithm(
      SignatureScheme.ecdsa,
      DigestAlgorithm.sha1,
    ),
    '1.2.840.10045.4.3.2': SignatureAlgorithm(
      SignatureScheme.ecdsa,
      DigestAlgorithm.sha256,
    ),
    '1.2.840.10045.4.3.3': SignatureAlgorithm(
      SignatureScheme.ecdsa,
      DigestAlgorithm.sha384,
    ),
    '1.2.840.10045.4.3.4': SignatureAlgorithm(
      SignatureScheme.ecdsa,
      DigestAlgorithm.sha512,
    ),
  };

  /// Key-type OIDs (rsaEncryption, id-ecPublicKey) used as a CMS
  /// signatureAlgorithm: they name the scheme only, the digest comes from the
  /// SignerInfo.
  static const _rsaEncryptionOid = '1.2.840.113549.1.1.1';

  static const _schemeByKeyOid = <String, SignatureScheme>{
    _rsaEncryptionOid: SignatureScheme.rsaPkcs1v15,
    '1.2.840.10045.2.1': SignatureScheme.ecdsa,
  };

  /// The OID a new CMS SignerInfo carries as signatureAlgorithm: the combined
  /// OID for ECDSA (RFC 5758), rsaEncryption for RSA PKCS#1 v1.5 (RFC 3370).
  String get cmsOid => switch (scheme) {
    SignatureScheme.rsaPkcs1v15 => _rsaEncryptionOid,
    SignatureScheme.ecdsa =>
      _byOid.entries
          .firstWhere(
            (e) => e.value == this && e.key.startsWith('1.2.840.10045'),
          )
          .key,
  };

  /// The algorithm named by [oid] (sha256WithRSAEncryption, ecdsa-with-SHA256,
  /// ...), or null when [oid] is not a known combined algorithm.
  static SignatureAlgorithm? fromOid(String oid) => _byOid[oid];

  /// Resolves the algorithm of a CMS SignerInfo from its signatureAlgorithm
  /// OID and its [digest] (null when the digest OID is unknown). Null when
  /// they do not name a supported algorithm or contradict each other.
  static SignatureAlgorithm? forCms(
    String signatureAlgorithmOid,
    DigestAlgorithm? digest,
  ) {
    if (digest == null) return null;
    final fixed = _byOid[signatureAlgorithmOid];
    if (fixed != null) return fixed.digest == digest ? fixed : null;
    final scheme = _schemeByKeyOid[signatureAlgorithmOid];
    return scheme == null ? null : SignatureAlgorithm(scheme, digest);
  }

  @override
  bool operator ==(Object other) =>
      other is SignatureAlgorithm &&
      other.scheme == scheme &&
      other.digest == digest;

  @override
  int get hashCode => Object.hash(scheme, digest);

  @override
  String toString() => '${scheme.name}/${digest.displayName}';
}
