import 'dart:typed_data';

import '../asn1/asn1.dart';
import '../asn1/structure.dart';
import '../crypto/algorithms.dart';
import '../crypto/crypto_provider.dart';
import 'signed_data_stream.dart';

/// OIDs used by CAdES-B-B.
abstract final class CmsOids {
  static const data = '1.2.840.113549.1.7.1';
  static const signedData = '1.2.840.113549.1.7.2';
  static const contentType = '1.2.840.113549.1.9.3';
  static const messageDigest = '1.2.840.113549.1.9.4';
  static const signingTime = '1.2.840.113549.1.9.5';
  static const signingCertificate = '1.2.840.113549.1.9.16.2.12';
  static const signingCertificateV2 = '1.2.840.113549.1.9.16.2.47';
}

/// How a signer identifies its certificate (RFC 5652 5.3).
sealed class SignerIdentifier {
  const SignerIdentifier();
}

final class IssuerAndSerial extends SignerIdentifier {
  const IssuerAndSerial(this.issuerDer, this.serialNumber);

  final Uint8List issuerDer;
  final BigInt serialNumber;
}

final class SubjectKeyId extends SignerIdentifier {
  const SubjectKeyId(this.keyId);

  final Uint8List keyId;
}

/// A SignerInfo's signed attributes.
final class CmsSignedAttributes {
  CmsSignedAttributes._(this.dtbs, this.isDer, this.byOid);

  /// The data to be signed: the attributes as transmitted, with the
  /// `[0] IMPLICIT` tag replaced by the SET OF tag (RFC 5652 5.4). Built from
  /// the original bytes, never re-encoded (ADR-0004).
  final Uint8List dtbs;

  /// Whether the SET OF is in DER order. A false value is a validation
  /// failure (ADR-0004), reported by the validator.
  final bool isDer;

  /// Attribute values by attribute OID, in transmission order.
  final Map<String, List<Asn1Element>> byOid;
}

/// A SignerInfo (RFC 5652 5.3).
final class CmsSignerInfo {
  const CmsSignerInfo({
    required this.identifier,
    required this.digestAlgorithmOid,
    required this.signedAttributes,
    required this.signatureAlgorithmOid,
    required this.signature,
  });

  final SignerIdentifier identifier;
  final String digestAlgorithmOid;
  final CmsSignedAttributes? signedAttributes;
  final String signatureAlgorithmOid;
  final Uint8List signature;
}

/// A parsed CMS SignedData (RFC 5652 5).
///
/// The outer structure is read as bounded BER (ADR-0004): indefinite lengths
/// and the other BER forms are accepted within limits and reported in
/// [deviations]. The signed attributes stay strict DER, certificates are
/// re-parsed strictly by the X.509 parser. Input comes either from memory
/// ([parse]) or from a stream ([parseStream]); in the second case the
/// encapsulated content is hashed on the fly and never held, so only
/// [contentDigests] and [contentLength] describe it.
final class CmsSignedData {
  const CmsSignedData({
    required this.contentType,
    required this.content,
    required this.certificates,
    required this.signerInfos,
    this.contentLength,
    this.contentDigests = const {},
    this.deviations = const [],
  });

  /// Parses a ContentInfo holding SignedData. Throws [StructureException] or
  /// [Asn1Exception].
  factory CmsSignedData.parse(
    Uint8List bytes, {
    Asn1Limits limits = Asn1Limits.defaults,
  }) {
    final dev = BerDeviations();
    final ci = decodeBer(bytes, limits: limits, deviations: dev);
    final ciParts = ci.sequenceOf('ContentInfo');
    if (ciParts.length != 2 || ciParts[0].asOid != CmsOids.signedData) {
      throw const StructureException('not a CMS SignedData ContentInfo');
    }
    if (!ciParts[1].isContext(0) || ciParts[1].children!.length != 1) {
      throw const StructureException('ContentInfo content must be [0]');
    }
    final sd = ciParts[1].children![0].sequenceOf('SignedData');
    if (sd.length < 4) throw const StructureException('SignedData too short');
    sd[0].expect(Asn1Tag.integer, 'SignedData version');
    sd[1].setOf('digestAlgorithms');
    final eci = sd[2].sequenceOf('EncapsulatedContentInfo');
    if (eci.isEmpty || eci.length > 2) {
      throw const StructureException('EncapsulatedContentInfo malformed');
    }
    final contentType = eci[0].asOid;
    Uint8List? content;
    if (eci.length == 2) {
      if (!eci[1].isContext(0) || eci[1].children!.length != 1) {
        throw const StructureException('eContent must be [0] EXPLICIT');
      }
      content = octetStringBytes(eci[1].children![0]);
    }
    return fromParts(
      contentType: contentType,
      content: content,
      contentLength: content?.length,
      contentDigests: const {},
      rest: sd.sublist(3),
      deviations: dev,
    );
  }

  /// Reads a ContentInfo holding SignedData from [input] without buffering
  /// the encapsulated content: it is passed to [digests] (one sink per
  /// digest algorithm listed in the SignedData) and dropped. Memory use is
  /// bounded by one input chunk plus the largest non-content element
  /// ([Asn1Limits.maxBufferedElement]).
  ///
  /// Throws [StructureException] or [Asn1Exception] (also for a failing
  /// input stream is reported as given).
  static Future<CmsSignedData> parseStream(
    Stream<List<int>> input, {
    required CryptoProvider crypto,
    Asn1Limits limits = Asn1Limits.defaults,
  }) => readCmsStream(input, crypto: crypto, limits: limits);

  /// Assembles the model from the elements after the EncapsulatedContentInfo
  /// (certificates, crls, signerInfos). Shared by the in-memory and the
  /// streaming readers.
  static CmsSignedData fromParts({
    required String contentType,
    required Uint8List? content,
    required int? contentLength,
    required Map<DigestAlgorithm, Uint8List> contentDigests,
    required List<Asn1Element> rest,
    required BerDeviations deviations,
  }) {
    var i = 0;
    final certs = <Uint8List>[];
    if (rest.isEmpty) throw const StructureException('SignedData too short');
    if (rest[i].isContext(0)) {
      for (final c in rest[i].childrenOf('certificates')) {
        // Only plain certificates; other CertificateChoices are ignored.
        if (c.tag == Asn1Tag.sequence) certs.add(c.encoded);
      }
      i++;
    }
    if (i < rest.length && rest[i].isContext(1)) i++; // CRLs: not used here
    if (i != rest.length - 1) {
      throw const StructureException('SignedData has unexpected elements');
    }
    final signerInfos = [
      for (final si in rest[i].setOf('signerInfos')) _parseSignerInfo(si),
    ];
    return CmsSignedData(
      contentType: contentType,
      content: content,
      contentLength: contentLength,
      contentDigests: Map.unmodifiable(contentDigests),
      certificates: List.unmodifiable(certs),
      signerInfos: List.unmodifiable(signerInfos),
      deviations: deviations.items,
    );
  }

  /// The digest algorithms named in a `digestAlgorithms` SET that this
  /// library can compute, without duplicates.
  static List<DigestAlgorithm> knownDigestAlgorithms(Asn1Element set) {
    final out = <DigestAlgorithm>[];
    for (final a in set.setOf('digestAlgorithms')) {
      final alg = DigestAlgorithm.fromOid(_algorithmOid(a, 'digestAlgorithm'));
      if (alg != null && !out.contains(alg)) out.add(alg);
    }
    return out;
  }

  /// eContentType.
  final String contentType;

  /// The encapsulated content octets (a view of the input), or null for a
  /// detached signature or when the input was streamed.
  final Uint8List? content;

  /// Number of content octets, or null when there is no encapsulated
  /// content.
  final int? contentLength;

  /// Digests of the content computed while streaming, by algorithm. Empty
  /// for in-memory input, where [content] is hashed by the caller.
  final Map<DigestAlgorithm, Uint8List> contentDigests;

  /// Embedded certificates, as original DER encodings.
  final List<Uint8List> certificates;
  final List<CmsSignerInfo> signerInfos;

  /// Non-DER forms found outside the signed attributes (warnings).
  final List<BerDeviation> deviations;
}

CmsSignerInfo _parseSignerInfo(Asn1Element e) {
  final f = e.sequenceOf('SignerInfo');
  if (f.length < 5) throw const StructureException('SignerInfo too short');
  f[0].expect(Asn1Tag.integer, 'SignerInfo version');
  final sid = _parseSid(f[1]);
  final digestOid = _algorithmOid(f[2], 'digestAlgorithm');
  var i = 3;
  CmsSignedAttributes? attrs;
  if (f[i].isContext(0)) {
    attrs = _parseSignedAttributes(f[i]);
    i++;
  }
  if (f.length < i + 2) throw const StructureException('SignerInfo too short');
  final sigAlg = _algorithmOid(f[i++], 'signatureAlgorithm');
  final sig = octetStringBytes(f[i++]);
  if (i < f.length && f[i].isContext(1)) i++; // unsignedAttrs: not used
  if (i != f.length) {
    throw const StructureException('SignerInfo has unexpected elements');
  }
  return CmsSignerInfo(
    identifier: sid,
    digestAlgorithmOid: digestOid,
    signedAttributes: attrs,
    signatureAlgorithmOid: sigAlg,
    signature: sig,
  );
}

SignerIdentifier _parseSid(Asn1Element e) {
  if (e.tag == Asn1Tag.sequence) {
    final p = e.children!;
    if (p.length != 2) {
      throw const StructureException('IssuerAndSerialNumber malformed');
    }
    return IssuerAndSerial(
      p[0].expect(Asn1Tag.sequence, 'issuer').encoded,
      p[1].expect(Asn1Tag.integer, 'serialNumber').asInteger,
    );
  }
  if (e.tag == const Asn1Tag(Asn1Class.contextSpecific, false, 0)) {
    return SubjectKeyId(e.contentBytes);
  }
  throw const StructureException('unknown SignerIdentifier');
}

String _algorithmOid(Asn1Element e, String what) {
  final p = e.sequenceOf(what);
  if (p.isEmpty || p.length > 2) {
    throw StructureException('$what is not an AlgorithmIdentifier');
  }
  return p[0].asOid;
}

CmsSignedAttributes _parseSignedAttributes(Asn1Element e) {
  final children = e.childrenOf('signedAttrs');
  final byOid = <String, List<Asn1Element>>{};
  for (final a in children) {
    final p = a.sequenceOf('Attribute');
    if (p.length != 2) throw const StructureException('Attribute malformed');
    byOid.putIfAbsent(p[0].asOid, () => []).addAll(p[1].setOf('attrValues'));
  }
  // Strict DER (ADR-0004): definite, minimal encodings, as transmitted.
  var sorted = true;
  try {
    decodeDer(e.encoded, enforceSetOrder: false);
  } on Asn1Exception {
    sorted = false;
  }
  for (var i = 1; i < children.length && sorted; i++) {
    sorted =
        compareSetOfEncodings(children[i - 1].encoded, children[i].encoded) <=
        0;
  }
  final dtbs = Uint8List.fromList(e.encoded)..[0] = 0x31;
  return CmsSignedAttributes._(dtbs, sorted, byOid);
}
