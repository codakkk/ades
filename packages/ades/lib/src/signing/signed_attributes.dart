import 'dart:convert';
import 'dart:typed_data';

import '../asn1/asn1.dart';
import '../cms/signed_data.dart';
import '../x509/certificate.dart';

/// Builds the CAdES-B-B signed attributes and returns the DTBS: the DER
/// `SET OF Attribute` (RFC 5652 5.4), sorted by encoding. Pure and
/// deterministic, so a draft can be re-checked from its fields.
///
/// Attributes: contentType, messageDigest, signingTime and
/// signingCertificateV2 (ESSCertIDv2 with the SHA-256 default hash
/// algorithm omitted, as DER requires for a DEFAULT value, and
/// issuerSerial).
Uint8List buildSignedAttributesDtbs({
  required String contentTypeOid,
  required Uint8List messageDigest,
  required DateTime signingTime,
  required Uint8List signingCertificateSha256,
  required X509Certificate signingCertificate,
}) {
  Asn1Element attr(String oid, Asn1Element value) => Asn1Element.sequence([
    Asn1Element.oid(oid),
    Asn1Element.setOf([value]),
  ]);

  final issuerName = decodeDer(signingCertificate.issuerDer);
  final essCertId = Asn1Element.sequence([
    Asn1Element.octetString(signingCertificateSha256),
    Asn1Element.sequence([
      Asn1Element.sequence([
        Asn1Element.constructed(
          const Asn1Tag(Asn1Class.contextSpecific, true, 4),
          [issuerName],
        ),
      ]),
      Asn1Element.integer(signingCertificate.serialNumber),
    ]),
  ]);

  final attrs = Asn1Element.setOf([
    attr(CmsOids.contentType, Asn1Element.oid(contentTypeOid)),
    attr(CmsOids.messageDigest, Asn1Element.octetString(messageDigest)),
    attr(CmsOids.signingTime, encodeTime(signingTime)),
    attr(
      CmsOids.signingCertificateV2,
      Asn1Element.sequence([
        Asn1Element.sequence([essCertId]),
      ]),
    ),
  ]);
  return attrs.encode();
}

/// UTCTime for 1950..2049, GeneralizedTime otherwise (RFC 5280 4.1.2.5),
/// always `Z`, whole seconds.
Asn1Element encodeTime(DateTime time) {
  final t = time.toUtc();
  String two(int v) => v.toString().padLeft(2, '0');
  final rest =
      '${two(t.month)}${two(t.day)}${two(t.hour)}${two(t.minute)}'
      '${two(t.second)}Z';
  if (t.year >= 1950 && t.year < 2050) {
    return Asn1Element.primitive(
      const Asn1Tag.universal(23),
      Uint8List.fromList(ascii.encode('${two(t.year % 100)}$rest')),
    );
  }
  return Asn1Element.primitive(
    const Asn1Tag.universal(24),
    Uint8List.fromList(
      ascii.encode('${t.year.toString().padLeft(4, '0')}$rest'),
    ),
  );
}
