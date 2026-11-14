import 'dart:convert';
import 'dart:typed_data';

import '../asn1/asn1.dart';
import '../asn1/structure.dart';
import '../crypto/public_key.dart';
import 'time.dart';

const _rsaEncryptionOid = '1.2.840.113549.1.1.1';
const _subjectKeyIdentifierOid = '2.5.29.14';
const _keyUsageOid = '2.5.29.15';
const _basicConstraintsOid = '2.5.29.19';

/// Bits of the keyUsage extension (RFC 5280 4.2.1.3), in bit order.
enum KeyUsageFlag {
  digitalSignature,
  nonRepudiation,
  keyEncipherment,
  dataEncipherment,
  keyAgreement,
  keyCertSign,
  cRlSign,
  encipherOnly,
  decipherOnly,
}

/// The basicConstraints extension (RFC 5280 4.2.1.9).
final class BasicConstraints {
  const BasicConstraints({required this.isCa, required this.pathLenConstraint});

  final bool isCa;

  /// Null when absent (no limit).
  final int? pathLenConstraint;
}

/// One certificate extension, unparsed (RFC 5280 4.1.2.9).
final class X509Extension {
  const X509Extension(this.oid, this.critical, this.value);

  final String oid;
  final bool critical;

  /// Content of the extnValue OCTET STRING (a DER structure).
  final Uint8List value;
}

/// A parsed X.509 certificate (RFC 5280). Strict DER throughout.
///
/// Public so that signing credentials (soft keys, smart cards) can read the
/// facts they need from a certificate: its public key, key usage and names
/// (ADR-0011). Typed accessors for further extensions are added over
/// [extensions]; path building uses [issuerDer]/[subjectDer] byte
/// comparison.
final class X509Certificate {
  X509Certificate._({
    required this.der,
    required this.tbsBytes,
    required this.serialNumber,
    required this.signatureAlgorithmOid,
    required this.issuerDer,
    required this.subjectDer,
    required this.issuer,
    required this.subject,
    required this.notBefore,
    required this.notAfter,
    required this.publicKey,
    required this.extensions,
    required this.signatureValue,
    required this.keyUsage,
    required this.basicConstraints,
  });

  /// Parses a DER certificate. Throws [FormatException] when [der] is not a
  /// well-formed certificate (the caller handed in something that is not one;
  /// hostile input inside a signature is handled by the validator instead).
  factory X509Certificate.parse(Uint8List der) {
    try {
      return _parse(der);
    } on StructureException catch (e) {
      throw FormatException('not a certificate: ${e.message}');
    } on Asn1Exception catch (e) {
      throw FormatException('not a certificate: $e');
    }
  }

  static X509Certificate _parse(Uint8List der) {
    final root = decodeDer(der);
    final top = root.sequenceOf('Certificate');
    if (top.length != 3) {
      throw const StructureException('Certificate must have 3 elements');
    }
    final tbs = top[0];
    final f = tbs.sequenceOf('TBSCertificate');
    var i = 0;
    if (i < f.length && f[i].isContext(0)) i++; // version
    if (f.length < i + 6) {
      throw const StructureException('TBSCertificate is too short');
    }
    final serial = f[i++].expect(Asn1Tag.integer, 'serialNumber').asInteger;
    final sigAlg = _algorithmOid(f[i++], 'signature');
    final issuer = f[i++].expect(Asn1Tag.sequence, 'issuer');
    final validity = f[i++].sequenceOf('validity');
    if (validity.length != 2) {
      throw const StructureException('validity must have 2 elements');
    }
    final subject = f[i++].expect(Asn1Tag.sequence, 'subject');
    final spki = f[i++].sequenceOf('subjectPublicKeyInfo');
    if (spki.length != 2) {
      throw const StructureException('SPKI must have 2 elements');
    }
    final outerSigAlg = _algorithmOid(top[1], 'signatureAlgorithm');
    if (outerSigAlg != sigAlg) {
      throw const StructureException('signature algorithm fields differ');
    }
    final extensions = <X509Extension>[];
    for (var j = i; j < f.length; j++) {
      if (f[j].isContext(3)) {
        extensions.addAll(_parseExtensions(f[j]));
      }
    }
    return X509Certificate._(
      der: der,
      tbsBytes: tbs.encoded,
      serialNumber: serial,
      signatureAlgorithmOid: sigAlg,
      issuerDer: issuer.encoded,
      subjectDer: subject.encoded,
      issuer: nameToString(issuer),
      subject: nameToString(subject),
      notBefore: parseAsn1Time(validity[0], 'notBefore'),
      notAfter: parseAsn1Time(validity[1], 'notAfter'),
      publicKey: _parsePublicKey(spki),
      extensions: List.unmodifiable(extensions),
      signatureValue: top[2].asBitString.bytes,
      keyUsage: _parseKeyUsage(extensions),
      basicConstraints: _parseBasicConstraints(extensions),
    );
  }

  /// The complete DER encoding (original bytes).
  final Uint8List der;

  /// The exact TBSCertificate bytes the issuer signed.
  final Uint8List tbsBytes;

  final BigInt serialNumber;
  final String signatureAlgorithmOid;

  /// Raw DER of the issuer and subject names (compare bytes, not strings).
  final Uint8List issuerDer;
  final Uint8List subjectDer;

  /// Human-readable RFC 4514-style renderings, for reports only.
  final String issuer;
  final String subject;

  final DateTime notBefore;
  final DateTime notAfter;
  final PublicKey publicKey;
  final List<X509Extension> extensions;
  final Uint8List signatureValue;

  /// keyUsage bits; null when the extension is absent.
  final Set<KeyUsageFlag>? keyUsage;

  /// Null when the extension is absent.
  final BasicConstraints? basicConstraints;

  /// The subjectKeyIdentifier extension value, if present.
  Uint8List? get subjectKeyIdentifier {
    for (final e in extensions) {
      if (e.oid == _subjectKeyIdentifierOid) {
        try {
          return decodeDer(e.value).asOctetString;
        } on Asn1Exception {
          return null;
        }
      }
    }
    return null;
  }
}

X509Extension? _find(List<X509Extension> exts, String oid) {
  X509Extension? found;
  for (final e in exts) {
    if (e.oid != oid) continue;
    if (found != null) {
      throw StructureException('duplicate extension $oid');
    }
    found = e;
  }
  return found;
}

Set<KeyUsageFlag>? _parseKeyUsage(List<X509Extension> exts) {
  final e = _find(exts, _keyUsageOid);
  if (e == null) return null;
  final bits = decodeDer(e.value).asBitString;
  final out = <KeyUsageFlag>{};
  for (final f in KeyUsageFlag.values) {
    final byte = f.index ~/ 8;
    if (byte < bits.bytes.length &&
        bits.bytes[byte] & (0x80 >> (f.index % 8)) != 0) {
      out.add(f);
    }
  }
  return Set.unmodifiable(out);
}

BasicConstraints? _parseBasicConstraints(List<X509Extension> exts) {
  final e = _find(exts, _basicConstraintsOid);
  if (e == null) return null;
  final seq = decodeDer(e.value).sequenceOf('BasicConstraints');
  var i = 0;
  var isCa = false;
  if (i < seq.length && seq[i].tag == Asn1Tag.boolean) {
    isCa = seq[i++].asBoolean;
  }
  int? pathLen;
  if (i < seq.length) {
    final v = seq[i++].expect(Asn1Tag.integer, 'pathLenConstraint').asInteger;
    if (v.sign < 0 || v > BigInt.from(0xffff)) {
      throw const StructureException('pathLenConstraint out of range');
    }
    pathLen = v.toInt();
  }
  if (i != seq.length) {
    throw const StructureException('BasicConstraints has extra elements');
  }
  return BasicConstraints(isCa: isCa, pathLenConstraint: pathLen);
}

List<X509Extension> _parseExtensions(Asn1Element wrapper) {
  final seq = wrapper.childrenOf('extensions');
  if (seq.length != 1) {
    throw const StructureException('extensions wrapper must hold one element');
  }
  final out = <X509Extension>[];
  for (final e in seq[0].sequenceOf('extensions')) {
    final p = e.sequenceOf('extension');
    if (p.length < 2 || p.length > 3) {
      throw const StructureException('extension has a wrong element count');
    }
    final oid = p[0].asOid;
    final critical = p.length == 3 ? p[1].asBoolean : false;
    out.add(X509Extension(oid, critical, p.last.asOctetString));
  }
  return out;
}

String _algorithmOid(Asn1Element e, String what) {
  final p = e.sequenceOf(what);
  if (p.isEmpty || p.length > 2) {
    throw StructureException('$what is not an AlgorithmIdentifier');
  }
  return p[0].asOid;
}

const _ecPublicKeyOid = '1.2.840.10045.2.1';

/// SubjectPublicKeyInfo with id-ecPublicKey (RFC 5480): named curve only,
/// uncompressed point. Other curves stay [UnsupportedPublicKey].
PublicKey _parseEcKey(List<Asn1Element> spki, Asn1BitString bits) {
  final params = spki[0].sequenceOf('SPKI algorithm');
  if (params.length != 2 || params[1].tag != Asn1Tag.oid) {
    return const UnsupportedPublicKey(_ecPublicKeyOid);
  }
  final curve = EcCurve.fromOid(params[1].asOid);
  if (curve == null) return UnsupportedPublicKey(params[1].asOid);
  final b = bits.bytes;
  final size = (curve == EcCurve.p521
      ? 521
      : curve == EcCurve.p384
      ? 384
      : 256);
  final n = (size + 7) ~/ 8;
  if (bits.unusedBits != 0 || b.length != 1 + 2 * n || b[0] != 4) {
    throw const StructureException('EC point must be uncompressed');
  }
  BigInt big(int from) {
    var v = BigInt.zero;
    for (var i = from; i < from + n; i++) {
      v = (v << 8) | BigInt.from(b[i]);
    }
    return v;
  }

  return EcPublicKey(curve, big(1), big(1 + n));
}

PublicKey _parsePublicKey(List<Asn1Element> spki) {
  final oid = _algorithmOid(spki[0], 'SPKI algorithm');
  final bits = spki[1].asBitString;
  if (oid == _ecPublicKeyOid) return _parseEcKey(spki, bits);
  if (oid != _rsaEncryptionOid) return UnsupportedPublicKey(oid);
  if (bits.unusedBits != 0) {
    throw const StructureException('RSA key has unused bits');
  }
  final k = decodeDer(bits.bytes).sequenceOf('RSAPublicKey');
  if (k.length != 2) {
    throw const StructureException('RSAPublicKey must have 2 elements');
  }
  final n = k[0].expect(Asn1Tag.integer, 'modulus').asInteger;
  final e = k[1].expect(Asn1Tag.integer, 'publicExponent').asInteger;
  if (n.sign <= 0 || e.sign <= 0) {
    throw const StructureException('RSA key has a non-positive component');
  }
  return RsaPublicKey(n, e);
}

const _attrNames = {
  '2.5.4.3': 'CN',
  '2.5.4.4': 'SN',
  '2.5.4.5': 'serialNumber',
  '2.5.4.6': 'C',
  '2.5.4.7': 'L',
  '2.5.4.8': 'ST',
  '2.5.4.10': 'O',
  '2.5.4.11': 'OU',
  '2.5.4.12': 'title',
  '2.5.4.42': 'GN',
};

/// Renders a Name as an RFC 4514-style string (most specific RDN first).
/// Display only: never compare names through this string.
String nameToString(Asn1Element name) {
  final rdns = <String>[];
  for (final rdn in name.children!) {
    if (rdn.tag != Asn1Tag.set) {
      throw const StructureException('RDN must be a SET');
    }
    final parts = <String>[];
    for (final atv in rdn.children!) {
      final p = atv.sequenceOf('AttributeTypeAndValue');
      if (p.length != 2) {
        throw const StructureException('AttributeTypeAndValue needs 2 items');
      }
      final oid = p[0].asOid;
      parts.add('${_attrNames[oid] ?? oid}=${_stringValue(p[1])}');
    }
    rdns.add(parts.join('+'));
  }
  return rdns.reversed.join(', ');
}

String _stringValue(Asn1Element v) {
  final c = v.contentBytes;
  if (v.tag.isUniversal && !v.tag.constructed) {
    switch (v.tag.number) {
      case 12: // UTF8String
        return utf8.decode(c, allowMalformed: true);
      case 19: // PrintableString
      case 22: // IA5String
      case 26: // VisibleString
        return ascii.decode(c, allowInvalid: true);
      case 20: // TeletexString
      case 27: // GeneralString
        return latin1.decode(c);
      case 30: // BMPString
        if (c.length.isEven) {
          return String.fromCharCodes([
            for (var i = 0; i < c.length; i += 2) (c[i] << 8) | c[i + 1],
          ]);
        }
    }
  }
  return '#${c.map((b) => b.toRadixString(16).padLeft(2, '0')).join()}';
}
