// Minimal read helpers over pointycastle's ASN.1 parser, for key files only
// (PKCS#8, PKCS#1, SEC1, PKCS#12). The core's own strict DER codec is not
// public (spec seam 4); these inputs are trusted-ish local files, and every
// structural problem is reported as a malformed key store.
import 'dart:typed_data';

import 'package:pointycastle/asn1.dart';

import 'key_material.dart';

SoftKeyLoadException malformed(String m) =>
    SoftKeyLoadException(SoftKeyLoadFailure.malformed, m);

/// Parses exactly one ASN.1 object from [der].
ASN1Object parseAsn1(Uint8List der, String what) {
  try {
    final p = ASN1Parser(der);
    final o = p.nextObject();
    if (p.hasNext()) throw malformed('$what: trailing data');
    return o;
  } on SoftKeyLoadException {
    rethrow;
  } on Object catch (e) {
    throw malformed('$what is not valid ASN.1 ($e)');
  }
}

/// The children of a constructed object (SEQUENCE, SET or a context tag).
List<ASN1Object> asn1Children(ASN1Object o, String what) {
  try {
    if (o is ASN1Sequence) return o.elements ?? const [];
    if (o is ASN1Set) return o.elements ?? const [];
    final p = ASN1Parser(o.valueBytes);
    final out = <ASN1Object>[];
    while (p.hasNext()) {
      out.add(p.nextObject());
    }
    return out;
  } on Object catch (e) {
    throw malformed('$what is not valid ASN.1 ($e)');
  }
}

/// The elements of a SEQUENCE.
List<ASN1Object> asn1Sequence(ASN1Object o, String what) {
  if (o is! ASN1Sequence) throw malformed('$what must be a SEQUENCE');
  return asn1Children(o, what);
}

/// Whether [o] carries the context-specific constructed tag [number].
bool isContext(ASN1Object o, int number) => o.tag == (0xA0 | number);

String asn1Oid(ASN1Object o, String what) {
  if (o is! ASN1ObjectIdentifier) throw malformed('$what must be an OID');
  return o.objectIdentifierAsString ?? (throw malformed('$what: bad OID'));
}

BigInt asn1Integer(ASN1Object o, String what) {
  if (o is! ASN1Integer) throw malformed('$what must be an INTEGER');
  return o.integer ?? (throw malformed('$what: bad INTEGER'));
}

Uint8List asn1Octets(ASN1Object o, String what) {
  if (o is! ASN1OctetString) throw malformed('$what must be an OCTET STRING');
  return o.valueBytes ?? (throw malformed('$what: bad OCTET STRING'));
}
