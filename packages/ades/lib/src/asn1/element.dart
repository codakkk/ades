import 'dart:convert';
import 'dart:typed_data';

import 'errors.dart';
import 'tag.dart';
import 'values.dart';

/// One ASN.1 element, either decoded from bytes or built for encoding.
///
/// [encoded] is always the element's complete encoding (header + content).
/// For a decoded element it is a zero-copy view of the original input, so
/// hashing it hashes exactly what was signed, never a re-encoding (ADR-0004).
/// For a built element it is the DER encoding.
class Asn1Element {
  Asn1Element._(
    this.tag,
    this.encoded,
    this.headerLength,
    this.children, {
    this.offset = 0,
  });

  /// Internal: used by decoders (DER now, bounded BER later).
  Asn1Element.decoded({
    required Asn1Tag tag,
    required Uint8List encoded,
    required int headerLength,
    required int offset,
    List<Asn1Element>? children,
  }) : this._(
         tag,
         encoded,
         headerLength,
         children == null ? null : List.unmodifiable(children),
         offset: offset,
       );

  final Asn1Tag tag;

  /// Complete original (decoded) or DER (built) encoding. Do not mutate.
  final Uint8List encoded;

  /// Identifier + length octets.
  final int headerLength;

  /// Children of a constructed element, null for a primitive one.
  final List<Asn1Element>? children;

  /// Offset of [encoded] within the decoded input (0 for built elements).
  final int offset;

  /// Content octets (a view into [encoded]).
  Uint8List get contentBytes => Uint8List.sublistView(encoded, headerLength);

  /// DER encoding. For a decoded (DER-valid) element this equals [encoded].
  Uint8List encode() => encoded;

  // ---- builders ----

  factory Asn1Element.primitive(Asn1Tag tag, Uint8List content) {
    assert(!tag.constructed);
    return Asn1Element._(
      tag,
      _wrap(tag, content),
      _headerLen(tag, content.length),
      null,
    );
  }

  factory Asn1Element.constructed(Asn1Tag tag, List<Asn1Element> children) {
    final total = children.fold<int>(0, (s, c) => s + c.encoded.length);
    final content = Uint8List(total);
    var p = 0;
    for (final c in children) {
      content.setAll(p, c.encoded);
      p += c.encoded.length;
    }
    final t = Asn1Tag(tag.tagClass, true, tag.number);
    return Asn1Element._(
      t,
      _wrap(t, content),
      _headerLen(t, total),
      List.unmodifiable(children),
    );
  }

  factory Asn1Element.sequence(List<Asn1Element> children) =>
      Asn1Element.constructed(Asn1Tag.sequence, children);

  /// SET OF: children are sorted into DER order.
  factory Asn1Element.setOf(List<Asn1Element> children) {
    final sorted = [...children]
      ..sort((a, b) => compareSetOfEncodings(a.encoded, b.encoded));
    return Asn1Element.constructed(Asn1Tag.set, sorted);
  }

  factory Asn1Element.integer(BigInt v) =>
      Asn1Element.primitive(Asn1Tag.integer, encodeInteger(v));

  factory Asn1Element.boolean(bool v) => Asn1Element.primitive(
    Asn1Tag.boolean,
    Uint8List.fromList([v ? 0xff : 0]),
  );

  factory Asn1Element.nullValue() =>
      Asn1Element.primitive(Asn1Tag.nullTag, Uint8List(0));

  factory Asn1Element.oid(String dotted) =>
      Asn1Element.primitive(Asn1Tag.oid, encodeOid(dotted));

  factory Asn1Element.octetString(Uint8List bytes) =>
      Asn1Element.primitive(Asn1Tag.octetString, bytes);

  factory Asn1Element.bitString(Uint8List bytes, {int unusedBits = 0}) =>
      Asn1Element.primitive(
        Asn1Tag.bitString,
        Uint8List.fromList([unusedBits, ...bytes]),
      );

  factory Asn1Element.utf8String(String s) => Asn1Element.primitive(
    Asn1Tag.utf8String,
    Uint8List.fromList(utf8.encode(s)),
  );

  // ---- typed access (throws Asn1Exception on wrong type / bad content) ----

  void _expect(Asn1Tag t) {
    if (tag != t) {
      throw Asn1Exception(
        Asn1ErrorKind.unexpectedType,
        offset,
        'expected $t, found $tag',
      );
    }
  }

  bool get asBoolean {
    _expect(Asn1Tag.boolean);
    return parseBoolean(contentBytes, offset);
  }

  BigInt get asInteger {
    if (tag != Asn1Tag.integer) _expect(Asn1Tag.enumerated);
    return parseInteger(contentBytes, offset);
  }

  String get asOid {
    _expect(Asn1Tag.oid);
    return parseOid(contentBytes, offset);
  }

  Asn1BitString get asBitString {
    _expect(Asn1Tag.bitString);
    final c = contentBytes;
    checkBitString(c, offset);
    return Asn1BitString(Uint8List.sublistView(c, 1), c[0]);
  }

  Uint8List get asOctetString {
    _expect(Asn1Tag.octetString);
    return contentBytes;
  }

  String get asUtf8String {
    _expect(Asn1Tag.utf8String);
    return utf8.decode(contentBytes);
  }

  @override
  String toString() => 'Asn1Element($tag, ${encoded.length} bytes)';
}

int _lengthOctets(int len) {
  if (len < 0x80) return 1;
  var n = 0;
  for (var v = len; v > 0; v = v ~/ 256) {
    n++;
  }
  return 1 + n;
}

int _tagOctets(Asn1Tag t) {
  if (t.number < 31) return 1;
  var n = 1;
  for (var v = t.number; v > 0; v >>= 7) {
    n++;
  }
  return n;
}

/// Length in bytes of the DER header (identifier + length octets) of an
/// element with tag [t] and content length [len].
int derHeaderLength(Asn1Tag t, int len) => _headerLen(t, len);

/// DER header bytes for an element with tag [t] and content length [len];
/// lets a writer emit content it does not hold in memory.
Uint8List derHeader(Asn1Tag t, int len) {
  final w = _wrap(t, Uint8List(0));
  // _wrap wrote a zero length; rebuild with the real one.
  final tagLen = _tagOctets(t);
  final out = Uint8List(_headerLen(t, len));
  out.setRange(0, tagLen, w);
  if (len < 0x80) {
    out[tagLen] = len;
  } else {
    final n = _lengthOctets(len) - 1;
    out[tagLen] = 0x80 | n;
    for (var i = 0; i < n; i++) {
      out[tagLen + 1 + i] = (len ~/ _pow256(n - 1 - i)) & 0xff;
    }
  }
  return out;
}

int _headerLen(Asn1Tag t, int len) => _tagOctets(t) + _lengthOctets(len);

Uint8List _wrap(Asn1Tag t, Uint8List content) {
  final hl = _headerLen(t, content.length);
  final out = Uint8List(hl + content.length);
  var p = 0;
  final first = (t.tagClass.index << 6) | (t.constructed ? 0x20 : 0);
  if (t.number < 31) {
    out[p++] = first | t.number;
  } else {
    out[p++] = first | 0x1f;
    final n = _tagOctets(t) - 1;
    for (var i = 0; i < n; i++) {
      final shift = 7 * (n - 1 - i);
      out[p++] = ((t.number >> shift) & 0x7f) | (i < n - 1 ? 0x80 : 0);
    }
  }
  final len = content.length;
  if (len < 0x80) {
    out[p++] = len;
  } else {
    final n = _lengthOctets(len) - 1;
    out[p++] = 0x80 | n;
    for (var i = 0; i < n; i++) {
      out[p++] = (len ~/ _pow256(n - 1 - i)) & 0xff;
    }
  }
  out.setAll(p, content);
  return out;
}

int _pow256(int n) {
  var r = 1;
  for (var i = 0; i < n; i++) {
    r *= 256;
  }
  return r;
}
