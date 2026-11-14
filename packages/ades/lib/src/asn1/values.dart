import 'dart:typed_data';

import 'errors.dart';
import 'tag.dart';

/// Primitive content rules shared by decoding (validation) and typed access.
/// All of them are DER rules; a lenient (BER) decoder will call the same
/// checks and downgrade the thrown [Asn1Exception] to a recorded warning.

Never _fail(Asn1ErrorKind k, int offset, String m) =>
    throw Asn1Exception(k, offset, m);

bool parseBoolean(Uint8List c, int offset) {
  if (c.length != 1) {
    _fail(Asn1ErrorKind.invalidBoolean, offset, 'BOOLEAN length ${c.length}');
  }
  if (c[0] == 0) return false;
  if (c[0] == 0xff) return true;
  _fail(Asn1ErrorKind.invalidBoolean, offset, 'BOOLEAN must be 0x00 or 0xFF');
}

void checkInteger(Uint8List c, int offset) {
  if (c.isEmpty) {
    _fail(Asn1ErrorKind.invalidInteger, offset, 'empty INTEGER');
  }
  if (c.length > 1 &&
      ((c[0] == 0 && c[1] & 0x80 == 0) || (c[0] == 0xff && c[1] & 0x80 != 0))) {
    _fail(Asn1ErrorKind.nonMinimalInteger, offset, 'non-minimal INTEGER');
  }
}

BigInt parseInteger(Uint8List c, int offset) {
  checkInteger(c, offset);
  var v = BigInt.zero;
  for (final b in c) {
    v = (v << 8) | BigInt.from(b);
  }
  if (c[0] & 0x80 != 0) v -= BigInt.one << (8 * c.length);
  return v;
}

Uint8List encodeInteger(BigInt v) {
  final n = v.bitLength ~/ 8 + 1;
  var u = v.isNegative ? v + (BigInt.one << (8 * n)) : v;
  final out = Uint8List(n);
  final mask = BigInt.from(0xff);
  for (var i = n - 1; i >= 0; i--) {
    out[i] = (u & mask).toInt();
    u >>= 8;
  }
  return out;
}

void checkNull(Uint8List c, int offset) {
  if (c.isNotEmpty) _fail(Asn1ErrorKind.invalidNull, offset, 'NULL not empty');
}

void checkBitString(Uint8List c, int offset) {
  if (c.isEmpty) {
    _fail(Asn1ErrorKind.invalidBitString, offset, 'empty BIT STRING');
  }
  final unused = c[0];
  if (unused > 7) {
    _fail(Asn1ErrorKind.invalidBitString, offset, 'unused bits $unused');
  }
  if (unused != 0) {
    if (c.length == 1) {
      _fail(Asn1ErrorKind.invalidBitString, offset, 'unused bits but no data');
    }
    if (c.last & ((1 << unused) - 1) != 0) {
      _fail(Asn1ErrorKind.invalidBitString, offset, 'non-zero padding bits');
    }
  }
}

/// Decoded BIT STRING content.
class Asn1BitString {
  Asn1BitString(this.bytes, this.unusedBits);
  final Uint8List bytes;
  final int unusedBits;
}

List<BigInt> parseOidArcs(Uint8List c, int offset) {
  if (c.isEmpty) _fail(Asn1ErrorKind.invalidOid, offset, 'empty OID');
  final subs = <BigInt>[];
  var cur = BigInt.zero;
  var start = true;
  for (var i = 0; i < c.length; i++) {
    final b = c[i];
    if (start && b == 0x80) {
      _fail(Asn1ErrorKind.invalidOid, offset + i, 'non-minimal subidentifier');
    }
    start = false;
    cur = (cur << 7) | BigInt.from(b & 0x7f);
    if (b & 0x80 == 0) {
      subs.add(cur);
      cur = BigInt.zero;
      start = true;
    }
  }
  if (!start) {
    _fail(Asn1ErrorKind.invalidOid, offset, 'truncated subidentifier');
  }
  final first = subs[0];
  final BigInt a0;
  final BigInt a1;
  if (first < BigInt.from(40)) {
    a0 = BigInt.zero;
    a1 = first;
  } else if (first < BigInt.from(80)) {
    a0 = BigInt.one;
    a1 = first - BigInt.from(40);
  } else {
    a0 = BigInt.two;
    a1 = first - BigInt.from(80);
  }
  return [a0, a1, ...subs.skip(1)];
}

String parseOid(Uint8List c, int offset) => parseOidArcs(c, offset).join('.');

Uint8List encodeOid(String dotted) {
  final arcs = dotted.split('.').map(BigInt.tryParse).toList();
  if (arcs.length < 2 || arcs.any((a) => a == null || a.isNegative)) {
    throw ArgumentError.value(dotted, 'dotted', 'invalid OID');
  }
  final a0 = arcs[0]!;
  final a1 = arcs[1]!;
  if (a0 > BigInt.two || (a0 < BigInt.two && a1 >= BigInt.from(40))) {
    throw ArgumentError.value(dotted, 'dotted', 'invalid first arcs');
  }
  final subs = [a0 * BigInt.from(40) + a1, ...arcs.skip(2).cast<BigInt>()];
  final out = <int>[];
  for (final s in subs) {
    final chunk = <int>[];
    var v = s;
    chunk.add((v & BigInt.from(0x7f)).toInt());
    v >>= 7;
    while (v > BigInt.zero) {
      chunk.add((v & BigInt.from(0x7f)).toInt() | 0x80);
      v >>= 7;
    }
    out.addAll(chunk.reversed);
  }
  return Uint8List.fromList(out);
}

const _primitiveOnly = {1, 2, 3, 4, 5, 6, 9, 10, 12, 13};

/// Universal types whose DER form must be primitive.
bool universalMustBePrimitive(int n) =>
    _primitiveOnly.contains(n) || (n >= 18 && n <= 30);

/// DER validation of a primitive universal element's content.
void validatePrimitive(Asn1Tag tag, Uint8List content, int offset) {
  if (!tag.isUniversal) return;
  switch (tag.number) {
    case 1:
      parseBoolean(content, offset);
    case 2 || 10:
      checkInteger(content, offset);
    case 3:
      checkBitString(content, offset);
    case 5:
      checkNull(content, offset);
    case 6:
      parseOidArcs(content, offset);
  }
}

/// X.690 11.6 ordering: compare as octet strings, shorter padded with zeros.
int compareSetOfEncodings(Uint8List a, Uint8List b) {
  final n = a.length < b.length ? a.length : b.length;
  for (var i = 0; i < n; i++) {
    if (a[i] != b[i]) return a[i] < b[i] ? -1 : 1;
  }
  final longer = a.length > b.length ? a : b;
  for (var i = n; i < longer.length; i++) {
    if (longer[i] != 0) return a.length > b.length ? 1 : -1;
  }
  return 0;
}
