import 'dart:typed_data';

import 'errors.dart';
import 'tag.dart';

/// A parsed identifier + length octets.
class Asn1Header {
  const Asn1Header(this.tag, this.headerLength, this.length);

  final Asn1Tag tag;

  /// Number of identifier + length octets.
  final int headerLength;

  /// Content length, or null for the indefinite form (BER only).
  final int? length;
}

/// Reads one header from [bytes] at [offset], never looking at or past [end].
///
/// This is the shared building block of the DER decoder and the future
/// bounded-BER decoder / incremental reader (ticket 11). Running out of bytes
/// throws [Asn1ErrorKind.truncated], which an incremental reader can treat as
/// "need more input". With the defaults it enforces DER; BER passes
/// `allowIndefinite: true, requireMinimal: false`.
Asn1Header readHeader(
  Uint8List bytes,
  int offset,
  int end, {
  bool allowIndefinite = false,
  bool requireMinimal = true,
}) {
  var p = offset;
  Never truncated() =>
      throw Asn1Exception(Asn1ErrorKind.truncated, p, 'unexpected end of data');
  if (p >= end) truncated();
  final b0 = bytes[p++];
  final cls = Asn1Class.values[b0 >> 6];
  final constructed = (b0 & 0x20) != 0;
  var number = b0 & 0x1f;
  if (number == 0x1f) {
    number = 0;
    var count = 0;
    while (true) {
      if (p >= end) truncated();
      final b = bytes[p++];
      if (count == 0 && b == 0x80 && requireMinimal) {
        throw Asn1Exception(
          Asn1ErrorKind.nonMinimalTag,
          p - 1,
          'leading zero in tag number',
        );
      }
      if (++count > 4) {
        throw Asn1Exception(Asn1ErrorKind.invalidTag, p - 1, 'tag too large');
      }
      number = (number << 7) | (b & 0x7f);
      if (b & 0x80 == 0) break;
    }
    if (number < 31 && requireMinimal) {
      throw Asn1Exception(
        Asn1ErrorKind.nonMinimalTag,
        offset,
        'high-form tag number $number fits low form',
      );
    }
  }
  final tag = Asn1Tag(cls, constructed, number);

  if (p >= end) truncated();
  final l0 = bytes[p++];
  int? length;
  if (l0 < 0x80) {
    length = l0;
  } else if (l0 == 0x80) {
    if (!allowIndefinite) {
      throw Asn1Exception(
        Asn1ErrorKind.indefiniteLength,
        p - 1,
        'indefinite length',
      );
    }
    if (!constructed) {
      throw Asn1Exception(
        Asn1ErrorKind.invalidLength,
        p - 1,
        'indefinite length on primitive',
      );
    }
  } else if (l0 == 0xff) {
    throw Asn1Exception(Asn1ErrorKind.invalidLength, p - 1, 'reserved length');
  } else {
    final n = l0 & 0x7f;
    if (end - p < n) {
      p = end;
      truncated();
    }
    if (bytes[p] == 0 && requireMinimal) {
      throw Asn1Exception(
        Asn1ErrorKind.nonMinimalLength,
        p,
        'leading zero in length',
      );
    }
    var v = 0;
    var i = 0;
    // Skip leading zeros (BER); more than 6 significant bytes cannot fit in
    // memory or in a JS-safe int.
    while (i < n && bytes[p + i] == 0) {
      i++;
    }
    if (n - i > 6) {
      throw Asn1Exception(Asn1ErrorKind.truncated, p, 'length exceeds input');
    }
    for (; i < n; i++) {
      v = v * 256 + bytes[p + i];
    }
    if (v < 0x80 && requireMinimal) {
      throw Asn1Exception(
        Asn1ErrorKind.nonMinimalLength,
        p - 1,
        'long form used for length $v',
      );
    }
    p += n;
    length = v;
  }
  return Asn1Header(tag, p - offset, length);
}
