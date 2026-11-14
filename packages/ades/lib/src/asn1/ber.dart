import 'dart:typed_data';

import 'element.dart';
import 'errors.dart';
import 'header.dart';
import 'limits.dart';
import 'tag.dart';
import 'values.dart';

/// A place where the input is valid BER but not DER (ADR-0004: a warning
/// outside the signed attributes).
class BerDeviation {
  const BerDeviation(this.kind, this.offset, this.message);

  /// One of the [Asn1ErrorKind.isDerStrictness] kinds.
  final Asn1ErrorKind kind;
  final int offset;
  final String message;

  @override
  String toString() => 'BerDeviation(${kind.name} at $offset): $message';
}

/// Collects [BerDeviation]s, keeping the first one of each kind.
class BerDeviations {
  final Map<Asn1ErrorKind, BerDeviation> _byKind = {};

  void add(Asn1ErrorKind kind, int offset, String message) =>
      _byKind.putIfAbsent(kind, () => BerDeviation(kind, offset, message));

  List<BerDeviation> get items => List.unmodifiable(_byKind.values);

  bool get isEmpty => _byKind.isEmpty;
}

/// Reads one header, tolerating the BER forms DER forbids (indefinite
/// length, non-minimal length or tag) and recording them in [deviations].
Asn1Header readBerHeader(
  Uint8List bytes,
  int offset,
  int end,
  BerDeviations? deviations, {
  int baseOffset = 0,
}) {
  try {
    return readHeader(bytes, offset, end);
  } on Asn1Exception catch (e) {
    if (e.kind != Asn1ErrorKind.nonMinimalLength &&
        e.kind != Asn1ErrorKind.nonMinimalTag &&
        e.kind != Asn1ErrorKind.indefiniteLength) {
      rethrow;
    }
    deviations?.add(e.kind, baseOffset + e.offset, e.message);
    return readHeader(
      bytes,
      offset,
      end,
      allowIndefinite: true,
      requireMinimal: false,
    );
  }
}

/// Whether [h] is the end-of-contents marker `00 00`.
bool isEndOfContents(Asn1Header h) =>
    h.tag.isUniversal &&
    !h.tag.constructed &&
    h.tag.number == 0 &&
    h.length == 0;

/// Decodes exactly one BER element covering all of [bytes] (bounded BER,
/// ADR-0004): indefinite lengths and the other BER forms are accepted
/// within [limits], and each place that is not DER is recorded in
/// [deviations] instead of failing.
///
/// Still throws [Asn1Exception] for input that is not BER at all (truncated,
/// bad content) and for limit violations. Every element's
/// [Asn1Element.encoded] is a zero-copy view of the original bytes
/// (including end-of-contents octets for indefinite lengths), so hashing
/// never re-encodes.
///
/// [baseOffset] is added to the offsets recorded in [deviations] (used when
/// [bytes] is a piece of a larger stream).
Asn1Element decodeBer(
  Uint8List bytes, {
  Asn1Limits limits = Asn1Limits.defaults,
  BerDeviations? deviations,
  int baseOffset = 0,
}) {
  if (bytes.length > limits.maxTotalSize) {
    throw Asn1Exception(
      Asn1ErrorKind.sizeLimit,
      0,
      'input of ${bytes.length} bytes exceeds ${limits.maxTotalSize}',
    );
  }
  final (e, end) = _decode(
    bytes,
    0,
    bytes.length,
    1,
    limits,
    deviations,
    baseOffset,
  );
  if (end != bytes.length) {
    throw Asn1Exception(
      Asn1ErrorKind.trailingData,
      end,
      '${bytes.length - end} trailing bytes',
    );
  }
  return e;
}

(Asn1Element, int) _decode(
  Uint8List bytes,
  int offset,
  int end,
  int depth,
  Asn1Limits limits,
  BerDeviations? dev,
  int base,
) {
  if (depth > limits.maxDepth) {
    throw Asn1Exception(
      Asn1ErrorKind.depthLimit,
      offset,
      'nesting deeper than ${limits.maxDepth}',
    );
  }
  final h = readBerHeader(bytes, offset, end, dev, baseOffset: base);
  final tag = h.tag;
  final contentStart = offset + h.headerLength;
  final indefinite = h.length == null;

  if (!indefinite && h.length! > end - contentStart) {
    throw Asn1Exception(
      Asn1ErrorKind.truncated,
      contentStart,
      'content length ${h.length} exceeds available ${end - contentStart}',
    );
  }
  if (tag.isUniversal) {
    if (tag.number == 0) {
      throw Asn1Exception(
        Asn1ErrorKind.endOfContents,
        offset,
        'unexpected end-of-contents',
      );
    }
    if (tag.constructed && universalMustBePrimitive(tag.number)) {
      // BER allows constructed (segmented) strings; only OCTET STRING is
      // supported, as CMS needs nothing else.
      if (tag.number != 4) {
        throw Asn1Exception(
          Asn1ErrorKind.constructedNotAllowed,
          offset,
          'constructed universal ${tag.number} is not supported',
        );
      }
      dev?.add(
        Asn1ErrorKind.constructedNotAllowed,
        base + offset,
        'constructed OCTET STRING',
      );
    }
    if (!tag.constructed && (tag.number == 16 || tag.number == 17)) {
      throw Asn1Exception(
        Asn1ErrorKind.primitiveNotAllowed,
        offset,
        'SEQUENCE/SET must be constructed',
      );
    }
  }

  List<Asn1Element>? children;
  int contentEnd;
  if (tag.constructed) {
    children = <Asn1Element>[];
    var p = contentStart;
    final limit = indefinite ? end : contentStart + h.length!;
    Asn1Element? prev;
    while (true) {
      if (indefinite) {
        // Look for the end-of-contents octets before decoding a child.
        if (limit - p >= 2 && bytes[p] == 0 && bytes[p + 1] == 0) {
          p += 2;
          break;
        }
        if (p >= limit) {
          throw Asn1Exception(
            Asn1ErrorKind.truncated,
            p,
            'missing end-of-contents',
          );
        }
      } else if (p >= limit) {
        break;
      }
      final (c, cEnd) = _decode(bytes, p, limit, depth + 1, limits, dev, base);
      if (prev != null &&
          tag.isUniversal &&
          tag.number == 17 &&
          compareSetOfEncodings(prev.encoded, c.encoded) > 0) {
        dev?.add(
          Asn1ErrorKind.unsortedSet,
          base + p,
          'SET OF elements not in DER order',
        );
      }
      children.add(c);
      prev = c;
      p = cEnd;
    }
    contentEnd = p;
  } else {
    contentEnd = contentStart + h.length!;
    try {
      validatePrimitive(
        tag,
        Uint8List.sublistView(bytes, contentStart, contentEnd),
        contentStart,
      );
    } on Asn1Exception catch (e) {
      if (!e.kind.isDerStrictness) rethrow;
      dev?.add(e.kind, base + e.offset, e.message);
    }
  }
  return (
    Asn1Element.decoded(
      tag: tag,
      encoded: Uint8List.sublistView(bytes, offset, contentEnd),
      headerLength: h.headerLength,
      offset: offset,
      children: children,
    ),
    contentEnd,
  );
}

/// The octets of an OCTET STRING element, primitive or constructed
/// (segmented, BER). Throws [Asn1Exception] when [e] is not an OCTET STRING.
Uint8List octetStringBytes(Asn1Element e) {
  if (!e.tag.matches(Asn1Class.universal, 4)) {
    throw Asn1Exception(
      Asn1ErrorKind.unexpectedType,
      e.offset,
      'expected OCTET STRING, found ${e.tag}',
    );
  }
  if (!e.tag.constructed) return e.contentBytes;
  final out = BytesBuilder(copy: false);
  void walk(Asn1Element x) {
    if (!x.tag.matches(Asn1Class.universal, 4)) {
      throw Asn1Exception(
        Asn1ErrorKind.unexpectedType,
        x.offset,
        'OCTET STRING segment expected, found ${x.tag}',
      );
    }
    if (x.tag.constructed) {
      x.children!.forEach(walk);
    } else {
      out.add(x.contentBytes);
    }
  }

  walk(e);
  return out.takeBytes();
}
