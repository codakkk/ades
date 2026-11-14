import 'dart:typed_data';

import 'element.dart';
import 'errors.dart';
import 'header.dart';
import 'limits.dart';
import 'values.dart';

/// Decodes exactly one strict DER element covering all of [bytes].
///
/// With `enforceSetOrder: false` the X.690 11.6 SET OF ordering check is
/// skipped (everything else stays strict). CMS parsing uses this so that a
/// non-DER signed-attributes SET is reported as a signature failure by the
/// validator (ADR-0004) rather than as unparseable input.
///
/// Throws only [Asn1Exception]. Every returned element's
/// [Asn1Element.encoded] is a zero-copy view of [bytes], so callers must not
/// mutate [bytes] afterwards.
///
/// Extension point (ticket 11): a bounded-BER decoder reuses [readHeader]
/// (`allowIndefinite`, `requireMinimal: false`) and `validatePrimitive` /
/// `compareSetOfEncodings` from values.dart, routing each DER violation
/// through a "violation" hook that records a warning instead of throwing;
/// this decoder is that hook's "always throw" configuration.
Asn1Element decodeDer(
  Uint8List bytes, {
  Asn1Limits limits = Asn1Limits.defaults,
  bool enforceSetOrder = true,
}) {
  if (bytes.length > limits.maxTotalSize) {
    throw Asn1Exception(
      Asn1ErrorKind.sizeLimit,
      0,
      'input of ${bytes.length} bytes exceeds ${limits.maxTotalSize}',
    );
  }
  final (element, end) = decodeDerPrefix(
    bytes,
    0,
    limits: limits,
    enforceSetOrder: enforceSetOrder,
  );
  if (end != bytes.length) {
    throw Asn1Exception(
      Asn1ErrorKind.trailingData,
      end,
      '${bytes.length - end} trailing bytes',
    );
  }
  return element;
}

/// Decodes one DER element starting at [offset]; returns it and the offset
/// just past it. Trailing data is not an error here.
(Asn1Element, int) decodeDerPrefix(
  Uint8List bytes,
  int offset, {
  Asn1Limits limits = Asn1Limits.defaults,
  bool enforceSetOrder = true,
}) {
  final e = _decode(bytes, offset, bytes.length, 1, limits, enforceSetOrder);
  return (e, offset + e.encoded.length);
}

Asn1Element _decode(
  Uint8List bytes,
  int offset,
  int end,
  int depth,
  Asn1Limits limits,
  bool enforceSetOrder,
) {
  if (depth > limits.maxDepth) {
    throw Asn1Exception(
      Asn1ErrorKind.depthLimit,
      offset,
      'nesting deeper than ${limits.maxDepth}',
    );
  }
  final h = readHeader(bytes, offset, end);
  final tag = h.tag;
  final length = h.length!; // DER: never indefinite
  final contentStart = offset + h.headerLength;
  if (length > end - contentStart) {
    throw Asn1Exception(
      Asn1ErrorKind.truncated,
      contentStart,
      'content length $length exceeds available ${end - contentStart}',
    );
  }
  final contentEnd = contentStart + length;

  if (tag.isUniversal) {
    if (tag.number == 0) {
      throw Asn1Exception(
        Asn1ErrorKind.endOfContents,
        offset,
        'end-of-contents is not valid in DER',
      );
    }
    if (tag.constructed && universalMustBePrimitive(tag.number)) {
      throw Asn1Exception(
        Asn1ErrorKind.constructedNotAllowed,
        offset,
        'universal ${tag.number} must be primitive in DER',
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
  if (tag.constructed) {
    children = <Asn1Element>[];
    var p = contentStart;
    Asn1Element? prev;
    while (p < contentEnd) {
      final c = _decode(
        bytes,
        p,
        contentEnd,
        depth + 1,
        limits,
        enforceSetOrder,
      );
      if (enforceSetOrder &&
          prev != null &&
          tag.isUniversal &&
          tag.number == 17 &&
          compareSetOfEncodings(prev.encoded, c.encoded) > 0) {
        throw Asn1Exception(
          Asn1ErrorKind.unsortedSet,
          p,
          'SET OF elements not in DER order',
        );
      }
      children.add(c);
      prev = c;
      p += c.encoded.length;
    }
  } else {
    validatePrimitive(
      tag,
      Uint8List.sublistView(bytes, contentStart, contentEnd),
      contentStart,
    );
  }
  return Asn1Element.decoded(
    tag: tag,
    encoded: Uint8List.sublistView(bytes, offset, contentEnd),
    headerLength: h.headerLength,
    offset: offset,
    children: children,
  );
}
