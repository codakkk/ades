/// Why ASN.1 decoding (or typed access) failed.
///
/// Kinds are grouped so callers and the differential fuzzer can tell
/// "the bytes are not even BER" ([isStructural]) from "valid BER but not DER"
/// ([isDerStrictness]) and from configured-limit rejections ([isLimit]).
enum Asn1ErrorKind {
  // Structural: not decodable under any ASN.1 encoding rules.
  truncated,
  trailingData,
  invalidLength,
  invalidTag,
  invalidBoolean,
  invalidInteger,
  invalidNull,
  invalidBitString,
  invalidOid,

  // Valid BER, forbidden by DER.
  nonMinimalLength,
  nonMinimalTag,
  indefiniteLength,
  endOfContents,
  nonMinimalInteger,
  constructedNotAllowed,
  primitiveNotAllowed,
  unsortedSet,

  // Configured limits.
  depthLimit,
  sizeLimit,

  // Programmer misuse of a typed accessor.
  unexpectedType;

  bool get isLimit => this == depthLimit || this == sizeLimit;

  bool get isDerStrictness => const {
    nonMinimalLength,
    nonMinimalTag,
    indefiniteLength,
    endOfContents,
    nonMinimalInteger,
    constructedNotAllowed,
    primitiveNotAllowed,
    unsortedSet,
  }.contains(this);

  bool get isStructural => !isLimit && !isDerStrictness;
}

/// The only exception the codec throws for bad input.
class Asn1Exception implements Exception {
  Asn1Exception(this.kind, this.offset, this.message);

  final Asn1ErrorKind kind;

  /// Byte offset in the decoded input where the problem was detected.
  final int offset;
  final String message;

  @override
  String toString() => 'Asn1Exception(${kind.name} at $offset): $message';
}
