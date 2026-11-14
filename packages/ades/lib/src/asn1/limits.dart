/// Resource limits applied while decoding (ADR-0004: bounded decoding).
class Asn1Limits {
  const Asn1Limits({
    this.maxDepth = 64,
    this.maxTotalSize = 256 * 1024 * 1024,
    this.maxBufferedElement = 32 * 1024 * 1024,
    this.maxStreamLength = 1024 * 1024 * 1024 * 1024,
  });

  /// Maximum nesting, counting the root as depth 1.
  final int maxDepth;

  /// Maximum input size in bytes for in-memory decoding.
  final int maxTotalSize;

  /// Streaming: maximum size of any single element that is buffered in
  /// memory (everything except the encapsulated content, which is streamed).
  final int maxBufferedElement;

  /// Streaming: maximum number of bytes read from the input in total.
  final int maxStreamLength;

  static const defaults = Asn1Limits();
}
