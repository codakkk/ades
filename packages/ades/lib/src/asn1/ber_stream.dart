import 'dart:async';
import 'dart:typed_data';

import 'ber.dart';
import 'element.dart';
import 'errors.dart';
import 'header.dart';
import 'limits.dart';
import 'tag.dart';

/// A pull reader over a byte stream: the incremental half of the BER reader
/// (ADR-0004). It never holds more than one source chunk, so a caller that
/// streams the content in pieces stays in bounded memory.
final class ByteStreamReader {
  ByteStreamReader(Stream<List<int>> source, {required this.maxBytes})
    : _it = StreamIterator(source);

  final StreamIterator<List<int>> _it;

  /// Upper bound on the bytes consumed in total.
  final int maxBytes;

  Uint8List _chunk = Uint8List(0);
  int _p = 0;
  bool _eof = false;

  /// Bytes consumed so far (the absolute offset of the next byte).
  int position = 0;

  Future<bool> _fill() async {
    while (_p >= _chunk.length) {
      if (_eof || !await _it.moveNext()) {
        _eof = true;
        return false;
      }
      final c = _it.current;
      _chunk = c is Uint8List ? c : Uint8List.fromList(c);
      _p = 0;
    }
    return true;
  }

  void _consumed(int n) {
    _p += n;
    position += n;
    if (position > maxBytes) {
      throw Asn1Exception(
        Asn1ErrorKind.sizeLimit,
        position,
        'input exceeds $maxBytes bytes',
      );
    }
  }

  /// Exactly [n] bytes, copied. Throws [Asn1ErrorKind.truncated] at the end
  /// of the input.
  Future<Uint8List> readExact(int n) async {
    final out = Uint8List(n);
    var o = 0;
    while (o < n) {
      if (!await _fill()) {
        throw Asn1Exception(
          Asn1ErrorKind.truncated,
          position,
          'unexpected end of data',
        );
      }
      final take = _min(n - o, _chunk.length - _p);
      out.setRange(o, o + take, _chunk, _p);
      o += take;
      _consumed(take);
    }
    return out;
  }

  /// Up to [max] next bytes as a view of the current source chunk (valid
  /// until the next read), or null at the end of the input.
  Future<Uint8List?> readChunk(int max) async {
    if (!await _fill()) return null;
    final take = _min(max, _chunk.length - _p);
    final v = Uint8List.sublistView(_chunk, _p, _p + take);
    _consumed(take);
    return v;
  }

  /// Whether the whole input has been consumed.
  Future<bool> atEnd() async => !await _fill();

  Future<void> cancel() async {
    try {
      await _it.cancel();
    } on Object {
      // The source already failed; nothing left to release.
    }
  }
}

int _min(int a, int b) => a < b ? a : b;

/// A header read from a stream.
final class StreamHeader {
  StreamHeader(this.header, this.raw, this.start);

  final Asn1Header header;

  /// The identifier and length octets as read.
  final Uint8List raw;

  /// Absolute offset of the first header octet.
  final int start;

  Asn1Tag get tag => header.tag;
  int? get length => header.length;
  bool get isIndefinite => header.length == null;

  /// Absolute offset just past the content, or null if indefinite.
  int? get contentEnd =>
      header.length == null ? null : start + raw.length + header.length!;
}

/// Reads one BER header from [r], recording deviations.
Future<StreamHeader> readStreamHeader(
  ByteStreamReader r,
  BerDeviations deviations,
) async {
  final start = r.position;
  final raw = <int>[];
  Future<int> next() async {
    final b = await r.readExact(1);
    raw.add(b[0]);
    return b[0];
  }

  final b0 = await next();
  if (b0 & 0x1f == 0x1f) {
    var count = 0;
    while (true) {
      final b = await next();
      if (b & 0x80 == 0) break;
      if (++count > 4) break; // readBerHeader reports the invalid tag
    }
  }
  final l0 = await next();
  if (l0 > 0x80 && l0 != 0xff) {
    raw.addAll(await r.readExact(l0 & 0x7f));
  }
  final bytes = Uint8List.fromList(raw);
  final h = readBerHeader(
    bytes,
    0,
    bytes.length,
    deviations,
    baseOffset: start,
  );
  return StreamHeader(h, bytes, start);
}

/// Copies the rest of the element whose header is [h] (content, and for the
/// indefinite form every nested element and the end-of-contents octets) into
/// a buffer and decodes it. The element must fit in
/// [Asn1Limits.maxBufferedElement].
Future<Asn1Element> readStreamElement(
  ByteStreamReader r,
  StreamHeader h,
  BerDeviations deviations,
  Asn1Limits limits,
) async {
  final out = BytesBuilder(copy: false)..add(h.raw);
  Never tooBig(int at) => throw Asn1Exception(
    Asn1ErrorKind.sizeLimit,
    at,
    'element larger than ${limits.maxBufferedElement} bytes',
  );
  Future<void> copy(StreamHeader x, int depth) async {
    if (depth > limits.maxDepth) {
      throw Asn1Exception(
        Asn1ErrorKind.depthLimit,
        x.start,
        'nesting deeper than ${limits.maxDepth}',
      );
    }
    if (!x.isIndefinite) {
      final len = x.length!;
      if (out.length + len > limits.maxBufferedElement) tooBig(x.start);
      out.add(await r.readExact(len));
      return;
    }
    while (true) {
      final c = await readStreamHeader(r, deviations);
      out.add(c.raw);
      if (isEndOfContents(c.header)) return;
      if (out.length > limits.maxBufferedElement) tooBig(c.start);
      await copy(c, depth + 1);
    }
  }

  await copy(h, 1);
  return decodeBer(
    out.takeBytes(),
    limits: limits,
    deviations: deviations,
    baseOffset: h.start,
  );
}
