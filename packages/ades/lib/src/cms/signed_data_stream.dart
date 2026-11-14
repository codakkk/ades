import 'dart:typed_data';

import '../asn1/asn1.dart';
import '../asn1/structure.dart';
import '../crypto/algorithms.dart';
import '../crypto/crypto_provider.dart';
import '../crypto/stream_digester.dart';
import 'signed_data.dart';

const _chunkSize = 64 * 1024;

/// Incremental reader for a CMS ContentInfo holding SignedData (ADR-0004):
/// walks the outer BER skeleton header by header, hands the encapsulated
/// content to digesters piece by piece, and buffers only the small
/// elements around it.
Future<CmsSignedData> readCmsStream(
  Stream<List<int>> input, {
  required CryptoProvider crypto,
  required Asn1Limits limits,
}) async {
  final r = ByteStreamReader(input, maxBytes: limits.maxStreamLength);
  final dev = BerDeviations();
  final digesters = <DigestAlgorithm, StreamDigester>{};
  try {
    return await _read(r, dev, limits, crypto, digesters);
  } on Object {
    for (final d in digesters.values) {
      d.abort();
    }
    rethrow;
  } finally {
    await r.cancel();
  }
}

/// One open constructed element on the walk.
final class _Frame {
  _Frame(this.header);

  final StreamHeader header;
}

Future<CmsSignedData> _read(
  ByteStreamReader r,
  BerDeviations dev,
  Asn1Limits limits,
  CryptoProvider crypto,
  Map<DigestAlgorithm, StreamDigester> digesters,
) async {
  Future<StreamHeader> header() => readStreamHeader(r, dev);
  Future<Asn1Element> whole(StreamHeader h) =>
      readStreamElement(r, h, dev, limits);

  // The next child of [f], or null at its end (consuming end-of-contents).
  Future<StreamHeader?> next(_Frame f) async {
    final end = f.header.contentEnd;
    if (end == null) {
      final h = await header();
      return isEndOfContents(h.header) ? null : h;
    }
    if (r.position > end) {
      throw Asn1Exception(
        Asn1ErrorKind.invalidLength,
        r.position,
        'element overruns its parent',
      );
    }
    return r.position == end ? null : header();
  }

  // The parent bounds every definite child.
  Future<void> checkInside(_Frame f, StreamHeader child) async {
    final end = f.header.contentEnd;
    final cEnd = child.contentEnd;
    if (end != null && (cEnd == null || cEnd > end)) {
      throw Asn1Exception(
        Asn1ErrorKind.invalidLength,
        child.start,
        'element does not fit in its parent',
      );
    }
  }

  Future<_Frame> open(_Frame? parent, Asn1Tag tag, String what) async {
    final h = await header();
    if (!h.tag.constructed ||
        h.tag.tagClass != tag.tagClass ||
        h.tag.number != tag.number) {
      throw StructureException('$what must be $tag');
    }
    if (parent != null) await checkInside(parent, h);
    return _Frame(h);
  }

  Future<void> close(_Frame f, String what) async {
    if (await next(f) != null) {
      throw StructureException('$what has unexpected elements');
    }
  }

  final ci = await open(null, Asn1Tag.sequence, 'ContentInfo');
  final oidH =
      await next(ci) ?? (throw const StructureException('ContentInfo empty'));
  final oid = await whole(oidH);
  if (oid.asOid != CmsOids.signedData) {
    throw const StructureException('not a CMS SignedData ContentInfo');
  }
  final wrapH = await next(ci);
  if (wrapH == null) throw const StructureException('ContentInfo too short');
  if (!wrapH.tag.constructed ||
      !wrapH.tag.matches(Asn1Class.contextSpecific, 0)) {
    throw const StructureException('ContentInfo content must be [0]');
  }
  final wrap = _Frame(wrapH);
  await checkInside(ci, wrapH);
  final sd = await open(wrap, Asn1Tag.sequence, 'SignedData');

  Future<Asn1Element> child(_Frame f, String what) async {
    final h = await next(f);
    if (h == null) throw StructureException('$what missing');
    await checkInside(f, h);
    return whole(h);
  }

  (await child(sd, 'version')).expect(Asn1Tag.integer, 'SignedData version');
  final digestAlgs = await child(sd, 'digestAlgorithms');
  final algorithms = CmsSignedData.knownDigestAlgorithms(digestAlgs);

  final eci = await open(sd, Asn1Tag.sequence, 'EncapsulatedContentInfo');
  final contentType = (await child(eci, 'eContentType')).asOid;
  int? contentLength;
  final eContentH = await next(eci);
  if (eContentH != null) {
    await checkInside(eci, eContentH);
    if (!eContentH.tag.constructed ||
        !eContentH.tag.matches(Asn1Class.contextSpecific, 0)) {
      throw const StructureException('eContent must be [0] EXPLICIT');
    }
    final eContent = _Frame(eContentH);
    final octetsH = await next(eContent);
    if (octetsH == null) {
      throw const StructureException('eContent must be [0] EXPLICIT');
    }
    await checkInside(eContent, octetsH);
    for (final a in algorithms) {
      digesters[a] = StreamDigester(crypto, a);
    }
    contentLength = await _streamOctets(r, octetsH, dev, limits, 1, (chunk) {
      for (final d in digesters.values) {
        d.add(chunk);
      }
    });
    await close(eContent, 'eContent');
    await close(eci, 'EncapsulatedContentInfo');
  }

  final rest = <Asn1Element>[];
  while (true) {
    final h = await next(sd);
    if (h == null) break;
    await checkInside(sd, h);
    rest.add(await whole(h));
  }
  await close(wrap, 'ContentInfo');
  await close(ci, 'ContentInfo');
  if (!await r.atEnd()) {
    throw Asn1Exception(
      Asn1ErrorKind.trailingData,
      r.position,
      'trailing bytes after the ContentInfo',
    );
  }

  final digests = <DigestAlgorithm, Uint8List>{};
  for (final e in digesters.entries) {
    digests[e.key] = await e.value.finish();
  }
  return CmsSignedData.fromParts(
    contentType: contentType,
    content: null,
    contentLength: contentLength,
    contentDigests: digests,
    rest: rest,
    deviations: dev,
  );
}

/// Streams the octets of an OCTET STRING (primitive, or constructed with
/// definite or indefinite segments) to [sink]; returns their number.
Future<int> _streamOctets(
  ByteStreamReader r,
  StreamHeader h,
  BerDeviations dev,
  Asn1Limits limits,
  int depth,
  void Function(Uint8List) sink,
) async {
  if (depth > limits.maxDepth) {
    throw Asn1Exception(
      Asn1ErrorKind.depthLimit,
      h.start,
      'nesting deeper than ${limits.maxDepth}',
    );
  }
  if (!h.tag.matches(Asn1Class.universal, 4)) {
    throw const StructureException('eContent must be an OCTET STRING');
  }
  var total = 0;
  if (!h.tag.constructed) {
    var left = h.length!;
    while (left > 0) {
      final c = await r.readChunk(left < _chunkSize ? left : _chunkSize);
      if (c == null) {
        throw Asn1Exception(
          Asn1ErrorKind.truncated,
          r.position,
          'unexpected end of data',
        );
      }
      sink(c);
      left -= c.length;
      total += c.length;
    }
    return total;
  }
  dev.add(
    Asn1ErrorKind.constructedNotAllowed,
    h.start,
    'constructed OCTET STRING',
  );
  final end = h.contentEnd;
  while (true) {
    if (end != null && r.position >= end) {
      if (r.position > end) {
        throw Asn1Exception(
          Asn1ErrorKind.invalidLength,
          r.position,
          'segment overruns its parent',
        );
      }
      break;
    }
    final c = await readStreamHeader(r, dev);
    if (end == null && isEndOfContents(c.header)) break;
    final cEnd = c.contentEnd;
    if (end != null && (cEnd == null || cEnd > end)) {
      throw Asn1Exception(
        Asn1ErrorKind.invalidLength,
        c.start,
        'segment does not fit in its parent',
      );
    }
    total += await _streamOctets(r, c, dev, limits, depth + 1, sink);
  }
  return total;
}
