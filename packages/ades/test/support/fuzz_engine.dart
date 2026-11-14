// Mutation fuzzer core for seam 1 (public validation entry points). No dart:io,
// so the replay test and the nightly tool share it. See tool/validation_fuzz.dart.
import 'dart:async';
import 'dart:math';
import 'dart:typed_data';

import 'package:ades/ades.dart';

/// Outcome of running one input through every public validation entry point.
class FuzzFinding {
  FuzzFinding(this.kind, this.message);

  /// `crash` (an exception escaped), `slow` (over the time budget), or
  /// `memory` (over the memory budget; set by the tool).
  final String kind;
  final String message;
  @override
  String toString() => '$kind: $message';
}

/// Runs [input] through `validate`, `validate(detachedContent:)` and
/// `validateStream` (chunked by [chunkSize]). Returns a finding or null.
///
/// Invariant: validation never throws, whatever the bytes, and stays inside
/// [timeBudget].
Future<FuzzFinding?> checkInput(
  Validator validator,
  Uint8List input, {
  Uint8List? detachedContent,
  int chunkSize = 7,
  Duration timeBudget = const Duration(seconds: 5),
  DateTime? validationTime,
}) async {
  final time = validationTime ?? DateTime.utc(2026, 11, 10);
  final sw = Stopwatch()..start();
  String? mode;
  try {
    mode = 'validate';
    await validator.validate(input, validationTime: time);
    if (detachedContent != null) {
      mode = 'validate(detachedContent)';
      await validator.validate(
        input,
        detachedContent: detachedContent,
        validationTime: time,
      );
    }
    mode = 'validateStream(chunk=$chunkSize)';
    await validator.validateStream(
      _chunks(input, chunkSize),
      validationTime: time,
    );
  } catch (e, st) {
    return FuzzFinding('crash', '$mode threw ${e.runtimeType}: $e\n$st');
  }
  sw.stop();
  if (sw.elapsed > timeBudget) {
    return FuzzFinding(
      'slow',
      '${sw.elapsedMilliseconds} ms > ${timeBudget.inMilliseconds} ms',
    );
  }
  return null;
}

Stream<List<int>> _chunks(Uint8List b, int size) async* {
  for (var i = 0; i < b.length; i += size) {
    yield Uint8List.sublistView(b, i, min(i + size, b.length));
  }
}

/// Mutates [seed] (copying it), optionally splicing from [others].
Uint8List mutate(Random r, Uint8List seed, List<Uint8List> others) {
  var b = Uint8List.fromList(seed);
  final rounds = 1 + r.nextInt(4);
  for (var i = 0; i < rounds; i++) {
    b = _mutateOnce(r, b, others);
  }
  return b;
}

const _interesting = [
  0x00, 0x01, 0x7f, 0x80, 0x81, 0x82, 0x84, 0xff, //
  0x30, 0x31, 0xa0, 0x04, 0x02, 0x06, 0x05,
];

/// Offsets of tag/length bytes of well-formed-looking TLVs (best effort).
List<int> _headerOffsets(Uint8List b) {
  final out = <int>[];
  void walk(int start, int end, int depth) {
    var p = start;
    while (p + 2 <= end && depth < 20) {
      out.add(p);
      out.add(p + 1);
      final l = b[p + 1];
      var hl = 2;
      int len;
      if (l < 0x80) {
        len = l;
      } else {
        final n = l & 0x7f;
        if (n == 0 || n > 3 || p + 2 + n > end) return;
        len = 0;
        for (var i = 0; i < n; i++) {
          len = (len << 8) | b[p + 2 + i];
        }
        hl = 2 + n;
      }
      final cEnd = p + hl + len;
      if (cEnd > end) return;
      if (b[p] & 0x20 != 0) walk(p + hl, cEnd, depth + 1);
      p = cEnd;
    }
  }

  walk(0, b.length, 0);
  return out;
}

Uint8List _mutateOnce(Random r, Uint8List b, List<Uint8List> others) {
  if (b.isEmpty) return Uint8List.fromList([r.nextInt(256)]);
  int pos() => r.nextInt(b.length);
  switch (r.nextInt(12)) {
    case 0: // bit flip
      b[pos()] ^= 1 << r.nextInt(8);
      return b;
    case 1: // random byte
      b[pos()] = r.nextInt(256);
      return b;
    case 2: // interesting byte at a header position
      final h = _headerOffsets(b);
      b[h.isEmpty ? pos() : h[r.nextInt(h.length)]] =
          _interesting[r.nextInt(_interesting.length)];
      return b;
    case 3: // truncate
      return Uint8List.sublistView(b, 0, r.nextInt(b.length));
    case 4: // delete a range
      final s = pos();
      final e = min(b.length, s + 1 + r.nextInt(16));
      return Uint8List.fromList([...b.sublist(0, s), ...b.sublist(e)]);
    case 5: // insert random bytes
      final s = pos();
      return Uint8List.fromList([
        ...b.sublist(0, s),
        ...List.generate(1 + r.nextInt(8), (_) => r.nextInt(256)),
        ...b.sublist(s),
      ]);
    case 6: // duplicate a range
      final s = pos();
      final e = min(b.length, s + 1 + r.nextInt(64));
      return Uint8List.fromList([
        ...b.sublist(0, e),
        ...b.sublist(s, e),
        ...b.sublist(e),
      ]);
    case 7: // splice from another seed
      final o = others[r.nextInt(others.length)];
      if (o.isEmpty) return b;
      final s = pos();
      final os = r.nextInt(o.length);
      final oe = min(o.length, os + 1 + r.nextInt(128));
      return Uint8List.fromList([
        ...b.sublist(0, s),
        ...o.sublist(os, oe),
        ...b.sublist(min(b.length, s + (oe - os))),
      ]);
    case 8: // extreme or indefinite length at a header
      final h = _headerOffsets(b);
      if (h.isEmpty) return b;
      final p = h[r.nextInt(h.length)];
      final lenForm = const [
        [0x84, 0xff, 0xff, 0xff, 0xff],
        [0x88, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        [0x82, 0xff, 0xff],
        [0x80], // indefinite
      ][r.nextInt(4)];
      return Uint8List.fromList([
        ...b.sublist(0, min(b.length, p + 1)),
        ...lenForm,
        ...b.sublist(min(b.length, p + 2)),
      ]);
    case 9: // wrap the rest in extra indefinite constructed headers
      final s = pos();
      final deep = r.nextInt(3) == 0 ? 80 : 1 + r.nextInt(3);
      final pre = <int>[];
      for (var i = 0; i < deep; i++) {
        pre.addAll(r.nextBool() ? [0x30, 0x80] : [0xa0, 0x80]);
      }
      return Uint8List.fromList([...b.sublist(0, s), ...pre, ...b.sublist(s)]);
    case 10: // trailing garbage / EOC
      return Uint8List.fromList([
        ...b,
        ...List.generate(
          1 + r.nextInt(6),
          (_) => r.nextBool() ? 0 : r.nextInt(256),
        ),
      ]);
    default: // swap two header bytes (tag/length confusion)
      final h = _headerOffsets(b);
      if (h.length < 2) return b;
      final a = h[r.nextInt(h.length)], c = h[r.nextInt(h.length)];
      final t = b[a];
      b[a] = b[c];
      b[c] = t;
      return b;
  }
}
