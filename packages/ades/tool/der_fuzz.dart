// Differential fuzzer: our strict DER codec vs OpenSSL 3 (`asn1parse`).
//
//   dart run packages/ades/tool/der_fuzz.dart --seconds 60 \
//       [--seed N] [--openssl PATH] [--out DIR] [--jobs 8]
//
// What is compared (OpenSSL's asn1parse is a BER-lenient framing parser; it
// does not validate primitive content, so content rules such as BOOLEAN or
// INTEGER minimality are covered by unit tests, not by this tool):
//
//  * we accept, OpenSSL rejects                      -> DISAGREEMENT
//  * both accept, but element structure differs
//    (offset, depth, header length, length, constructed) -> DISAGREEMENT
//  * we reject on framing grounds (truncated, bad length/tag, trailing data),
//    OpenSSL accepts                                  -> DISAGREEMENT
//  * we reject on DER-strictness / content grounds, OpenSSL accepts
//                                                     -> expected, counted
//  * limit rejections (our maxDepth is 64, OpenSSL's 128) are skipped.
//
// Exit code 1 if any disagreement is found; each is saved as hex in --out.
// ignore_for_file: avoid_print
import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:ades/src/asn1/asn1.dart';

const _framing = {
  Asn1ErrorKind.truncated,
  Asn1ErrorKind.trailingData,
  Asn1ErrorKind.invalidLength,
  Asn1ErrorKind.invalidTag,
};

class _Node {
  _Node(this.offset, this.depth, this.hl, this.len, this.cons);
  final int offset, depth, hl;
  final int? len;
  final bool cons;
  @override
  bool operator ==(Object o) =>
      o is _Node &&
      o.offset == offset &&
      o.depth == depth &&
      o.hl == hl &&
      o.len == len &&
      o.cons == cons;
  @override
  int get hashCode => Object.hash(offset, depth, hl, len, cons);
  @override
  String toString() =>
      '@$offset d=$depth hl=$hl l=$len ${cons ? 'cons' : 'prim'}';
}

void _flatten(Asn1Element e, int depth, List<_Node> out) {
  out.add(
    _Node(
      e.offset,
      depth,
      e.headerLength,
      e.contentBytes.length,
      e.tag.constructed,
    ),
  );
  for (final c in e.children ?? const <Asn1Element>[]) {
    _flatten(c, depth + 1, out);
  }
}

final _line = RegExp(
  r'^\s*(\d+):d=(\d+)\s+hl=\s*(\d+)\s+l=\s*(\d+|inf)\s+(cons|prim):',
);

/// Returns null if OpenSSL rejected the input.
Future<List<_Node>?> _openssl(String bin, Uint8List data, File f) async {
  await f.writeAsBytes(data);
  final r = await Process.run(
    bin,
    ['asn1parse', '-inform', 'DER', '-in', f.path],
    stdoutEncoding: latin1,
    stderrEncoding: latin1,
  );
  if (r.exitCode != 0) return null;
  final nodes = <_Node>[];
  for (final l in (r.stdout as String).split('\n')) {
    final m = _line.firstMatch(l);
    if (m == null) continue;
    nodes.add(
      _Node(
        int.parse(m[1]!),
        int.parse(m[2]!),
        int.parse(m[3]!),
        m[4] == 'inf' ? null : int.parse(m[4]!),
        m[5] == 'cons',
      ),
    );
  }
  if (nodes.isEmpty) return null;
  if (nodes.where((n) => n.depth == 0).length > 1) return null; // trailing
  return nodes;
}

// ---- input generation ----

Asn1Element _gen(Random r, int depth) {
  switch (r.nextInt(depth > 0 ? 9 : 6)) {
    case 0:
      return Asn1Element.integer(BigInt.from(r.nextInt(1 << 31) - (1 << 30)));
    case 1:
      return Asn1Element.boolean(r.nextBool());
    case 2:
      return Asn1Element.octetString(
        Uint8List.fromList(
          List.generate(
            r.nextInt(r.nextBool() ? 8 : 300),
            (_) => r.nextInt(256),
          ),
        ),
      );
    case 3:
      return Asn1Element.nullValue();
    case 4:
      return Asn1Element.oid(
        '${r.nextInt(3)}.${r.nextInt(40)}.${r.nextInt(1 << 20)}',
      );
    case 5:
      return Asn1Element.utf8String('abc' * r.nextInt(5));
    case 6:
      return Asn1Element.sequence(
        List.generate(r.nextInt(5), (_) => _gen(r, depth - 1)),
      );
    case 7:
      return Asn1Element.setOf(
        List.generate(r.nextInt(5), (_) => _gen(r, depth - 1)),
      );
    default:
      return Asn1Element.constructed(
        Asn1Tag(Asn1Class.contextSpecific, true, r.nextInt(100)),
        List.generate(r.nextInt(4), (_) => _gen(r, depth - 1)),
      );
  }
}

/// Re-encodes a tree with random BER/DER deviations while keeping the
/// framing self-consistent.
void _evil(Asn1Element e, Random r, BytesBuilder out, double p) {
  final tagBytes = _tagBytes(e.tag, r, p);
  Uint8List content;
  if (e.children != null) {
    final b = BytesBuilder();
    var kids = [...e.children!];
    if (e.tag == Asn1Tag.set && r.nextDouble() < p) kids.shuffle(r);
    for (final c in kids) {
      _evil(c, r, b, p);
    }
    content = b.toBytes();
  } else {
    content = Uint8List.fromList(e.contentBytes);
    if (r.nextDouble() < p && content.isNotEmpty) {
      switch (r.nextInt(3)) {
        case 0:
          content = Uint8List.fromList([r.nextBool() ? 0 : 0xff, ...content]);
        case 1:
          content[r.nextInt(content.length)] = r.nextInt(256);
        default:
          content = content.sublist(0, r.nextInt(content.length));
      }
    }
  }
  out.add(tagBytes);
  if (e.children != null && r.nextDouble() < p / 2) {
    out.addByte(0x80);
    out.add(content);
    out.add([0, 0]);
    return;
  }
  out.add(_lenBytes(content.length, r, p));
  out.add(content);
}

List<int> _tagBytes(Asn1Tag t, Random r, double p) {
  final first = (t.tagClass.index << 6) | (t.constructed ? 0x20 : 0);
  if (t.number < 31 && r.nextDouble() >= p / 4) return [first | t.number];
  final nb = <int>[];
  var n = t.number;
  nb.add(n & 0x7f);
  n >>= 7;
  while (n > 0) {
    nb.add((n & 0x7f) | 0x80);
    n >>= 7;
  }
  final body = nb.reversed.toList();
  if (r.nextDouble() < p / 4) body.insert(0, 0x80);
  return [first | 0x1f, ...body];
}

List<int> _lenBytes(int len, Random r, double p) {
  final nonMinimal = r.nextDouble() < p;
  if (len < 128 && !nonMinimal) return [len];
  var bytes = <int>[];
  for (var v = len; v > 0; v >>= 8) {
    bytes.insert(0, v & 0xff);
  }
  if (bytes.isEmpty) bytes = [0];
  if (nonMinimal) bytes = [...List.filled(1 + r.nextInt(2), 0), ...bytes];
  return [0x80 | bytes.length, ...bytes];
}

Uint8List _byteMutate(Uint8List src, Random r) {
  final l = src.toList();
  for (var i = 0; i < 1 + r.nextInt(3) && l.isNotEmpty; i++) {
    final pos = r.nextInt(l.length);
    switch (r.nextInt(5)) {
      case 0:
        l[pos] = r.nextInt(256);
      case 1:
        l[pos] = const [0, 0x7f, 0x80, 0x81, 0x82, 0xff, 0x1f][r.nextInt(7)];
      case 2:
        l.insert(pos, r.nextInt(256));
      case 3:
        l.removeAt(pos);
      default:
        l.length = pos;
    }
  }
  return Uint8List.fromList(l);
}

Future<void> main(List<String> args) async {
  String opt(String name, String def) {
    final i = args.indexOf('--$name');
    return i >= 0 && i + 1 < args.length ? args[i + 1] : def;
  }

  final seconds = int.parse(opt('seconds', '60'));
  final seed = int.parse(
    opt('seed', '${DateTime.now().millisecondsSinceEpoch}'),
  );
  final bin = opt('openssl', 'openssl');
  final outDir = Directory(opt('out', 'der_fuzz_findings'));
  final jobs = int.parse(opt('jobs', '8'));

  final version = await Process.run(bin, ['version']);
  stdout.writeln('openssl: ${(version.stdout as String).trim()}');
  stdout.writeln('seed: $seed, budget: ${seconds}s, jobs: $jobs');

  final tmp = Directory.systemTemp.createTempSync('der_fuzz');
  final files = [for (var i = 0; i < jobs; i++) File('${tmp.path}/in$i.der')];
  final r = Random(seed);
  final deadline = DateTime.now().add(Duration(seconds: seconds));
  const limits = Asn1Limits(maxDepth: 120);

  var total = 0, bothAccept = 0, bothReject = 0, strictOnly = 0, skipped = 0;
  var disagreements = 0;

  void report(String why, Uint8List data) {
    disagreements++;
    outDir.createSync(recursive: true);
    final hex = data.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
    File(
      '${outDir.path}/disagreement_${seed}_$disagreements.hex',
    ).writeAsStringSync('$hex\n# $why\n');
    stdout.writeln('DISAGREEMENT: $why\n  $hex');
  }

  while (DateTime.now().isBefore(deadline)) {
    final batch = <Uint8List>[];
    for (var j = 0; j < jobs; j++) {
      final tree = _gen(r, 4);
      final mode = r.nextInt(3);
      Uint8List data;
      if (mode == 0) {
        data = tree.encode();
      } else if (mode == 1) {
        final b = BytesBuilder();
        _evil(tree, r, b, 0.08);
        data = b.toBytes();
      } else {
        data = _byteMutate(tree.encode(), r);
      }
      batch.add(data);
    }
    final results = await Future.wait([
      for (var j = 0; j < jobs; j++) _openssl(bin, batch[j], files[j]),
    ]);
    for (var j = 0; j < jobs; j++) {
      total++;
      final data = batch[j];
      final ossl = results[j];
      Asn1Element? ours;
      Asn1Exception? err;
      try {
        ours = decodeDer(data, limits: limits);
      } on Asn1Exception catch (e) {
        err = e;
      } catch (e) {
        report('non-Asn1Exception thrown: $e', data);
        continue;
      }
      if (ours != null) {
        if (ossl == null) {
          report('we accept, OpenSSL rejects', data);
          continue;
        }
        final mine = <_Node>[];
        _flatten(ours, 0, mine);
        if (mine.length != ossl.length ||
            Iterable<int>.generate(
              mine.length,
            ).any((i) => mine[i] != ossl[i])) {
          report('structure differs\n  ours:    $mine\n  openssl: $ossl', data);
          continue;
        }
        bothAccept++;
      } else if (ossl == null) {
        bothReject++;
      } else if (err!.kind.isLimit) {
        skipped++;
      } else if (_framing.contains(err.kind)) {
        report(
          'we reject (${err.kind.name}), OpenSSL accepts: ${err.message}',
          data,
        );
      } else {
        strictOnly++;
      }
    }
  }
  tmp.deleteSync(recursive: true);
  stdout.writeln(
    'cases: $total  both-accept: $bothAccept  '
    'both-reject: $bothReject  strictness-only-reject: $strictOnly  '
    'skipped(limits): $skipped  DISAGREEMENTS: $disagreements',
  );
  exit(disagreements == 0 ? 0 : 1);
}
