// Bounded-memory check for streaming (ticket 11). Not part of the default
// test suite: it hashes the document three times.
//
//   dart compile exe packages/ades/tool/large_stream_check.dart -o /tmp/lsc
//   /tmp/lsc --gib 4
//
// Generates a document of --gib GiB on the fly (nothing is written to disk),
// signs it as a stream (prepare: hash pass; complete: second pass), pipes the
// signature stream straight into `Validator.validateStream` (third pass), and
// prints the peak resident set size. Exit 1 if the result is wrong or the
// peak exceeds --max-rss-mib (default 200).
import 'dart:io';
import 'dart:typed_data';

import 'package:ades/ades.dart';

import '../test/support/test_credential.dart';
import '../test/support/tier1.dart';

const _chunk = 1024 * 1024;

/// [length] deterministic bytes in 1 MiB chunks, each a fresh buffer.
Stream<List<int>> generate(int length) async* {
  var done = 0;
  var x = 12345;
  while (done < length) {
    final n = length - done < _chunk ? length - done : _chunk;
    final b = Uint8List(n);
    for (var i = 0; i < n; i += 64) {
      x = (x * 1103515245 + 12345) & 0x7fffffff;
      b[i] = x & 0xff;
    }
    yield b;
    done += n;
  }
}

Future<void> main(List<String> args) async {
  var gib = 2.0;
  var maxRssMib = 200;
  for (var i = 0; i < args.length; i++) {
    if (args[i] == '--gib') gib = double.parse(args[++i]);
    if (args[i] == '--max-rss-mib') maxRssMib = int.parse(args[++i]);
  }
  final length = (gib * 1024 * 1024 * 1024).round();
  final started = DateTime.now();
  final baseline = ProcessInfo.currentRss;

  final cred = TestRsaCredential();
  final draft = await Cades.prepareEnvelopingStream(
    document: generate(length),
    credential: cred,
  );
  final value = await cred.sign(await draft.signRequest());
  final signature = Cades.completeEnvelopingStream(
    draft: draft,
    value: value,
    document: generate(length),
    documentLength: length,
  );
  final report = await Validator(
    trustAnchors: [TrustAnchor.fromDer(tier1('pki/rsa2048/leaf-qsign.der'))],
  ).validateStream(signature);

  final s = report.detailed.signatures.single;
  final cv = s.result(BuildingBlock.cryptographicVerification)!.indication;
  final scope = report.simple.signatures.single.scope.single;
  final peak = ProcessInfo.maxRss / (1024 * 1024);
  final secs = DateTime.now().difference(started).inSeconds;
  stdout
    ..writeln('document: ${length ~/ (1024 * 1024)} MiB, $secs s')
    ..writeln('CV: ${cv.name}, scope length: ${scope.length}')
    ..writeln('baseline RSS: ${(baseline / (1024 * 1024)).round()} MiB')
    ..writeln('peak RSS: ${peak.round()} MiB');
  if (cv != BlockIndication.passed || scope.length != length) {
    stderr.writeln('FAIL: wrong result');
    exit(1);
  }
  if (peak > maxRssMib) {
    stderr.writeln('FAIL: peak RSS above $maxRssMib MiB');
    exit(1);
  }
}
