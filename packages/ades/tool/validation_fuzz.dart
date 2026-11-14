// Mutation fuzzer for the public validation entry points (bytes and stream).
//
//   dart run packages/ades/tool/validation_fuzz.dart --seconds 60 \
//       [--seed N] [--out DIR] [--time-budget-ms 5000] [--memory-mb 512]
//
// Seeds: every .p7m/.p7s under fixtures/tier1/signatures (tier-1 corpus).
// Invariants per input: no exception escapes validate / validateStream, the
// input is judged within --time-budget-ms, and process RSS does not grow by
// more than --memory-mb over its previous level. A violating input is saved
// to --out (default fixtures/fuzz/regressions) as `<kind>-<hash>.bin`;
// test/fuzz_regression_test.dart replays everything in that directory.
// Exit code 1 when anything was found.
// ignore_for_file: avoid_print
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:ades/ades.dart';

import '../test/support/fuzz_engine.dart';

String _arg(List<String> a, String name, String def) {
  final i = a.indexOf('--$name');
  return i >= 0 && i + 1 < a.length ? a[i + 1] : def;
}

String _hash(Uint8List b) {
  var h = 0x811c9dc5;
  for (final x in b) {
    h = ((h ^ x) * 0x01000193) & 0xffffffff;
  }
  return h.toRadixString(16).padLeft(8, '0');
}

Future<void> main(List<String> args) async {
  final seconds = int.parse(_arg(args, 'seconds', '60'));
  final seed = int.parse(
    _arg(args, 'seed', '${DateTime.now().millisecondsSinceEpoch}'),
  );
  final timeBudget = Duration(
    milliseconds: int.parse(_arg(args, 'time-budget-ms', '5000')),
  );
  final memBudget = int.parse(_arg(args, 'memory-mb', '512')) * 1024 * 1024;
  final root = Platform.script.resolve('../../../').toFilePath();
  final fixtures = _arg(args, 'fixtures', '${root}fixtures/tier1');
  final out = Directory(_arg(args, 'out', '${root}fixtures/fuzz/regressions'));

  Uint8List read(String p) => File('$fixtures/$p').readAsBytesSync();
  final seeds = <Uint8List>[
    for (final f in Directory('$fixtures/signatures').listSync(recursive: true))
      if (f is File && (f.path.endsWith('.p7m') || f.path.endsWith('.p7s')))
        f.readAsBytesSync(),
  ];
  final detached = read('content/hello.txt');
  final validator = Validator(
    trustAnchors: [
      TrustAnchor.fromDer(read('pki/rsa2048/root.der')),
      TrustAnchor.fromDer(read('pki/p256/root.der')),
    ],
    certificatePool: [
      read('pki/rsa2048/intermediate.der'),
      read('pki/p256/intermediate.der'),
    ],
  );

  print('seed=$seed seeds=${seeds.length} budget=${seconds}s');
  final r = Random(seed);
  final end = DateTime.now().add(Duration(seconds: seconds));
  var runs = 0, found = 0, rss = ProcessInfo.currentRss;
  final saved = <String>{};
  while (DateTime.now().isBefore(end)) {
    final input = mutate(r, seeds[r.nextInt(seeds.length)], seeds);
    runs++;
    var f = await checkInput(
      validator,
      input,
      detachedContent: detached,
      chunkSize: 1 + r.nextInt(64),
      timeBudget: timeBudget,
    );
    final now = ProcessInfo.currentRss;
    if (f == null && now - rss > memBudget) {
      f = FuzzFinding('memory', 'RSS grew ${(now - rss) >> 20} MiB');
    }
    rss = now;
    if (f == null) continue;
    found++;
    final name = '${f.kind}-${_hash(input)}.bin';
    print('FINDING $name (${input.length} bytes): $f');
    if (saved.add(name)) {
      out.createSync(recursive: true);
      File('${out.path}/$name').writeAsBytesSync(input);
    }
  }
  print('runs=$runs findings=$found');
  if (found > 0) exit(1);
}
