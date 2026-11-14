// Ticket 16: replays every saved fuzzer finding (fixtures/fuzz/regressions)
// and a short deterministic fuzz burst. Seam 1 (public validation API).
@TestOn('vm')
library;

import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:ades/ades.dart';
import 'package:test/test.dart';

import 'support/fuzz_engine.dart';
import 'support/tier1.dart';
import 'support/tier1_data.g.dart' show tier1Base64;

Validator _validator() => Validator(
  trustAnchors: [
    TrustAnchor.fromDer(tier1('pki/rsa2048/root.der')),
    TrustAnchor.fromDer(tier1('pki/p256/root.der')),
  ],
  certificatePool: [
    tier1('pki/rsa2048/intermediate.der'),
    tier1('pki/p256/intermediate.der'),
  ],
);

void main() {
  final dir = Directory('../../fixtures/fuzz/regressions');
  final files = dir.existsSync()
      ? (dir
            .listSync()
            .whereType<File>()
            .where((f) => f.path.endsWith('.bin'))
            .toList()
          ..sort((a, b) => a.path.compareTo(b.path)))
      : <File>[];

  group('saved fuzzer findings', () {
    for (final f in files) {
      test(f.uri.pathSegments.last, () async {
        final f0 = await checkInput(
          _validator(),
          f.readAsBytesSync(),
          detachedContent: tier1('content/hello.txt'),
        );
        expect(f0, isNull, reason: '$f0');
      });
    }
  });

  test('fixed-seed fuzz burst over the tier-1 corpus finds nothing', () async {
    final seeds = <Uint8List>[
      for (final k in tier1Base64.keys)
        if (k.startsWith('signatures/') &&
            (k.endsWith('.p7m') || k.endsWith('.p7s')))
          tier1(k),
    ];
    final r = Random(16);
    final v = _validator();
    for (var i = 0; i < 300; i++) {
      final input = mutate(r, seeds[r.nextInt(seeds.length)], seeds);
      final f = await checkInput(
        v,
        input,
        detachedContent: tier1('content/hello.txt'),
        chunkSize: 1 + r.nextInt(64),
      );
      expect(f, isNull, reason: 'iteration $i: $f');
    }
  });
}
