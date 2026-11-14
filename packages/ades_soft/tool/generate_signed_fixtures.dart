// Generates fixtures/tier1/signatures/ours/*: CAdES-B-B made by OUR signer
// (ades + ades_soft) with the tier-1 keys over content/hello.txt, enveloping
// (.p7m) and detached (.p7s), RSA and ECDSA P-256. RSA PKCS#1 v1.5 and
// ades_soft's ECDSA (RFC 6979) are deterministic and the signing time is
// fixed, so the output is byte-stable. Run from the repo root:
//   dart run packages/ades_soft/tool/generate_signed_fixtures.dart
// Then regenerate the DSS goldens: dart run tool/dss_oracle/run.dart
import 'dart:io';

import 'package:ades/ades.dart';
import 'package:ades_soft/ades_soft.dart';

Future<void> main() async {
  final fixtures = Directory('fixtures/tier1');
  final doc = File('${fixtures.path}/content/hello.txt').readAsBytesSync();
  final out = Directory('${fixtures.path}/signatures/ours')
    ..createSync(recursive: true);
  final algorithms = {
    'rsa2048': SignatureAlgorithm.rsaPkcs1v15Sha256,
    'p256': const SignatureAlgorithm(
      SignatureScheme.ecdsa,
      DigestAlgorithm.sha256,
    ),
  };
  for (final hierarchy in algorithms.keys) {
    for (final leaf in ['qsign', 'auth']) {
      final credential = SoftSigningCredential.fromPkcs12(
        File(
          '${fixtures.path}/pki/$hierarchy/leaf-$leaf.p12',
        ).readAsBytesSync(),
        password: 'test',
      );
      for (final detached in [false, true]) {
        final signature = await Cades.sign(
          document: doc,
          credential: credential,
          algorithm: algorithms[hierarchy]!,
          detached: detached,
          signingTime: DateTime.utc(2026, 6, 1, 12),
        );
        final path = '${out.path}/$hierarchy-$leaf.${detached ? 'p7s' : 'p7m'}';
        File(path).writeAsBytesSync(signature);
        stdout.writeln('wrote $path');
      }
    }
  }
}
