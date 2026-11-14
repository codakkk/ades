/// Smoke test for the benchmark runner (kept out of the default suite):
///   dart test benchmark/smoke_test.dart
library;

import 'package:test/test.dart';

import 'rust_gate.dart';

void main() {
  test('runner produces parsable output with sane values', () async {
    final results = await runRustGate(
      sha256Bytes: 2 << 20,
      minVerifySeconds: 0,
      minVerifyIterations: 3,
      rsaBits: 1024,
    );
    final parsed = parseResults('noise\n${formatResults(results)}\n');
    expect(parsed.map((r) => r.name), [
      'sha256_stream',
      'rsa1024_pkcs1v15_sha256_verify',
      'ecdsa_p256_sha256_verify',
    ]);
    expect(parsed.every((r) => r.value > 0), isTrue);
  });
}
