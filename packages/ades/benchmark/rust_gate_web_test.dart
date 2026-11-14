/// Web runner (not part of `dart test`, which only scans `test/`):
///   dart test -p chrome benchmark/rust_gate_web_test.dart
///   dart test -p chrome -c dart2wasm benchmark/rust_gate_web_test.dart
@Timeout(Duration(minutes: 15))
library;

import 'package:test/test.dart';

import 'rust_gate.dart';

void main() {
  test('rust gate benchmarks', () async {
    final results = await runRustGate(sha256Bytes: 64 << 20);
    print(formatResults(results));
    expect(results, hasLength(3));
  });
}
