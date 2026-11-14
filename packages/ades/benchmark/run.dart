/// VM / AOT runner:
///   dart run benchmark/run.dart
///   dart compile exe benchmark/run.dart -o OUT && OUT
library;

import 'rust_gate.dart';

Future<void> main() async {
  print(formatResults(await runRustGate()));
}
