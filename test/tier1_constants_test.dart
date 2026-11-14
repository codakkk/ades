import 'package:test/test.dart';

import '../tool/fixtures/generate_dart_constants.dart';
import 'dart:io';

void main() {
  test('embedded tier-1 constants match fixtures/tier1', () {
    expect(
      File(outputPath).readAsStringSync(),
      generate('fixtures/tier1'),
      reason: 'run: dart run tool/fixtures/generate_dart_constants.dart',
    );
  });
}
