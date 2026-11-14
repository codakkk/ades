// Triage helper: prints every difference between our reports and the DSS
// goldens as known-divergences.json entries (reasons left empty).
//   cd packages/ades && dart run test/support/dss_diff.dart
import 'dart:convert';

import 'dss_compare.dart';

Future<void> main() async {
  final loaded = loadCases();
  for (final c in loaded.cases) {
    final diff = await diffCase(c, loaded.validationTime);
    for (final e in diff.entries) {
      print(
        jsonEncode({
          'case': c['id'],
          'path': e.key,
          'ours': e.value.$1,
          'dss': e.value.$2,
          'reason': '',
        }),
      );
    }
  }
}
