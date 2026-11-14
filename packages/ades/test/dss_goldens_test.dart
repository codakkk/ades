// Seam 1 against the DSS oracle (ADR-0010, ticket 09): our reports for every
// tier-1 fixture are normalized and diffed against the committed DSS goldens.
// Fails on any difference that is not listed, with a reason, in
// fixtures/tier1/known-divergences.json, and on listed entries that no longer
// differ. No Java and no Docker: goldens are produced by tool/dss_oracle/run.dart.
@TestOn('vm')
library;

import 'package:test/test.dart';

import 'support/dss_compare.dart';

void main() {
  final loaded = loadCases();
  final divergences =
      ((readFixtureJson('known-divergences.json')! as Map)['divergences']!
              as List)
          .cast<Map<String, Object?>>();

  test('every known divergence has a reason and names a real case', () {
    final ids = {for (final c in loaded.cases) c['id']};
    for (final d in divergences) {
      expect(ids, contains(d['case']), reason: 'unknown case ${d['case']}');
      expect(
        (d['reason'] as String?)?.trim() ?? '',
        isNotEmpty,
        reason: 'divergence ${d['case']} ${d['path']} needs a reason',
      );
    }
  });

  for (final c in loaded.cases) {
    final id = c['id']! as String;
    test('$id matches the DSS golden or is a known divergence', () async {
      final actual = await diffCase(c, loaded.validationTime);
      final listed = {
        for (final d in divergences)
          if (d['case'] == id) d['path']! as String: (d['ours'], d['dss']),
      };
      expect(
        {
          for (final e in actual.entries)
            if (listed[e.key] != e.value) e.key: e.value,
        },
        isEmpty,
        reason:
            'unexplained differences from DSS (path: (ours, dss)); fix the '
            'validator or add them with a reason to known-divergences.json',
      );
      expect(
        {
          for (final e in listed.entries)
            if (actual[e.key] != e.value) e.key: e.value,
        },
        isEmpty,
        reason: 'known-divergences.json lists differences that are gone',
      );
    });
  }
}
