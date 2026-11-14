// The DSS version is pinned in one file and must agree everywhere it appears:
// the pom, and every committed golden (so a version bump cannot leave stale
// goldens behind). No Java or Docker needed.
@TestOn('vm')
library;

import 'dart:convert';
import 'dart:io';

import 'package:test/test.dart';

void main() {
  final pinned = File(
    'tool/dss_oracle/dss_version.txt',
  ).readAsStringSync().trim();

  test('pom.xml pins the same DSS version', () {
    final pom = File('tool/dss_oracle/pom.xml').readAsStringSync();
    expect(pom, contains('<dss.version>$pinned</dss.version>'));
  });

  test('docker-compose builds the webapp at the pinned DSS version', () {
    final compose = File(
      'tool/dss_webapp/docker-compose.yml',
    ).readAsStringSync();
    expect(compose, contains('dss-demonstrations.git#$pinned'));
    expect(compose, contains('ades-dss-webapp:$pinned'));
  });

  test('every golden was produced by the pinned DSS version', () {
    final goldens = Directory('fixtures/tier1/signatures')
        .listSync(recursive: true)
        .whereType<File>()
        .where((f) => f.path.contains('.dss'))
        .toList();
    expect(goldens, isNotEmpty);
    for (final f in goldens) {
      final json = jsonDecode(f.readAsStringSync()) as Map<String, Object?>;
      expect(json['dssVersion'], pinned, reason: f.path);
    }
  });

  test('every manifest case has a golden next to its fixture', () {
    final manifest =
        jsonDecode(File('fixtures/tier1/oracle-cases.json').readAsStringSync())
            as Map<String, Object?>;
    for (final c in (manifest['cases']! as List).cast<Map<String, Object?>>()) {
      expect(
        File('fixtures/tier1/${c['golden']}').existsSync(),
        isTrue,
        reason: c['id'] as String,
      );
    }
  });
}
