// VM-only helper shared by test/dss_goldens_test.dart and the triage script
// test/support/dss_diff.dart. Reads fixtures/tier1 relative to packages/ades.
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:ades/ades.dart';

final fixturesDir = Directory('../../fixtures/tier1');

Object? readFixtureJson(String path) =>
    jsonDecode(File('${fixturesDir.path}/$path').readAsStringSync());

Uint8List _bytes(String path) =>
    File('${fixturesDir.path}/$path').readAsBytesSync();

/// One case of `oracle-cases.json`.
typedef OracleCase = Map<String, Object?>;

({String validationTime, List<OracleCase> cases}) loadCases() {
  final m = readFixtureJson('oracle-cases.json')! as Map<String, Object?>;
  return (
    validationTime: m['validationTime']! as String,
    cases: (m['cases']! as List).cast<OracleCase>(),
  );
}

/// Differences between our normalized report and the DSS golden for [c]:
/// `path -> (ours, dss)`. Empty when they agree.
Future<Map<String, (Object?, Object?)>> diffCase(
  OracleCase c,
  String validationTime,
) async {
  final golden =
      readFixtureJson(c['golden']! as String)! as Map<String, Object?>;
  if (golden.containsKey('error')) {
    throw StateError('golden for ${c['id']} records ${golden['error']}');
  }
  final content = c['content'] as String?;
  final validator = Validator(
    trustAnchors: [TrustAnchor.fromDer(_bytes(c['anchor']! as String))],
  );
  final report = await validator.validate(
    _bytes(c['signature']! as String),
    detachedContent: content == null ? null : _bytes(content),
    validationTime: DateTime.parse(validationTime),
    policy: switch (c['policy']) {
      'no-revocation' => const ValidationPolicy(
        revocationDataAvailable: ConstraintLevel.ignore,
      ),
      _ => const ValidationPolicy(),
    },
  );
  final ours = flattenReport(
    projectForComparison(
      normalizeReport(report, validationTime: validationTime),
    ),
  );
  final dss = flattenReport(projectForComparison(golden));
  return {
    for (final p in {...ours.keys, ...dss.keys})
      if (ours[p] != dss[p]) p: (ours[p], dss[p]),
  };
}
