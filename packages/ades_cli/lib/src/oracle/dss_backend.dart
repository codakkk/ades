import 'dart:io';

import 'package:ades/ades.dart';

/// The two validation policies the oracle compares under. Each names the DSS
/// policy file of the harness image and the equal `ValidationPolicy` of ours.
enum OraclePolicy {
  /// DSS's default policy; ours is the default.
  standard('default', ValidationPolicy()),

  /// DSS's default with revocation data ignored; ours the same (the only way
  /// to reach TOTAL-PASSED offline).
  noRevocation(
    'no-revocation',
    ValidationPolicy(revocationDataAvailable: ConstraintLevel.ignore),
  );

  const OraclePolicy(this.dssName, this.validationPolicy);

  /// File name (without `.xml`) in the harness image's `/app/policy`.
  final String dssName;

  /// Our side of the same policy.
  final ValidationPolicy validationPolicy;
}

/// The DSS release pinned in `tool/dss_oracle/dss_version.txt`: the file in
/// [harnessDir], or else the one found in the current directory or a parent.
String readPinnedDssVersion({String? harnessDir}) {
  if (harnessDir != null) {
    return File('$harnessDir/dss_version.txt').readAsStringSync().trim();
  }
  var dir = Directory.current.absolute;
  while (true) {
    final f = File('${dir.path}/tool/dss_oracle/dss_version.txt');
    if (f.existsSync()) return f.readAsStringSync().trim();
    if (dir.parent.path == dir.path) {
      throw DssBackendException('tool/dss_oracle not found');
    }
    dir = dir.parent;
  }
}

/// What the DSS side needs to know about one ad-hoc validation.
final class OracleRequest {
  OracleRequest({
    required this.signaturePath,
    required this.trustAnchorPaths,
    required this.validationTime,
    required this.policy,
    this.documentPath,
    this.certificatePaths = const [],
  });

  final String signaturePath;
  final String? documentPath;
  final List<String> trustAnchorPaths;
  final List<String> certificatePaths;

  /// UTC, whole seconds.
  final DateTime validationTime;

  final OraclePolicy policy;
}

/// The DSS side is unusable (Docker missing, webapp down, DSS error).
final class DssBackendException implements Exception {
  DssBackendException(this.message);
  final String message;
  @override
  String toString() => message;
}

/// Produces DSS's verdict as the normalized JSON of `tool/dss_oracle/README.md`
/// (`{signatures: [{index, indication, subIndication, signingTime, scope,
/// blocks}]}`). Injectable so tests need no Docker.
abstract interface class DssBackend {
  String get name;
  Future<Map<String, Object?>> validate(OracleRequest request);
}
