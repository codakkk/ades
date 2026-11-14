import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:ades/ades.dart';
import 'package:args/args.dart';

import '../core_bridge.dart';
import '../environment.dart';
import '../exit_codes.dart';
import 'dss_backend.dart';
import 'harness_backend.dart';
import 'webapp_backend.dart';

export 'dss_backend.dart';
export 'harness_backend.dart';
export 'webapp_backend.dart';

/// `ades oracle` exit code: our report and DSS's differ.
const int oracleDifferences = 3;

ArgParser oracleParser() => ArgParser()
  ..addFlag('help', abbr: 'h', negatable: false, help: 'Show this help.')
  ..addMultiOption(
    'trust-anchor',
    abbr: 't',
    valueHelp: 'file',
    help:
        'Trust anchor certificate (PEM or DER). Repeatable for our side; the\n'
        'harness takes exactly one. Ignored by --webapp (it uses its own\n'
        'trusted lists).',
  )
  ..addMultiOption(
    'certificate',
    abbr: 'c',
    valueHelp: 'file',
    help: 'Extra certificate for path building (PEM or DER). Repeatable.',
  )
  ..addOption(
    'document',
    abbr: 'd',
    valueHelp: 'file',
    help: 'Signed document, for a detached signature (.p7s).',
  )
  ..addOption(
    'validation-time',
    valueHelp: 'ISO-8601',
    help:
        'Validate as of this time (default: now). Ignored by --webapp,\n'
        'which always validates at the current time.',
  )
  ..addFlag(
    'ignore-revocation',
    negatable: false,
    help:
        'Ignore missing revocation data on both sides (DSS policy\n'
        '"no-revocation"; harness only).',
  )
  ..addFlag(
    'webapp',
    negatable: false,
    help:
        'Ask the DSS demo webapp (tool/dss_webapp) instead of the offline\n'
        'Docker harness.',
  )
  ..addOption(
    'webapp-url',
    valueHelp: 'url',
    defaultsTo: 'http://localhost:9795',
    help: 'Base URL of the DSS demo webapp.',
  )
  ..addFlag(
    'json',
    negatable: false,
    help: 'Print both normalized reports and the differences as JSON.',
  );

const String oracleUsage = '''
Usage: ades oracle <file> [options]

Validates <file> with ades and with the pinned DSS (default: the offline
Docker harness of tool/dss_oracle; --webapp: the demo webapp), normalizes both
to the oracle JSON format and highlights differences. Exit 0: identical,
3: differences, 69: DSS side unavailable. For ad-hoc investigation; not part
of CI.
''';

/// Runs `ades oracle`. [backend] overrides the DSS side (tests).
Future<int> runOracle(
  List<String> args, {
  required CliEnvironment env,
  DssBackend? backend,
}) async {
  final parser = oracleParser();
  final ArgResults r;
  try {
    r = parser.parse(args);
  } on FormatException catch (e) {
    env.err.writeln('${e.message}\n\n$oracleUsage${parser.usage}');
    return ExitCode.usage;
  }
  if (r['help'] as bool) {
    env.out.writeln('$oracleUsage\n${parser.usage}');
    return ExitCode.ok;
  }
  if (r.rest.length != 1) {
    env.err.writeln(
      'Expected exactly one <file>.\n\n$oracleUsage${parser.usage}',
    );
    return ExitCode.usage;
  }
  final file = r.rest.single;
  final anchorPaths = r['trust-anchor'] as List<String>;
  final poolPaths = r['certificate'] as List<String>;
  final docPath = r['document'] as String?;
  for (final p in [file, ?docPath, ...anchorPaths, ...poolPaths]) {
    if (!File(p).existsSync()) {
      env.err.writeln('Cannot read "$p".');
      return ExitCode.noInput;
    }
  }
  final DateTime time;
  final t = r['validation-time'] as String?;
  if (t == null) {
    final now = DateTime.now().toUtc();
    time = DateTime.utc(
      now.year,
      now.month,
      now.day,
      now.hour,
      now.minute,
      now.second,
    );
  } else {
    final parsed = DateTime.tryParse(t)?.toUtc();
    if (parsed == null) {
      env.err.writeln('Invalid --validation-time "$t".');
      return ExitCode.usage;
    }
    time = parsed;
  }
  final request = OracleRequest(
    signaturePath: file,
    documentPath: docPath,
    trustAnchorPaths: anchorPaths,
    certificatePaths: poolPaths,
    validationTime: time,
    policy: (r['ignore-revocation'] as bool)
        ? OraclePolicy.noRevocation
        : OraclePolicy.standard,
  );

  final dssBackend =
      backend ??
      ((r['webapp'] as bool)
          ? WebappBackend(baseUrl: r['webapp-url'] as String)
          : HarnessBackend.discover());

  final Map<String, Object?> ours;
  try {
    ours = await _ourReport(request);
  } on FormatException catch (e) {
    env.err.writeln('Invalid certificate: ${e.message}');
    return ExitCode.dataError;
  }
  final Map<String, Object?> dss;
  try {
    dss = projectForComparison(await dssBackend.validate(request));
  } on DssBackendException catch (e) {
    env.err.writeln('DSS (${dssBackend.name}) unavailable: ${e.message}');
    return ExitCode.unavailable;
  }

  final a = flattenReport(ours);
  final b = flattenReport(dss);
  final paths = <String>{...a.keys, ...b.keys}.toList()..sort(_comparePaths);
  final diffs = [
    for (final p in paths)
      if (a[p] != b[p]) p,
  ];

  if (r['json'] as bool) {
    env.out.writeln(
      const JsonEncoder.withIndent('  ').convert({
        'backend': dssBackend.name,
        'ours': ours,
        'dss': dss,
        'differences': [
          for (final p in diffs) {'path': p, 'ours': a[p], 'dss': b[p]},
        ],
      }),
    );
  } else {
    _printTable(env.out, file, dssBackend.name, request, paths, a, b, diffs);
  }
  return diffs.isEmpty ? ExitCode.ok : oracleDifferences;
}

Future<Map<String, Object?>> _ourReport(OracleRequest q) async {
  final anchors = [
    for (final p in q.trustAnchorPaths)
      for (final der in readCertificates(p)) TrustAnchor.fromDer(der),
  ];
  final pool = [for (final p in q.certificatePaths) ...readCertificates(p)];
  final outcome = await runCoreValidation(
    signature: File(q.signaturePath).readAsBytesSync(),
    document: q.documentPath == null
        ? null
        : File(q.documentPath!).readAsBytesSync(),
    trustAnchors: anchors,
    pool: pool,
    validationTime: q.validationTime,
    policy: q.policy.validationPolicy,
  );
  return projectForComparison(
    normalizeReport(
      outcome.report,
      validationTime: q.validationTime.toIso8601String().replaceFirst(
        '.000Z',
        'Z',
      ),
    ),
  );
}

/// All certificates of a PEM (or one DER) file, as DER.
List<Uint8List> readCertificates(String path) {
  final bytes = File(path).readAsBytesSync();
  final text = latin1.decode(bytes, allowInvalid: true);
  if (!text.contains('-----BEGIN')) return [bytes];
  final out = <Uint8List>[];
  final re = RegExp(
    r'-----BEGIN CERTIFICATE-----([^-]*)-----END CERTIFICATE-----',
  );
  for (final m in re.allMatches(text)) {
    out.add(base64.decode(m.group(1)!.replaceAll(RegExp(r'\s'), '')));
  }
  if (out.isEmpty) throw FormatException('"$path" has no certificate');
  return out;
}

/// Orders `signatures[2].x` after `signatures[10]`-safe: numeric-aware.
int _comparePaths(String x, String y) {
  String pad(String s) => s.replaceAllMapped(
    RegExp(r'\[(\d+)\]'),
    (m) => '[${m.group(1)!.padLeft(6, '0')}]',
  );
  return pad(x).compareTo(pad(y));
}

void _printTable(
  StringSink out,
  String file,
  String backendName,
  OracleRequest q,
  List<String> paths,
  Map<String, Object?> a,
  Map<String, Object?> b,
  List<String> diffs,
) {
  String v(Object? x) => x == null ? '-' : '$x';
  out.writeln('File: $file');
  out.writeln(
    'Validation time: ${q.validationTime.toIso8601String().replaceFirst('.000Z', 'Z')}   '
    'DSS: $backendName, policy ${q.policy.dssName}',
  );
  final width = paths.fold<int>(4, (m, p) => p.length > m ? p.length : m);
  final col = paths.fold<int>(
    4,
    (m, p) => v(a[p]).length > m ? v(a[p]).length : m,
  );
  out.writeln('      ${'path'.padRight(width)}  ${'ours'.padRight(col)}  DSS');
  for (final p in paths) {
    final differs = diffs.contains(p);
    out.writeln(
      '${differs ? 'DIFF  ' : '      '}${p.padRight(width)}  '
      '${v(a[p]).padRight(col)}  ${v(b[p])}',
    );
  }
  out.writeln(
    diffs.isEmpty
        ? 'No differences.'
        : '${diffs.length} difference${diffs.length == 1 ? '' : 's'} '
              '(marked DIFF).',
  );
}
