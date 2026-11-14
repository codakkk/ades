import 'dart:convert';
import 'dart:io';

import 'dss_backend.dart';

/// Runs a process with inherited stdio and returns its exit code.
typedef ProcessRun = Future<int> Function(String executable, List<String> args);

Future<int> _inherit(String exe, List<String> args) async {
  try {
    if (args.first == 'image') return (await Process.run(exe, args)).exitCode;
    final p = await Process.start(
      exe,
      args,
      mode: ProcessStartMode.inheritStdio,
    );
    return await p.exitCode;
  } on ProcessException catch (e) {
    throw DssBackendException('cannot run $exe: ${e.message}');
  }
}

/// The offline Docker harness of `tool/dss_oracle` (ADR-0010): the same image
/// and policies that produce the committed goldens.
final class HarnessBackend implements DssBackend {
  HarnessBackend({
    required this.harnessDir,
    String? version,
    ProcessRun run = _inherit,
  }) : _run = run,
       _version = version;

  /// Finds `tool/dss_oracle` in the current directory or a parent.
  factory HarnessBackend.discover() {
    var dir = Directory.current.absolute;
    while (true) {
      final candidate = '${dir.path}/tool/dss_oracle';
      if (File('$candidate/Dockerfile').existsSync()) {
        return HarnessBackend(harnessDir: candidate);
      }
      if (dir.parent.path == dir.path) {
        throw DssBackendException(
          'tool/dss_oracle not found; run ades oracle from inside the repo',
        );
      }
      dir = dir.parent;
    }
  }

  final String harnessDir;
  final String? _version;
  final ProcessRun _run;

  @override
  String get name => 'harness';

  String get _pinned =>
      _version ?? readPinnedDssVersion(harnessDir: harnessDir);

  @override
  Future<Map<String, Object?>> validate(OracleRequest q) async {
    if (q.trustAnchorPaths.length != 1) {
      throw DssBackendException(
        'the harness needs exactly one trust anchor (-t), '
        'got ${q.trustAnchorPaths.length}',
      );
    }
    final image = 'ades-dss-oracle:$_pinned';
    if (await _run('docker', ['image', 'inspect', image]) != 0) {
      stderr.writeln('building $image ...');
      if (await _run('docker', ['build', '-t', image, harnessDir]) != 0) {
        throw DssBackendException('docker build of $image failed');
      }
    }
    final work = Directory.systemTemp.createTempSync('ades_oracle_');
    try {
      // Stage everything under one directory mounted read-only at /in; the
      // harness resolves manifest paths against it.
      final inDir = Directory('${work.path}/in')..createSync();
      Directory('${work.path}/out').createSync();
      File(
        '${inDir.path}/sig',
      ).writeAsBytesSync(File(q.signaturePath).readAsBytesSync());
      File(
        '${inDir.path}/anchor',
      ).writeAsBytesSync(File(q.trustAnchorPaths.single).readAsBytesSync());
      if (q.documentPath != null) {
        File(
          '${inDir.path}/content',
        ).writeAsBytesSync(File(q.documentPath!).readAsBytesSync());
      }
      final pool = <String>[];
      for (final (i, p) in q.certificatePaths.indexed) {
        // One DER file per certificate: the harness loads one per path.
        final certs = _pemOrDer(File(p).readAsBytesSync());
        for (final (j, der) in certs.indexed) {
          final n = 'pool$i-$j';
          File('${inDir.path}/$n').writeAsBytesSync(der);
          pool.add(n);
        }
      }
      final iso = q.validationTime.toUtc().toIso8601String().replaceFirst(
        '.000Z',
        'Z',
      );
      File('${work.path}/manifest.tsv').writeAsStringSync(
        '${['adhoc', 'sig', q.documentPath == null ? '-' : 'content', 'anchor', iso, pool.isEmpty ? '-' : pool.join(','), q.policy.dssName].join('\t')}\n',
      );
      // /work holds the manifest and output; mount order matters to the test.
      final code = await _run('docker', [
        'run',
        '--rm',
        '--network',
        'none',
        '-v',
        '${inDir.path}:/in:ro',
        '-v',
        '${work.path}:/work',
        image,
        '/work/manifest.tsv',
        '/in',
        '/work/out',
      ]);
      if (code != 0) throw DssBackendException('docker run exited with $code');
      final out = File('${work.path}/out/adhoc.json');
      if (!out.existsSync()) {
        throw DssBackendException('harness wrote no output');
      }
      final json = jsonDecode(out.readAsStringSync()) as Map<String, Object?>;
      if (json.containsKey('error')) {
        throw DssBackendException('DSS failed: ${json['error']}');
      }
      return json;
    } finally {
      work.deleteSync(recursive: true);
    }
  }
}

List<List<int>> _pemOrDer(List<int> bytes) {
  final text = latin1.decode(bytes, allowInvalid: true);
  if (!text.contains('-----BEGIN')) return [bytes];
  return [
    for (final m in RegExp(
      r'-----BEGIN CERTIFICATE-----([^-]*)-----END CERTIFICATE-----',
    ).allMatches(text))
      base64.decode(m.group(1)!.replaceAll(RegExp(r'\s'), '')),
  ];
}
