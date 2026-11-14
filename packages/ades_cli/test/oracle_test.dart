@TestOn('vm')
library;

import 'dart:convert';
import 'dart:io';

import 'package:ades_cli/ades_cli.dart';
import 'package:ades_cli/src/oracle/oracle_command.dart';
import 'package:test/test.dart';

const _fx = '../../fixtures/tier1';
const _root = '$_fx/pki/rsa2048/root.pem';
const _qsign = '$_fx/signatures/positive/rsa2048-qsign.p7m';
const _time = '2026-11-10T00:00:00Z';

/// Fake DSS: returns the committed golden for the requested policy and
/// records the request.
final class FakeDss implements DssBackend {
  FakeDss(this.result);
  final Map<String, Object?> result;
  OracleRequest? seen;

  @override
  String get name => 'fake';

  @override
  Future<Map<String, Object?>> validate(OracleRequest request) async {
    seen = request;
    return result;
  }
}

final class ThrowingDss implements DssBackend {
  @override
  String get name => 'broken';
  @override
  Future<Map<String, Object?>> validate(OracleRequest request) =>
      throw DssBackendException('docker not found');
}

Map<String, Object?> golden(String name) =>
    jsonDecode(File('$_fx/$name').readAsStringSync()) as Map<String, Object?>;

Future<({int code, String out, String err})> oracle(
  List<String> args,
  DssBackend backend,
) async {
  final out = StringBuffer();
  final err = StringBuffer();
  final code = await runOracle(
    args,
    env: CliEnvironment(out: out, err: err, promptPassword: (_) async => ''),
    backend: backend,
  );
  return (code: code, out: '$out', err: '$err');
}

void main() {
  const base = [
    _qsign,
    '-t',
    _root,
    '--validation-time',
    _time,
    '--ignore-revocation',
  ];

  test('agreeing verdicts: no differences, exit 0', () async {
    final dss = FakeDss(
      golden('signatures/positive/rsa2048-qsign.p7m.dss-norev.json'),
    );
    final r = await oracle(base, dss);
    expect(r.err, isEmpty);
    expect(r.out, contains('TOTAL-PASSED'));
    expect(r.out, contains('No differences'));
    expect(r.code, 0);
    expect(dss.seen!.policy, OraclePolicy.noRevocation);
    expect(dss.seen!.validationTime, DateTime.utc(2026, 11, 10));
    expect(dss.seen!.signaturePath, _qsign);
    expect(dss.seen!.trustAnchorPaths, [_root]);
  });

  test('differences are highlighted and exit 3', () async {
    // default policy on the DSS side but ours ignores revocation
    final dss = FakeDss(
      golden('signatures/positive/rsa2048-qsign.p7m.dss.json'),
    );
    final r = await oracle(base, dss);
    expect(r.code, 3);
    expect(r.out, contains('DIFF'));
    expect(r.out, contains('signatures[0].indication'));
    expect(r.out, contains('TOTAL-PASSED'));
    expect(r.out, contains('INDETERMINATE'));
    expect(r.out, isNot(contains('No differences')));
  });

  test('without --ignore-revocation asks DSS for the default policy', () async {
    final dss = FakeDss(
      golden('signatures/positive/rsa2048-qsign.p7m.dss.json'),
    );
    final r = await oracle([
      _qsign,
      '-t',
      _root,
      '--validation-time',
      _time,
    ], dss);
    expect(dss.seen!.policy, OraclePolicy.standard);
    expect(r.code, isIn([0, 3]));
  });

  test('--json prints both normalized reports', () async {
    final dss = FakeDss(
      golden('signatures/positive/rsa2048-qsign.p7m.dss-norev.json'),
    );
    final r = await oracle([...base, '--json'], dss);
    final j = jsonDecode(r.out) as Map<String, Object?>;
    expect(j.keys, containsAll(['ours', 'dss', 'differences']));
    expect(j['differences'], isEmpty);
  });

  test('backend failure exits 69 with the reason', () async {
    final r = await oracle(base, ThrowingDss());
    expect(r.code, ExitCode.unavailable);
    expect(r.err, contains('docker not found'));
  });

  test('missing file exits 66, missing argument exits 64', () async {
    expect((await oracle(['nope.p7m'], ThrowingDss())).code, ExitCode.noInput);
    expect((await oracle([], ThrowingDss())).code, ExitCode.usage);
  });

  test('harness backend rejects more than one trust anchor', () async {
    final backend = HarnessBackend(
      harnessDir: '.',
      run: (_, _) async => throw 1,
    );
    expect(
      () => backend.validate(
        OracleRequest(
          signaturePath: _qsign,
          trustAnchorPaths: [_root, _root],
          validationTime: DateTime.utc(2026),
          policy: OraclePolicy.standard,
        ),
      ),
      throwsA(isA<DssBackendException>()),
    );
  });

  test(
    'harness backend stages files, runs docker offline, reads the output',
    () async {
      final calls = <List<String>>[];
      final backend = HarnessBackend(
        harnessDir: 'tool/dss_oracle',
        version: '6.5.1',
        run: (exe, args) async {
          calls.add([exe, ...args]);
          if (args.first == 'image') return 1; // image missing: must build
          if (args.first == 'run') {
            // emulate the container: write <id>.json into the mounted /work/out
            final work = args[args.indexOf('-v', args.indexOf('-v') + 1) + 1]
                .split(':')
                .first;
            final manifest = File('$work/manifest.tsv').readAsLinesSync();
            expect(manifest, hasLength(1));
            final f = manifest.single.split('\t');
            expect(f[4], _time);
            expect(f[6], 'no-revocation');
            File('$work/out/${f[0]}.json').writeAsStringSync(
              File(
                '$_fx/signatures/positive/rsa2048-qsign.p7m.dss-norev.json',
              ).readAsStringSync(),
            );
          }
          return 0;
        },
      );
      final result = await backend.validate(
        OracleRequest(
          signaturePath: _qsign,
          trustAnchorPaths: [_root],
          validationTime: DateTime.utc(2026, 11, 10),
          policy: OraclePolicy.noRevocation,
        ),
      );
      expect(result['signatures'], isNotEmpty);
      final run = calls.firstWhere((c) => c[1] == 'run');
      expect(run, containsAllInOrder(['--network', 'none']));
      expect(run.last, '/work/out');
      expect(calls.any((c) => c[1] == 'build'), isTrue);
    },
  );
}
