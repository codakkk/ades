@TestOn('vm')
library;

import 'dart:convert';
import 'dart:io';

import 'package:ades_cli/ades_cli.dart';
import 'package:test/test.dart';

const _fx = '../../fixtures/tier1';
const _root = '$_fx/pki/rsa2048/root.pem';
const _qsign = '$_fx/signatures/positive/rsa2048-qsign.p7m';

final class CliResult {
  CliResult(this.code, this.out, this.err, this.prompts);
  final int code;
  final String out;
  final String err;
  final List<String> prompts;
}

Future<CliResult> ades(List<String> args, {String password = 'test'}) async {
  final out = StringBuffer();
  final err = StringBuffer();
  final prompts = <String>[];
  final code = await runCli(
    args,
    env: CliEnvironment(
      out: out,
      err: err,
      promptPassword: (m) async {
        prompts.add(m);
        return password;
      },
    ),
  );
  return CliResult(code, '$out', '$err', prompts);
}

void main() {
  late Directory tmp;
  setUp(() => tmp = Directory.systemTemp.createTempSync('ades_cli_test'));
  tearDown(() => tmp.deleteSync(recursive: true));

  group('validate', () {
    test(
      'prints the simple report; indeterminate (revocation) exits 2',
      () async {
        final r = await ades(['validate', _qsign, '-t', _root]);
        expect(r.code, ExitCode.indeterminate);
        expect(
          r.out,
          contains('INDETERMINATE / CERTIFICATE_CHAIN_GENERAL_FAILURE'),
        );
        expect(r.out, contains('TESTSURNAME'));
        expect(r.out, contains('Signatures: 1'));
      },
    );

    test('tampered content is failed and exits 1', () async {
      final r = await ades([
        'validate',
        '$_fx/signatures/negative/rsa2048-tampered-content.p7m',
        '-t',
        _root,
      ]);
      expect(r.code, ExitCode.failed);
      expect(r.out, contains('TOTAL-FAILED / HASH_FAILURE'));
    });

    test('unreadable signature is failed (FORMAT_FAILURE)', () async {
      final f = File('${tmp.path}/junk.p7m')..writeAsBytesSync([1, 2, 3]);
      final r = await ades(['validate', f.path]);
      expect(r.code, ExitCode.failed);
      expect(r.out, contains('FORMAT_FAILURE'));
    });

    test('a certificate option supplies the missing intermediate', () async {
      const neg = '$_fx/signatures/negative/rsa2048-missing-intermediate.p7m';
      final without = await ades(['validate', neg, '-t', _root]);
      expect(without.out, contains('NO_CERTIFICATE_CHAIN_FOUND'));
      final withIt = await ades([
        'validate',
        neg,
        '-t',
        _root,
        '-c',
        '$_fx/pki/rsa2048/intermediate.pem',
      ]);
      expect(withIt.out, isNot(contains('NO_CERTIFICATE_CHAIN_FOUND')));
    });

    test('detached signature validates with --document', () async {
      const p7s = '$_fx/signatures/positive/rsa2048-qsign.p7s';
      final ok = await ades([
        'validate',
        p7s,
        '-t',
        _root,
        '-d',
        '$_fx/content/hello.txt',
      ]);
      expect(ok.code, ExitCode.indeterminate);
      expect(ok.out, contains('CERTIFICATE_CHAIN_GENERAL_FAILURE'));
      final bad = await ades([
        'validate',
        p7s,
        '-t',
        _root,
        '-d',
        '$_fx/content/hello-tampered.txt',
      ]);
      expect(bad.code, ExitCode.failed);
      expect(bad.out, contains('HASH_FAILURE'));
      final none = await ades(['validate', p7s, '-t', _root]);
      expect(none.out, contains('SIGNED_DATA_NOT_FOUND'));
    });

    test('--report-json writes simple and detailed reports', () async {
      final path = '${tmp.path}/report.json';
      final r = await ades([
        'validate',
        _qsign,
        '-t',
        _root,
        '--report-json',
        path,
      ]);
      expect(r.code, ExitCode.indeterminate);
      final json = jsonDecode(File(path).readAsStringSync()) as Map;
      final simple = (json['simple'] as Map)['signatures'] as List;
      expect((simple.single as Map)['indication'], 'INDETERMINATE');
      final blocks =
          ((json['detailed'] as Map)['signatures'] as List).single as Map;
      expect(
        (blocks['blocks'] as List).map((b) => (b as Map)['block']),
        containsAll(['XCV', 'CV']),
      );
    });

    test('--report-json - writes to stdout', () async {
      final r = await ades([
        'validate',
        _qsign,
        '-t',
        _root,
        '--report-json',
        '-',
      ]);
      expect(r.out, contains('"detailed"'));
    });

    test('--validation-time sets the time (before leaf validity)', () async {
      final r = await ades([
        'validate',
        _qsign,
        '-t',
        _root,
        '--validation-time',
        '2022-01-01T00:00:00Z',
        '--ignore-revocation',
      ]);
      expect(r.out, contains('NOT_YET_VALID'));
    });

    test('--diagnostic-json writes the diagnostic data', () async {
      final path = '${tmp.path}/diag.json';
      final r = await ades([
        'validate',
        _qsign,
        '-t',
        _root,
        '--diagnostic-json',
        path,
      ]);
      expect(r.code, ExitCode.indeterminate);
      final json = jsonDecode(File(path).readAsStringSync()) as Map;
      expect(json['formatFailure'], isNull);
      expect(json['signatures'], hasLength(1));
      expect(json['certificates'], isNotEmpty);
    });

    test(
      '--ignore-revocation makes the positive fixture pass (exit 0)',
      () async {
        final r = await ades([
          'validate',
          _qsign,
          '-t',
          _root,
          '--ignore-revocation',
        ]);
        expect(r.code, ExitCode.ok, reason: r.out);
        expect(r.out, contains('TOTAL-PASSED'));
      },
    );

    test('--policy loads a policy JSON file', () async {
      final f = File('${tmp.path}/policy.json')
        ..writeAsStringSync('{"revocationDataAvailable":"ignore"}');
      final r = await ades([
        'validate',
        _qsign,
        '-t',
        _root,
        '--policy',
        f.path,
      ]);
      expect(r.code, ExitCode.ok, reason: r.out);
      final bad = File('${tmp.path}/bad.json')..writeAsStringSync('{"nope":1}');
      expect(
        (await ades(['validate', _qsign, '--policy', bad.path])).code,
        ExitCode.dataError,
      );
    });

    test('usage errors exit 64', () async {
      expect((await ades(['validate'])).code, ExitCode.usage);
      expect((await ades(['validate', _qsign, '--nope'])).code, ExitCode.usage);
      expect((await ades(['frobnicate'])).code, ExitCode.usage);
      expect((await ades([])).code, ExitCode.usage);
      expect(
        (await ades(['validate', _qsign, '--validation-time', 'x'])).code,
        ExitCode.usage,
      );
    });

    test('missing file exits 66, bad trust anchor exits 65', () async {
      expect(
        (await ades(['validate', '${tmp.path}/none'])).code,
        ExitCode.noInput,
      );
      final bad = File('${tmp.path}/bad.der')..writeAsBytesSync([1, 2, 3]);
      expect(
        (await ades(['validate', _qsign, '-t', bad.path])).code,
        ExitCode.dataError,
      );
    });
  });

  group('sign', () {
    const p12 = '$_fx/pki/rsa2048/leaf-qsign.p12';

    test(
      'signs with PKCS#12 after a password prompt; result validates',
      () async {
        final doc = File('$_fx/content/hello.txt').path;
        final out = '${tmp.path}/hello.p7m';
        final s = await ades(['sign', doc, '--p12', p12, '-o', out]);
        expect(s.code, ExitCode.ok, reason: s.err);
        expect(s.prompts, hasLength(1));
        final v = await ades([
          'validate',
          out,
          '-t',
          _root,
          '--ignore-revocation',
        ]);
        expect(v.out, contains('TOTAL-PASSED'));
        expect(v.out, contains('TESTSURNAME'));
      },
    );

    test('password file avoids the prompt', () async {
      final pw = File('${tmp.path}/pw')..writeAsStringSync('test\n');
      final out = '${tmp.path}/a.p7m';
      final s = await ades([
        'sign',
        '$_fx/content/hello.txt',
        '--p12',
        p12,
        '--p12-password-file',
        pw.path,
        '-o',
        out,
      ]);
      expect(s.code, ExitCode.ok, reason: s.err);
      expect(s.prompts, isEmpty);
    });

    test('default output is <file>.p7m and refuses to overwrite', () async {
      final doc = File('${tmp.path}/d.txt')..writeAsStringSync('x');
      expect((await ades(['sign', doc.path, '--p12', p12])).code, ExitCode.ok);
      expect(File('${doc.path}.p7m').existsSync(), isTrue);
      final again = await ades(['sign', doc.path, '--p12', p12]);
      expect(again.code, ExitCode.dataError);
      expect(again.err, contains('--force'));
      expect(
        (await ades(['sign', doc.path, '--p12', p12, '--force'])).code,
        ExitCode.ok,
      );
    });

    test('wrong password exits 65 and writes nothing', () async {
      final out = '${tmp.path}/w.p7m';
      final s = await ades([
        'sign',
        '$_fx/content/hello.txt',
        '--p12',
        p12,
        '-o',
        out,
      ], password: 'nope');
      expect(s.code, ExitCode.dataError);
      expect(s.err, contains('Wrong PKCS#12 password'));
      expect(File(out).existsSync(), isFalse);
    });

    test('usage errors exit 64', () async {
      final doc = '$_fx/content/hello.txt';
      expect((await ades(['sign', doc])).code, ExitCode.usage);
      expect((await ades(['sign', '--p12', p12])).code, ExitCode.usage);
    });

    test('missing document exits 66', () async {
      expect(
        (await ades(['sign', '${tmp.path}/none', '--p12', p12])).code,
        ExitCode.noInput,
      );
    });

    test(
      '--detached signs a detached .p7s that validates with --document',
      () async {
        final doc = '$_fx/content/hello.txt';
        final out = '${tmp.path}/hello.p7s';
        final r = await ades([
          'sign',
          doc,
          '--p12',
          p12,
          '--detached',
          '-o',
          out,
        ]);
        expect(r.code, ExitCode.ok, reason: r.err);
        final v = await ades([
          'validate',
          out,
          '-t',
          _root,
          '-d',
          doc,
          '--ignore-revocation',
        ]);
        expect(v.out, contains('TOTAL-PASSED'));
        expect(v.out, isNot(contains('HASH_FAILURE')));
        final bad = await ades([
          'validate',
          out,
          '-t',
          _root,
          '-d',
          '$_fx/content/hello-tampered.txt',
        ]);
        expect(bad.code, ExitCode.failed);
      },
    );

    test('signs with an ECDSA P-256 PKCS#12', () async {
      final out = '${tmp.path}/ec.p7m';
      final r = await ades([
        'sign',
        '$_fx/content/hello.txt',
        '--p12',
        '$_fx/pki/p256/leaf-qsign.p12',
        '-o',
        out,
      ]);
      expect(r.code, ExitCode.ok, reason: r.err);
      final v = await ades([
        'validate',
        out,
        '-t',
        '$_fx/pki/p256/root.pem',
        '--ignore-revocation',
      ]);
      expect(v.out, contains('TOTAL-PASSED'));
    });

    test('a signing credential from the registry is required', () {
      expect(CredentialSource.registry, isNotEmpty);
    });
  });
}
