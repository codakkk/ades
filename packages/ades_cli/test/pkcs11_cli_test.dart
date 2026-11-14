// `ades sign --pkcs11` against SoftHSM2 with two credentials on one token.
// Needs SOFTHSM2_CONF, ADES_PKCS11_MODULE, softhsm2-util and pkcs11-tool; run
// with tool/test_pkcs11_in_docker.sh. The token-based tests are skipped when
// ADES_PKCS11_MODULE is unset, unless ADES_PKCS11_REQUIRED is set.
@TestOn('vm')
library;

import 'dart:io';

import 'package:ades_cli/ades_cli.dart';
import 'package:test/test.dart';

const _pin = '1234';
const _soPin = '5678';
const _fx = '../../fixtures/tier1';
final _tier1 = Directory(_fx).absolute.path;
const _root = '$_fx/pki/rsa2048/root.pem';

final _module = Platform.environment['ADES_PKCS11_MODULE'];
final _required = Platform.environment['ADES_PKCS11_REQUIRED'] != null;

final class Run {
  Run(this.code, this.out, this.err, this.pinPrompts, this.linePrompts);
  final int code;
  final String out;
  final String err;
  final List<String> pinPrompts;
  final List<String> linePrompts;
}

Future<Run> ades(
  List<String> args, {
  String pin = _pin,
  List<String> answers = const [],
  bool interactive = true,
}) async {
  final out = StringBuffer();
  final err = StringBuffer();
  final pins = <String>[];
  final lines = <String>[];
  final queue = [...answers];
  final code = await runCli(
    args,
    env: CliEnvironment(
      out: out,
      err: err,
      promptPassword: (m) async {
        pins.add(m);
        return pin;
      },
      promptLine: interactive
          ? (m) async {
              lines.add(m);
              return queue.isEmpty ? '' : queue.removeAt(0);
            }
          : null,
    ),
  );
  return Run(code, '$out', '$err', pins, lines);
}

void _run(String exe, List<String> args) {
  final r = Process.runSync(exe, args);
  if (r.exitCode != 0) {
    throw StateError('$exe ${args.join(' ')} failed:\n${r.stdout}${r.stderr}');
  }
}

void _addCredential(String token, String leaf, String id, String label) {
  _run('softhsm2-util', [
    '--import', '$_tier1/pki/rsa2048/$leaf.key', '--token', token,
    '--label', label, '--id', id, '--pin', _pin, //
  ]);
  _run('pkcs11-tool', [
    '--module', _module!, '--token-label', token, '--login', '--pin', _pin,
    '--write-object', '$_tier1/pki/rsa2048/$leaf.der', '--type', 'cert',
    '--label', label, '--id', id, //
  ]);
}

void main() {
  late Directory tmp;
  setUp(() => tmp = Directory.systemTemp.createTempSync('ades_cli_p11'));
  tearDown(() => tmp.deleteSync(recursive: true));

  group('option handling (no token needed)', () {
    test(
      'a missing module is a data error (65) with a clear message',
      () async {
        final doc = File('${tmp.path}/doc.txt')..writeAsStringSync('hello');
        final r = await ades(['sign', doc.path, '--pkcs11', '/nope/lib.so']);
        expect(r.code, ExitCode.dataError);
        expect(r.err, contains('Cannot load PKCS#11 module'));
        expect(r.pinPrompts, isEmpty);
      },
    );

    test('--pkcs11 together with --p12 is a usage error', () async {
      final doc = File('${tmp.path}/doc.txt')..writeAsStringSync('hello');
      final r = await ades([
        'sign', doc.path, '--pkcs11', '/x', '--p12', 'k.p12', //
      ]);
      expect(r.code, ExitCode.usage);
    });
  });

  if (_module == null) {
    test('SoftHSM2 tests', () {
      if (_required) fail('ADES_PKCS11_MODULE is not set');
    }, skip: _required ? false : 'ADES_PKCS11_MODULE not set');
    return;
  }

  final token = 'ades-cli-${DateTime.now().microsecondsSinceEpoch}';
  setUpAll(() {
    _run('softhsm2-util', [
      '--init-token', '--free', '--label', token,
      '--so-pin', _soPin, '--pin', _pin, //
    ]);
    _addCredential(token, 'leaf-qsign', '0a', 'qsign');
    _addCredential(token, 'leaf-auth', '0b', 'auth');
  });

  Future<Run> validate(String sig, String doc) => ades([
    'validate', sig, '-t', _root, '--ignore-revocation', //
    // The card holds only the leaf; the intermediate comes from outside.
    '-c', '$_fx/pki/rsa2048/intermediate.pem',
  ]);

  test('--pkcs11-credential picks one; PIN comes from the hidden prompt; '
      'the signature validates', () async {
    final doc = File('${tmp.path}/doc.txt')..writeAsStringSync('hello cns');
    final out = '${tmp.path}/doc.p7m';
    final r = await ades([
      'sign', doc.path, '--pkcs11', _module!, //
      '--pkcs11-credential', 'qsign', '-o', out,
    ]);
    expect(r.err, isNot(contains(_pin)));
    expect(r.code, ExitCode.ok, reason: r.err);
    expect(r.pinPrompts, hasLength(1));
    expect(r.pinPrompts.single, contains(token));
    expect(r.linePrompts, isEmpty);
    final v = await validate(out, doc.path);
    expect(v.code, ExitCode.ok, reason: v.out);
    expect(v.out, contains('TOTAL-PASSED'));
  });

  test('without a flag both credentials are listed and the user picks '
      'by number', () async {
    final doc = File('${tmp.path}/doc.txt')..writeAsStringSync('hello cns');
    final a = '${tmp.path}/a.p7m';
    final b = '${tmp.path}/b.p7m';
    final r1 = await ades(
      [
        'sign', doc.path, '--pkcs11', _module!, '-o', a, //
      ],
      answers: ['1'],
    );
    final r2 = await ades(
      [
        'sign', doc.path, '--pkcs11', _module!, '-o', b, //
      ],
      answers: ['nonsense', '2'],
    );
    for (final r in [r1, r2]) {
      expect(r.code, ExitCode.ok, reason: r.err);
      expect(r.err, contains('qsign'));
      expect(r.err, contains('auth'));
      expect(r.err, contains('nonRepudiation'));
      expect(r.err, contains('digitalSignature'));
    }
    expect(r2.err, contains('Not a valid choice'));
    // Different credentials: different signer certificates.
    final va = await validate(a, doc.path);
    final vb = await validate(b, doc.path);
    expect(va.code, ExitCode.ok, reason: va.out);
    expect(vb.code, ExitCode.ok, reason: vb.out);
    // The list is sorted by token and label: 1 = auth, 2 = qsign.
    expect(va.out, contains('(authentication)'));
    expect(vb.out, contains('(qualified signing)'));
  });

  test(
    'without a terminal and without a flag it refuses, listing both',
    () async {
      final doc = File('${tmp.path}/doc.txt')..writeAsStringSync('hello cns');
      final r = await ades([
        'sign', doc.path, '--pkcs11', _module!, //
      ], interactive: false);
      expect(r.code, ExitCode.dataError);
      expect(r.err, contains('--pkcs11-credential'));
      expect(r.err, contains('qsign'));
      expect(r.err, contains('auth'));
      expect(r.pinPrompts, isEmpty);
    },
  );

  test('an unknown credential name is refused and lists the options', () async {
    final doc = File('${tmp.path}/doc.txt')..writeAsStringSync('hello cns');
    final r = await ades([
      'sign', doc.path, '--pkcs11', _module!, '--pkcs11-credential', 'zzz', //
    ]);
    expect(r.code, ExitCode.dataError);
    expect(r.err, contains('qsign'));
  });

  test('a wrong PIN exits 65 and writes no file', () async {
    final doc = File('${tmp.path}/doc.txt')..writeAsStringSync('hello cns');
    final out = '${tmp.path}/bad.p7m';
    final r = await ades([
      'sign', doc.path, '--pkcs11', _module!, //
      '--pkcs11-credential', '1', '-o', out,
    ], pin: '0000');
    expect(r.code, ExitCode.dataError);
    expect(r.err.toLowerCase(), contains('pin'));
    expect(File(out).existsSync(), isFalse);
  });
}
