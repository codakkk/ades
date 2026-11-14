// Seam 3 (spec): ades_pkcs11 public API against SoftHSM2, results validated
// by the core. Needs SOFTHSM2_CONF (a conf with a writable token dir),
// ADES_PKCS11_MODULE (path of libsofthsm2) and softhsm2-util + pkcs11-tool on
// PATH. Locally: tool/test_in_docker.sh. Skipped when ADES_PKCS11_MODULE is
// unset, unless ADES_PKCS11_REQUIRED is set (CI), which makes it a failure.
@TestOn('vm')
library;

import 'dart:async';
import 'dart:io';
import 'dart:isolate';
import 'dart:typed_data';

import 'package:ades/ades.dart';
import 'package:ades_pkcs11/ades_pkcs11.dart';
import 'package:test/test.dart';

const _pin = '1234';
const _soPin = '5678';

final _module = Platform.environment['ADES_PKCS11_MODULE'];
final _required = Platform.environment['ADES_PKCS11_REQUIRED'] != null;

final _tier1 = Directory('../../fixtures/tier1').absolute.path;
Uint8List _fixture(String p) => File('$_tier1/$p').readAsBytesSync();

String get _modulePath => _module!;

void _run(String exe, List<String> args) {
  final r = Process.runSync(exe, args);
  if (r.exitCode != 0) {
    throw StateError(
      '$exe ${args.join(' ')} failed:\n${r.stdout}\n${r.stderr}',
    );
  }
}

/// Fresh token with one imported key + certificate.
void _makeToken(String label, String leaf, String id, String credLabel) {
  _run('softhsm2-util', [
    '--init-token', '--free', '--label', label,
    '--so-pin', _soPin, '--pin', _pin, //
  ]);
  _run('softhsm2-util', [
    '--import', '$_tier1/pki/rsa2048/$leaf.key', '--token', label,
    '--label', credLabel, '--id', id, '--pin', _pin, //
  ]);
  _run('pkcs11-tool', [
    '--module', _modulePath, '--token-label', label, '--login', '--pin', _pin,
    '--write-object', '$_tier1/pki/rsa2048/$leaf.der', '--type', 'cert',
    '--label', credLabel, '--id', id, //
  ]);
}

/// Fresh token whose private key has CKA_ALWAYS_AUTHENTICATE=true: every
/// signature needs a context-specific login right before C_Sign.
void _makeAlwaysAuthToken(String label, String leaf, String id, String name) {
  _run('softhsm2-util', [
    '--init-token', '--free', '--label', label,
    '--so-pin', _soPin, '--pin', _pin, //
  ]);
  _run('pkcs11-tool', [
    '--module', _modulePath, '--token-label', label, '--login', '--pin', _pin,
    '--write-object', '$_tier1/pki/rsa2048/$leaf.key', '--type', 'privkey',
    '--usage-sign', '--always-auth', '--label', name, '--id', id, //
  ]);
  _run('pkcs11-tool', [
    '--module', _modulePath, '--token-label', label, '--login', '--pin', _pin,
    '--write-object', '$_tier1/pki/rsa2048/$leaf.der', '--type', 'cert',
    '--label', name, '--id', id, //
  ]);
}

Future<String?> _goodPin(PinRequest _) async => _pin;

Future<Pkcs11Credential> _qsign(Pkcs11Module m) async =>
    (await m.listCredentials()).singleWhere((c) => c.label == 'qsign');

void main() {
  if (_module == null) {
    test('SoftHSM2 tests', () {
      if (_required) fail('ADES_PKCS11_MODULE is not set');
    }, skip: _required ? false : 'ADES_PKCS11_MODULE not set');
    return;
  }

  test(
    'discovery loads the real module and reports a broken library',
    () async {
      final dir = Directory.systemTemp.createTempSync('ades_disc');
      addTearDown(() => dir.deleteSync(recursive: true));
      final broken = File('${dir.path}/libbroken.so')
        ..writeAsStringSync('not an ELF');
      final r = await discoverPkcs11Modules(
        includeKnown: false,
        candidates: [
          MiddlewareCandidate(name: 'SoftHSM', path: _modulePath),
          MiddlewareCandidate(name: 'Broken', path: broken.path),
          const MiddlewareCandidate(name: 'Missing', path: '/nope/lib.so'),
        ],
      );
      expect(r.foundPaths, [_modulePath]);
      expect(r.failed.single.candidate.name, 'Broken');
      expect(r.failed.single.reason, isNotEmpty);
      expect(r.absent.single.name, 'Missing');
    },
  );

  final stamp = DateTime.now().microsecondsSinceEpoch;
  final tokenA = 'ades-a-$stamp';
  final tokenB = 'ades-b-$stamp';
  final tokenAlways = 'ades-always-$stamp';

  setUpAll(() {
    _makeToken(tokenA, 'leaf-qsign', '0a', 'qsign');
    _makeToken(tokenB, 'leaf-auth', '0b', 'auth');
    _makeAlwaysAuthToken(tokenAlways, 'leaf-qsign', '0c', 'always');
  });

  late Pkcs11Module module;
  final opened = <Pkcs11Module>[];

  Future<Pkcs11Module> open({
    PinCallback onPin = _goodPin,
    Duration delay = Duration.zero,
  }) async {
    final m = await Pkcs11Module.load(
      _modulePath,
      onPin: onPin,
      debugBlockingDelay: delay,
    );
    opened.add(m);
    return m;
  }

  tearDown(() async {
    for (final m in opened) {
      await m.close();
    }
    opened.clear();
  });

  test('loading a path that is not a PKCS#11 module is a typed error', () {
    expect(
      Pkcs11Module.load('/nonexistent/libnope.so', onPin: _goodPin),
      throwsA(isA<Pkcs11ModuleLoadException>()),
    );
  });

  test(
    'lists credentials across slots with label, usage and certificate',
    () async {
      module = await open();
      final creds = await module.listCredentials();
      final mine = creds.where(
        (c) => c.tokenLabel == tokenA || c.tokenLabel == tokenB,
      );
      expect(mine.map((c) => c.label).toSet(), {'qsign', 'auth'});
      final q = mine.singleWhere((c) => c.label == 'qsign');
      final a = mine.singleWhere((c) => c.label == 'auth');
      expect(q.slotId, isNot(a.slotId));
      expect(q.keyUsage, {Pkcs11KeyUsage.nonRepudiation});
      expect(a.keyUsage, {Pkcs11KeyUsage.digitalSignature});
      expect(await q.certificate, _fixture('pki/rsa2048/leaf-qsign.der'));
    },
  );

  test('advertises SHA-256 only (new signatures use nothing else)', () async {
    module = await open();
    final cred = await _qsign(module);
    expect(cred.supportedAlgorithms, [SignatureAlgorithm.rsaPkcs1v15Sha256]);
  });

  test('signs through the card; the core validates the result', () async {
    module = await open();
    final cred = await _qsign(module);
    final doc = _fixture('content/hello.txt');
    final draft = await Cades.prepareEnveloping(
      document: doc,
      credential: cred,
    );
    final value = await cred.sign(await draft.signRequest());
    final p7m = await Cades.complete(draft: draft, value: value, document: doc);
    final report = await Validator(
      trustAnchors: [
        TrustAnchor.fromDer(_fixture('pki/rsa2048/leaf-qsign.der')),
      ],
    ).validate(p7m);
    final d = report.detailed.signatures.single;
    for (final b in [
      BuildingBlock.formatChecking,
      BuildingBlock.identificationOfSigningCertificate,
      BuildingBlock.cryptographicVerification,
      BuildingBlock.signatureAcceptanceValidation,
    ]) {
      expect(d.result(b)!.indication, BlockIndication.passed, reason: '$b');
    }
  });

  group('CKA_ALWAYS_AUTHENTICATE key (qualified CNS keys)', () {
    Future<Pkcs11Credential> always(Pkcs11Module m) async =>
        (await m.listCredentials()).singleWhere(
          (c) => c.tokenLabel == tokenAlways,
        );

    test(
      'every signature asks for the PIN again, right before C_Sign',
      () async {
        final requests = <PinRequest>[];
        module = await open(
          onPin: (r) async {
            requests.add(r);
            return _pin;
          },
        );
        final cred = await always(module);
        final doc = _fixture('content/hello.txt');
        final draft = await Cades.prepareEnveloping(
          document: doc,
          credential: cred,
        );
        final value = await cred.sign(await draft.signRequest());
        final p7m = await Cades.complete(
          draft: draft,
          value: value,
          document: doc,
        );
        // User login once, then one context-specific login per signature.
        expect(requests.map((r) => r.forSignature), [false, true]);
        await cred.sign(_request());
        expect(requests.map((r) => r.forSignature), [false, true, true]);
        final report = await Validator(
          trustAnchors: [
            TrustAnchor.fromDer(_fixture('pki/rsa2048/leaf-qsign.der')),
          ],
        ).validate(p7m);
        expect(
          report.detailed.signatures.single
              .result(BuildingBlock.cryptographicVerification)!
              .indication,
          BlockIndication.passed,
        );
      },
    );

    test('a wrong signing PIN is a typed error; cancelling too', () async {
      var answer = _pin;
      module = await open(onPin: (r) async => r.forSignature ? answer : _pin);
      final cred = await always(module);
      answer = '0000';
      await expectLater(
        cred.sign(_request()),
        throwsA(isA<Pkcs11WrongPinException>()),
      );
      answer = _pin;
      expect((await cred.sign(_request())).bytes, hasLength(256));
      module = await open(onPin: (r) async => r.forSignature ? null : _pin);
      await expectLater(
        (await always(module)).sign(_request()),
        throwsA(isA<Pkcs11PinCancelledException>()),
      );
    });

    test('a key without the attribute never gets a signing prompt', () async {
      final requests = <PinRequest>[];
      module = await open(
        onPin: (r) async {
          requests.add(r);
          return _pin;
        },
      );
      final cred = await _qsign(module);
      await cred.sign(_request());
      await cred.sign(_request());
      expect(requests.where((r) => r.forSignature), isEmpty);
    });
  });

  test('PIN is asked on the caller isolate, once per token', () async {
    final callerPort = Isolate.current.controlPort;
    final requests = <PinRequest>[];
    var onCaller = true;
    module = await open(
      onPin: (r) async {
        requests.add(r);
        onCaller &= Isolate.current.controlPort == callerPort;
        return _pin;
      },
    );
    final cred = await _qsign(module);
    for (var i = 0; i < 2; i++) {
      await cred.sign(_request());
    }
    expect(onCaller, isTrue);
    expect(requests, hasLength(1));
    expect(requests.single.tokenLabel, tokenA);
    expect(requests.single.credentialLabel, 'qsign');
    expect(requests.single.forSignature, isFalse);
  });

  test('wrong PIN is a typed error and a later correct PIN works', () async {
    var attempt = 0;
    module = await open(onPin: (_) async => attempt++ == 0 ? '0000' : _pin);
    final cred = await _qsign(module);
    await expectLater(
      cred.sign(_request()),
      throwsA(isA<Pkcs11WrongPinException>()),
    );
    expect((await cred.sign(_request())).bytes, hasLength(256));
  });

  test('cancelling the PIN prompt is a typed error', () async {
    module = await open(onPin: (_) async => null);
    final cred = await _qsign(module);
    await expectLater(
      cred.sign(_request()),
      throwsA(isA<Pkcs11PinCancelledException>()),
    );
  });

  test('a throwing PIN callback is a typed error', () async {
    module = await open(onPin: (_) async => throw StateError('dialog died'));
    final cred = await _qsign(module);
    await expectLater(
      cred.sign(_request()),
      throwsA(isA<Pkcs11PinCallbackException>()),
    );
  });

  test(
    'the caller event loop keeps running during C_Login and C_Sign',
    () async {
      // The worker blocks 600 ms inside the login and 600 ms inside the sign
      // (debugBlockingDelay is a real blocking sleep on the worker isolate).
      // A 10 ms ticker on this isolate must not stall.
      const delay = Duration(milliseconds: 600);
      module = await open(delay: delay);
      final cred = await _qsign(module);

      final ticks = <int>[];
      final sw = Stopwatch()..start();
      final timer = Timer.periodic(const Duration(milliseconds: 10), (_) {
        ticks.add(sw.elapsedMilliseconds);
      });
      await cred.sign(_request());
      timer.cancel();
      final total = sw.elapsedMilliseconds;

      expect(total, greaterThanOrEqualTo(1200), reason: 'login + sign blocked');
      expect(ticks.length, greaterThan(60));
      var maxGap = ticks.first;
      for (var i = 1; i < ticks.length; i++) {
        final g = ticks[i] - ticks[i - 1];
        if (g > maxGap) maxGap = g;
      }
      expect(ticks.last, greaterThan(total - 200));
      expect(maxGap, lessThan(150), reason: 'event loop stalled');
    },
  );

  test('close releases everything; calls after close are typed errors; '
      'the module can be loaded again', () async {
    final m = await Pkcs11Module.load(_modulePath, onPin: _goodPin);
    final cred = await _qsign(m);
    await cred.sign(_request());
    await m.close();
    await m.close(); // idempotent
    await expectLater(
      m.listCredentials(),
      throwsA(isA<Pkcs11ClosedException>()),
    );
    await expectLater(
      cred.sign(_request()),
      throwsA(isA<Pkcs11ClosedException>()),
    );
    // C_Finalize ran: a fresh load + login works.
    final again = await open();
    expect((await (await _qsign(again)).sign(_request())).bytes, isNotEmpty);
  });

  test('close while a sign is in flight waits for it, then releases', () async {
    final m = await open(delay: const Duration(milliseconds: 300));
    final cred = await _qsign(m);
    final inFlight = cred.sign(_request());
    await Future<void>.delayed(const Duration(milliseconds: 100));
    await m.close();
    expect((await inFlight).bytes, hasLength(256));
    await expectLater(
      cred.sign(_request()),
      throwsA(isA<Pkcs11ClosedException>()),
    );
  });

  test(
    'a cancelled PIN prompt leaves the module usable and closable',
    () async {
      var cancel = true;
      final m = await open(onPin: (_) async => cancel ? null : _pin);
      final cred = await _qsign(m);
      await expectLater(
        cred.sign(_request()),
        throwsA(isA<Pkcs11PinCancelledException>()),
      );
      cancel = false;
      expect((await cred.sign(_request())).bytes, hasLength(256));
    },
  );
}

SignRequest _request() {
  final dtbs = Uint8List.fromList([1, 2, 3]);
  // dtbsr is just a digest-sized blob for the device here.
  return SignRequest(
    dtbs: dtbs,
    dtbsr: Uint8List(32)..fillRange(0, 32, 7),
    signatureAlgorithm: const SignatureAlgorithm(
      SignatureScheme.rsaPkcs1v15,
      DigestAlgorithm.sha256,
    ),
  );
}
