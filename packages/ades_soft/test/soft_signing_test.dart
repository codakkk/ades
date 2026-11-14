// Seam 1 with a real key store: ades_soft signs over the tier-1 keys, our
// validator checks the result, and OpenSSL 3 is the independent check.
@TestOn('vm')
library;

import 'dart:io';
import 'dart:typed_data';

import 'package:ades/ades.dart';
import 'package:ades_soft/ades_soft.dart';
import 'package:test/test.dart';

final _fixtures = Directory('../../fixtures/tier1');

Uint8List _bytes(String path) =>
    File('${_fixtures.path}/$path').readAsBytesSync();
String _text(String path) => File('${_fixtures.path}/$path').readAsStringSync();

final _openssl = () {
  final env = Platform.environment['OPENSSL'];
  for (final c in [
    ?env,
    '/opt/homebrew/opt/openssl@3/bin/openssl',
    '/usr/local/opt/openssl@3/bin/openssl',
    'openssl',
  ]) {
    try {
      final r = Process.runSync(c, ['version']);
      if (r.exitCode == 0 && (r.stdout as String).startsWith('OpenSSL 3')) {
        return c;
      }
    } on ProcessException {
      continue;
    }
  }
  return null;
}();

SoftSigningCredential _fromP12(String name) => SoftSigningCredential.fromPkcs12(
  _bytes('pki/rsa2048/$name.p12'),
  password: 'test',
);

Future<Uint8List> _sign(SoftSigningCredential c, Uint8List doc) async {
  final draft = await Cades.prepareEnveloping(document: doc, credential: c);
  final value = await c.sign(await draft.signRequest());
  return Cades.complete(draft: draft, value: value, document: doc);
}

void main() {
  final doc = _bytes('content/hello.txt');

  group('PKCS#12 credential', () {
    test(
      'signs; our validator accepts it (signer is the trust anchor)',
      () async {
        final p7m = await _sign(_fromP12('leaf-qsign'), doc);
        final v = Validator(
          trustAnchors: [
            TrustAnchor.fromDer(_bytes('pki/rsa2048/leaf-qsign.der')),
          ],
        );
        final d = (await v.validate(p7m)).detailed.signatures.single;
        expect(
          d.result(BuildingBlock.cryptographicVerification)!.indication,
          BlockIndication.passed,
        );
        expect(
          d
              .result(BuildingBlock.identificationOfSigningCertificate)!
              .indication,
          BlockIndication.passed,
        );
        expect(d.indication, Indication.totalPassed);
      },
    );

    test('exposes leaf and chain from the file', () async {
      final c = _fromP12('leaf-qsign');
      expect(await c.certificate, _bytes('pki/rsa2048/leaf-qsign.der'));
      expect(await c.chain, [_bytes('pki/rsa2048/intermediate.der')]);
    });

    test('works for the authentication leaf too', () async {
      final p7m = await _sign(_fromP12('leaf-auth'), doc);
      final v = Validator(
        trustAnchors: [
          TrustAnchor.fromDer(_bytes('pki/rsa2048/leaf-auth.der')),
        ],
      );
      final d = (await v.validate(p7m)).detailed.signatures.single;
      expect(
        d.result(BuildingBlock.cryptographicVerification)!.indication,
        BlockIndication.passed,
      );
    });

    test('wrong password is a typed error', () {
      expect(
        () => SoftSigningCredential.fromPkcs12(
          _bytes('pki/rsa2048/leaf-qsign.p12'),
          password: 'nope',
        ),
        throwsA(
          isA<SoftKeyLoadException>().having(
            (e) => e.failure,
            'failure',
            SoftKeyLoadFailure.wrongPassword,
          ),
        ),
      );
    });

    test('garbage is a typed error', () {
      expect(
        () => SoftSigningCredential.fromPkcs12(
          Uint8List.fromList([1, 2, 3]),
          password: 'test',
        ),
        throwsA(
          isA<SoftKeyLoadException>().having(
            (e) => e.failure,
            'failure',
            SoftKeyLoadFailure.malformed,
          ),
        ),
      );
    });
  });

  group('PEM credential', () {
    test('loads key plus certificates and signs', () async {
      final c = SoftSigningCredential.fromPem(
        privateKeyPem: _text('pki/rsa2048/leaf-qsign.key'),
        certificatesPem:
            _text('pki/rsa2048/intermediate.pem') +
            _text('pki/rsa2048/leaf-qsign.pem'),
      );
      expect(await c.certificate, _bytes('pki/rsa2048/leaf-qsign.der'));
      final p7m = await _sign(c, doc);
      final r = await Validator(
        trustAnchors: [
          TrustAnchor.fromDer(_bytes('pki/rsa2048/leaf-qsign.der')),
        ],
      ).validate(p7m);
      expect(
        r.detailed.signatures.single
            .result(BuildingBlock.cryptographicVerification)!
            .indication,
        BlockIndication.passed,
      );
    });

    test('a key with no matching certificate is refused', () {
      expect(
        () => SoftSigningCredential.fromPem(
          privateKeyPem: _text('pki/rsa2048/leaf-qsign.key'),
          certificatesPem: _text('pki/rsa2048/leaf-auth.pem'),
        ),
        throwsA(
          isA<SoftKeyLoadException>().having(
            (e) => e.failure,
            'failure',
            SoftKeyLoadFailure.incomplete,
          ),
        ),
      );
    });
  });

  group('creation policy with a real credential', () {
    test('SHA-1 refused before sign', () async {
      await expectLater(
        Cades.prepareEnveloping(
          document: doc,
          credential: _fromP12('leaf-qsign'),
          algorithm: const SignatureAlgorithm(
            SignatureScheme.rsaPkcs1v15,
            DigestAlgorithm.sha1,
          ),
        ),
        throwsA(isA<WeakDigestException>()),
      );
    });

    test('RSA-1024 certificate refused', () async {
      final ossl = _openssl;
      if (ossl == null) markTestSkipped('OpenSSL 3 not found');
      if (ossl == null) return;
      final dir = Directory.systemTemp.createTempSync('ades_soft_weak');
      addTearDown(() => dir.deleteSync(recursive: true));
      final r = Process.runSync(ossl, [
        'req',
        '-x509',
        '-newkey',
        'rsa:1024',
        '-nodes',
        '-days',
        '30',
        '-subj',
        '/CN=weak',
        '-keyout',
        '${dir.path}/k.pem',
        '-out',
        '${dir.path}/c.pem',
      ]);
      expect(r.exitCode, 0, reason: '${r.stderr}');
      final c = SoftSigningCredential.fromPem(
        privateKeyPem: File('${dir.path}/k.pem').readAsStringSync(),
        certificatesPem: File('${dir.path}/c.pem').readAsStringSync(),
      );
      await expectLater(
        Cades.prepareEnveloping(document: doc, credential: c),
        throwsA(isA<WeakKeyException>()),
      );
    });
  });

  test('OpenSSL 3 verifies the signature and extracts the content', () async {
    final ossl = _openssl;
    if (ossl == null) {
      markTestSkipped('OpenSSL 3 not found');
      return;
    }
    final dir = Directory.systemTemp.createTempSync('ades_soft_cms');
    addTearDown(() => dir.deleteSync(recursive: true));
    final p7m = await _sign(_fromP12('leaf-qsign'), doc);
    File('${dir.path}/s.p7m').writeAsBytesSync(p7m);
    final r = Process.runSync(ossl, [
      'cms',
      '-verify',
      '-inform',
      'DER',
      '-in',
      '${dir.path}/s.p7m',
      '-CAfile',
      '${_fixtures.path}/pki/rsa2048/root.pem',
      '-purpose',
      'any',
      '-out',
      '${dir.path}/out.txt',
    ]);
    expect(r.exitCode, 0, reason: '${r.stderr}');
    expect(File('${dir.path}/out.txt').readAsBytesSync(), doc);
    // The signature is DER: OpenSSL can dump it without complaint.
    final p = Process.runSync(ossl, [
      'asn1parse',
      '-inform',
      'DER',
      '-in',
      '${dir.path}/s.p7m',
    ]);
    expect(p.exitCode, 0);
  });

  group('P-256 credential and detached signing', () {
    SoftSigningCredential p256() => SoftSigningCredential.fromPkcs12(
      _bytes('pki/p256/leaf-qsign.p12'),
      password: 'test',
    );
    const ecdsa = SignatureAlgorithm(
      SignatureScheme.ecdsa,
      DigestAlgorithm.sha256,
    );
    final v = Validator(
      trustAnchors: [TrustAnchor.fromDer(_bytes('pki/p256/root.der'))],
    );

    test('PKCS#12 loads; enveloping and detached validate with us', () async {
      final c = p256();
      expect(await c.certificate, _bytes('pki/p256/leaf-qsign.der'));
      final p7m = await Cades.sign(
        document: doc,
        credential: c,
        algorithm: ecdsa,
      );
      var r = Validator.decide(
        await v.collect(p7m),
        validationTime: DateTime.utc(2026, 11, 9),
      );
      expect(
        r.detailed.signatures.single
            .result(BuildingBlock.cryptographicVerification)!
            .indication,
        BlockIndication.passed,
      );
      final p7s = await Cades.sign(
        document: doc,
        credential: c,
        algorithm: ecdsa,
        detached: true,
      );
      r = Validator.decide(
        await v.collect(p7s, detachedContent: doc),
        validationTime: DateTime.utc(2026, 11, 9),
      );
      expect(
        r.detailed.signatures.single
            .result(BuildingBlock.cryptographicVerification)!
            .indication,
        BlockIndication.passed,
      );
    });

    test('PEM (PKCS#8) loads', () async {
      final c = SoftSigningCredential.fromPem(
        privateKeyPem: _text('pki/p256/leaf-qsign.key'),
        certificatesPem: _text('pki/p256/leaf-qsign.pem'),
      );
      expect(await c.certificate, _bytes('pki/p256/leaf-qsign.der'));
      expect(c.supportedAlgorithms, contains(ecdsa));
    });

    test('OpenSSL 3 verifies ECDSA p7m and detached p7s', () async {
      final ossl = _openssl;
      if (ossl == null) {
        markTestSkipped('OpenSSL 3 not found');
        return;
      }
      final dir = Directory.systemTemp.createTempSync('ades_soft_ec');
      addTearDown(() => dir.deleteSync(recursive: true));
      final c = p256();
      File('${dir.path}/d.txt').writeAsBytesSync(doc);
      for (final detached in [false, true]) {
        final sig = await Cades.sign(
          document: doc,
          credential: c,
          algorithm: ecdsa,
          detached: detached,
        );
        File('${dir.path}/s.der').writeAsBytesSync(sig);
        final r = Process.runSync(ossl, [
          'cms',
          '-verify',
          '-inform',
          'DER',
          '-in',
          '${dir.path}/s.der',
          if (detached) ...['-binary', '-content', '${dir.path}/d.txt'],
          '-CAfile',
          '${_fixtures.path}/pki/p256/root.pem',
          '-purpose',
          'any',
          '-out',
          '${dir.path}/out.txt',
        ]);
        expect(r.exitCode, 0, reason: 'detached=$detached ${r.stderr}');
      }
    });

    test('RSA detached verifies with OpenSSL 3', () async {
      final ossl = _openssl;
      if (ossl == null) {
        markTestSkipped('OpenSSL 3 not found');
        return;
      }
      final dir = Directory.systemTemp.createTempSync('ades_soft_rsad');
      addTearDown(() => dir.deleteSync(recursive: true));
      File('${dir.path}/d.txt').writeAsBytesSync(doc);
      File('${dir.path}/s.der').writeAsBytesSync(
        await Cades.sign(
          document: doc,
          credential: _fromP12('leaf-qsign'),
          detached: true,
        ),
      );
      final r = Process.runSync(ossl, [
        'cms',
        '-verify',
        '-inform',
        'DER',
        '-in',
        '${dir.path}/s.der',
        '-binary',
        '-content',
        '${dir.path}/d.txt',
        '-CAfile',
        '${_fixtures.path}/pki/rsa2048/root.pem',
        '-purpose',
        'any',
        '-out',
        '${dir.path}/out.txt',
      ]);
      expect(r.exitCode, 0, reason: '${r.stderr}');
    });
  });
}
