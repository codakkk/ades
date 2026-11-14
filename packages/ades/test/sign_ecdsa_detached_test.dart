// Ticket 10: detached and ECDSA signing, one-call sign, batch, KU refusal.
import 'dart:typed_data';

import 'package:ades/ades.dart';
import 'package:test/test.dart';

import 'support/test_credential.dart';
import 'support/tier1.dart';

Uint8List _doc() => tier1('content/hello.txt');

const _ecdsa256 = SignatureAlgorithm(
  SignatureScheme.ecdsa,
  DigestAlgorithm.sha256,
);

Validator _p256() =>
    Validator(trustAnchors: [TrustAnchor.fromDer(tier1('pki/p256/root.der'))]);

Validator _rsa() => Validator(
  trustAnchors: [TrustAnchor.fromDer(tier1('pki/rsa2048/leaf-qsign.der'))],
);

void _expectCryptoOk(ValidationReport r) {
  final d = r.detailed.signatures.single;
  for (final b in [
    BuildingBlock.formatChecking,
    BuildingBlock.identificationOfSigningCertificate,
    BuildingBlock.cryptographicVerification,
  ]) {
    expect(d.result(b)!.indication, BlockIndication.passed, reason: '$b');
  }
}

Future<ValidationReport> _validate(
  Validator v,
  Uint8List sig, {
  Uint8List? document,
}) async => Validator.decide(
  await v.collect(sig, detachedContent: document),
  validationTime: DateTime.utc(2026, 11, 9),
);

int _indexOf(Uint8List haystack, List<int> needle) {
  for (var i = 0; i <= haystack.length - needle.length; i++) {
    var ok = true;
    for (var j = 0; j < needle.length && ok; j++) {
      ok = haystack[i + j] == needle[j];
    }
    if (ok) return i;
  }
  return -1;
}

void main() {
  group('ECDSA P-256 enveloping', () {
    for (final der in [false, true]) {
      test('credential returning ${der ? 'DER' : 'raw r||s'}', () async {
        final cred = TestEcCredential(
          derOutput: der,
          chainPaths: ['pki/p256/intermediate.der'],
        );
        final p7m = await Cades.sign(
          document: _doc(),
          credential: cred,
          algorithm: _ecdsa256,
        );
        _expectCryptoOk(await _validate(_p256(), p7m));
      });
    }
  });

  group('detached', () {
    test('RSA detached validates with the document, fails without', () async {
      final p7s = await Cades.sign(
        document: _doc(),
        credential: TestRsaCredential(),
        detached: true,
      );
      expect(_indexOf(p7s, _doc()), -1);
      final ok = await _validate(_rsa(), p7s, document: _doc());
      _expectCryptoOk(ok);
      expect(
        ok.simple.signatures.single.scope.single.kind,
        SignatureScopeKind.detachedDocument,
      );
      final missing = await _validate(_rsa(), p7s);
      expect(
        missing.detailed.signatures.single.subIndication,
        SubIndication.signedDataNotFound,
      );
      final wrong = await _validate(
        _rsa(),
        p7s,
        document: tier1('content/hello-tampered.txt'),
      );
      expect(
        wrong.detailed.signatures.single.subIndication,
        SubIndication.hashFailure,
      );
    });

    test('ECDSA detached, raw and DER credentials', () async {
      for (final der in [false, true]) {
        final p7s = await Cades.sign(
          document: _doc(),
          credential: TestEcCredential(derOutput: der),
          algorithm: _ecdsa256,
          detached: true,
        );
        _expectCryptoOk(await _validate(_p256(), p7s, document: _doc()));
      }
    });

    test('two-phase detached via JSON draft', () async {
      final cred = TestRsaCredential();
      final draft = await Cades.prepareDetached(
        document: _doc(),
        credential: cred,
      );
      expect(draft.kind, SignatureDraftKind.cadesDetached);
      final back = await SignatureDraft.fromJson(draft.toJson());
      expect(back.kind, SignatureDraftKind.cadesDetached);
      final p7s = await Cades.complete(
        draft: back,
        value: await cred.sign(await back.signRequest()),
        document: _doc(),
      );
      _expectCryptoOk(await _validate(_rsa(), p7s, document: _doc()));
    });
  });

  group('ECDSA value handling', () {
    test('a raw value of the wrong length is a mismatch', () async {
      final cred = TestEcCredential();
      final draft = await Cades.prepareEnveloping(
        document: _doc(),
        credential: cred,
        algorithm: _ecdsa256,
      );
      final v = await cred.sign(await draft.signRequest());
      expect(
        Cades.complete(
          draft: draft,
          value: SignatureValue.raw(Uint8List.sublistView(v.bytes, 0, 63)),
          document: _doc(),
        ),
        throwsA(isA<DraftMismatchException>()),
      );
    });

    test('a value for another draft is a mismatch', () async {
      final cred = TestEcCredential(derOutput: true);
      final a = await Cades.prepareEnveloping(
        document: _doc(),
        credential: cred,
        algorithm: _ecdsa256,
      );
      final b = await Cades.prepareEnveloping(
        document: tier1('content/hello-tampered.txt'),
        credential: cred,
        algorithm: _ecdsa256,
      );
      expect(
        Cades.complete(
          draft: a,
          value: await cred.sign(await b.signRequest()),
          document: _doc(),
        ),
        throwsA(isA<DraftMismatchException>()),
      );
    });

    test('an RSA algorithm with an EC certificate is refused', () async {
      final cred = _AnyAlgCredential(TestEcCredential());
      await expectLater(
        Cades.prepareEnveloping(document: _doc(), credential: cred),
        throwsA(isA<UnsupportedCredentialAlgorithmException>()),
      );
      expect(cred.inner.signCalls, 0);
    });
  });

  group('one-call sign', () {
    test('wraps a credential failure', () async {
      await expectLater(
        Cades.sign(document: _doc(), credential: _FailingCredential()),
        throwsA(
          isA<SigningFailedException>().having(
            (e) => e.cause,
            'cause',
            isA<StateError>(),
          ),
        ),
      );
    });

    test('enveloping RSA validates', () async {
      final p7m = await Cades.sign(
        document: _doc(),
        credential: TestRsaCredential(),
      );
      _expectCryptoOk(await _rsa().validate(p7m));
    });
  });

  group('signBatch', () {
    test('default signBatch is sequential and ordered', () async {
      final cred = TestRsaCredential();
      final drafts = [
        for (final d in [_doc(), tier1('content/hello-tampered.txt')])
          await Cades.prepareEnveloping(document: d, credential: cred),
      ];
      final reqs = [for (final d in drafts) await d.signRequest()];
      final values = await cred.signBatch(reqs);
      expect(values, hasLength(2));
      expect(cred.signCalls, 2);
    });

    test('N documents become N valid signatures', () async {
      final docs = [
        _doc(),
        tier1('content/hello-tampered.txt'),
        Uint8List.fromList([1, 2, 3]),
      ];
      final cred = TestEcCredential();
      final sigs = await Cades.signBatch(
        documents: docs,
        credential: cred,
        algorithm: _ecdsa256,
        detached: true,
      );
      expect(sigs, hasLength(3));
      expect(cred.batchCalls, 1);
      for (var i = 0; i < 3; i++) {
        _expectCryptoOk(await _validate(_p256(), sigs[i], document: docs[i]));
      }
    });
  });

  group('key usage', () {
    test(
      'neither digitalSignature nor nonRepudiation: refused pre-sign',
      () async {
        final cred = TestRsaCredential(
          certificatePath: 'pki/rsa2048/leaf-noku.der',
        );
        await expectLater(
          Cades.sign(document: _doc(), credential: cred),
          throwsA(isA<InvalidCertificateException>()),
        );
        expect(cred.signCalls, 0);
      },
    );
  });
}

/// Claims to support RSA while holding an EC certificate.
final class _AnyAlgCredential extends SigningCredential {
  _AnyAlgCredential(this.inner);

  final TestEcCredential inner;

  @override
  List<SignatureAlgorithm> get supportedAlgorithms => const [
    SignatureAlgorithm.rsaPkcs1v15Sha256,
  ];

  @override
  Future<Uint8List> get certificate => inner.certificate;

  @override
  Future<SignatureValue> sign(SignRequest request) => inner.sign(request);
}

final class _FailingCredential extends SigningCredential {
  @override
  List<SignatureAlgorithm> get supportedAlgorithms => const [
    SignatureAlgorithm.rsaPkcs1v15Sha256,
  ];

  @override
  Future<Uint8List> get certificate async =>
      tier1('pki/rsa2048/leaf-qsign.der');

  @override
  Future<SignatureValue> sign(SignRequest request) async =>
      throw StateError('card removed');
}
