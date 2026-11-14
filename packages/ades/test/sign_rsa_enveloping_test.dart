// Tracer (ticket 08): two-phase signing, validated by our own validator.
import 'dart:convert';
import 'dart:typed_data';

import 'package:ades/ades.dart';
import 'package:test/test.dart';

import 'support/test_credential.dart';
import 'support/tier1.dart';

Uint8List _doc() => tier1('content/hello.txt');

Validator _validator() => Validator(
  trustAnchors: [TrustAnchor.fromDer(tier1('pki/rsa2048/leaf-qsign.der'))],
);

Future<Uint8List> _signTwoPhase(
  TestRsaCredential cred, {
  Uint8List? document,
  DateTime? time,
}) async {
  final doc = document ?? _doc();
  final draft = await Cades.prepareEnveloping(
    document: doc,
    credential: cred,
    signingTime: time,
  );
  final value = await cred.sign(await draft.signRequest());
  return Cades.complete(draft: draft, value: value, document: doc);
}

void main() {
  test(
    'signed output validates: TOTAL-PASSED when revocation is ignored',
    () async {
      final p7m = await _signTwoPhase(TestRsaCredential());
      final report = await _validator().validate(
        p7m,
        policy: const ValidationPolicy(
          revocationDataAvailable: ConstraintLevel.ignore,
        ),
      );
      final d = report.detailed.signatures.single;
      for (final b in [
        BuildingBlock.formatChecking,
        BuildingBlock.identificationOfSigningCertificate,
        BuildingBlock.cryptographicVerification,
        BuildingBlock.signatureAcceptanceValidation,
      ]) {
        expect(d.result(b)!.indication, BlockIndication.passed, reason: '$b');
      }
      expect(d.indication, Indication.totalPassed);
      final s = report.simple.signatures.single;
      expect(s.scope.single.length, _doc().length);
      expect(s.signedBy, contains('TESTSURNAME'));
    },
  );

  test('signing time is frozen in the draft', () async {
    final t = DateTime.utc(2026, 11, 9, 10, 20, 30, 999);
    final cred = TestRsaCredential();
    final draft = await Cades.prepareEnveloping(
      document: _doc(),
      credential: cred,
      signingTime: t,
    );
    expect(draft.signingTime, DateTime.utc(2026, 11, 9, 10, 20, 30));
    final value = await cred.sign(await draft.signRequest());
    await Future<void>.delayed(const Duration(milliseconds: 1100));
    final p7m = await Cades.complete(
      draft: draft,
      value: value,
      document: _doc(),
    );
    final r = await _validator().validate(p7m);
    expect(
      r.simple.signatures.single.signingTime,
      DateTime.utc(2026, 11, 9, 10, 20, 30),
    );
  });

  test('draft survives JSON serialization and still completes', () async {
    final cred = TestRsaCredential(
      chainPaths: ['pki/rsa2048/intermediate.der'],
    );
    final draft = await Cades.prepareEnveloping(
      document: _doc(),
      credential: cred,
    );
    final wire = jsonDecode(jsonEncode(draft.toJson())) as Map<String, Object?>;
    final back = await SignatureDraft.fromJson(wire);
    expect(back.dtbs, draft.dtbs);
    expect(back.signingTime, draft.signingTime);
    expect(back.chain, hasLength(1));
    final value = await cred.sign(await back.signRequest());
    final p7m = await Cades.complete(
      draft: back,
      value: value,
      document: _doc(),
    );
    final r = await _validator().validate(p7m);
    expect(
      r.detailed.signatures.single
          .result(BuildingBlock.cryptographicVerification)!
          .indication,
      BlockIndication.passed,
    );
  });

  test('draft is immutable', () async {
    final draft = await Cades.prepareEnveloping(
      document: _doc(),
      credential: TestRsaCredential(),
    );
    expect(() => draft.dtbs[0] = 0, throwsUnsupportedError);
    expect(() => draft.chain.add(Uint8List(1)), throwsUnsupportedError);
  });

  test('a tampered draft is rejected on deserialization', () async {
    final draft = await Cades.prepareEnveloping(
      document: _doc(),
      credential: TestRsaCredential(),
    );
    final json = draft.toJson();
    json['signingTime'] = '2020-01-01T00:00:00.000Z';
    expect(
      SignatureDraft.fromJson(json),
      throwsA(isA<InvalidDraftException>()),
    );
    expect(
      SignatureDraft.fromJson({'format': 'nope'}),
      throwsA(isA<InvalidDraftException>()),
    );
  });

  group('completion rejects mismatches', () {
    test('another document', () async {
      final cred = TestRsaCredential();
      final draft = await Cades.prepareEnveloping(
        document: _doc(),
        credential: cred,
      );
      final value = await cred.sign(await draft.signRequest());
      expect(
        Cades.complete(
          draft: draft,
          value: value,
          document: tier1('content/hello-tampered.txt'),
        ),
        throwsA(isA<DraftMismatchException>()),
      );
    });

    test('a signature value of another draft', () async {
      final cred = TestRsaCredential();
      final a = await Cades.prepareEnveloping(
        document: _doc(),
        credential: cred,
      );
      final b = await Cades.prepareEnveloping(
        document: tier1('content/hello-tampered.txt'),
        credential: cred,
      );
      final valueB = await cred.sign(await b.signRequest());
      expect(
        Cades.complete(draft: a, value: valueB, document: _doc()),
        throwsA(isA<DraftMismatchException>()),
      );
    });

    test('a DER-tagged RSA value', () async {
      final cred = TestRsaCredential();
      final draft = await Cades.prepareEnveloping(
        document: _doc(),
        credential: cred,
      );
      final v = await cred.sign(await draft.signRequest());
      expect(
        Cades.complete(
          draft: draft,
          value: SignatureValue.der(Uint8List.fromList(v.bytes)),
          document: _doc(),
        ),
        throwsA(isA<DraftMismatchException>()),
      );
    });
  });

  group('creation policy, checked before sign is called', () {
    test('SHA-1 is refused', () async {
      final cred = TestRsaCredential(
        algorithms: const [
          SignatureAlgorithm(SignatureScheme.rsaPkcs1v15, DigestAlgorithm.sha1),
        ],
      );
      await expectLater(
        Cades.prepareEnveloping(
          document: _doc(),
          credential: cred,
          algorithm: const SignatureAlgorithm(
            SignatureScheme.rsaPkcs1v15,
            DigestAlgorithm.sha1,
          ),
        ),
        throwsA(isA<WeakDigestException>()),
      );
      expect(cred.signCalls, 0);
    });

    for (final digest in [DigestAlgorithm.sha384, DigestAlgorithm.sha512]) {
      test(
        '${digest.displayName} is refused at creation (out of scope)',
        () async {
          final algorithm = SignatureAlgorithm(
            SignatureScheme.rsaPkcs1v15,
            digest,
          );
          final cred = TestRsaCredential(algorithms: [algorithm]);
          await expectLater(
            Cades.prepareEnveloping(
              document: _doc(),
              credential: cred,
              algorithm: algorithm,
            ),
            throwsA(isA<UnsupportedCredentialAlgorithmException>()),
          );
          expect(cred.signCalls, 0);
        },
      );
    }

    test('a credential without the algorithm is refused', () async {
      final cred = TestRsaCredential(algorithms: const []);
      await expectLater(
        Cades.prepareEnveloping(document: _doc(), credential: cred),
        throwsA(isA<UnsupportedCredentialAlgorithmException>()),
      );
      expect(cred.signCalls, 0);
    });

    test('garbage certificate is refused', () async {
      final cred = TestRsaCredential(certificatePath: 'content/hello.txt');
      await expectLater(
        Cades.prepareEnveloping(document: _doc(), credential: cred),
        throwsA(isA<InvalidCertificateException>()),
      );
    });
  });

  test('AdesException is sealed: exhaustive switch compiles', () {
    String name(AdesException e) => switch (e) {
      InvalidCertificateException() => 'cert',
      WeakKeyException() => 'key',
      WeakDigestException() => 'digest',
      UnsupportedCredentialAlgorithmException() => 'alg',
      InvalidDraftException() => 'draft',
      DraftMismatchException() => 'mismatch',
      SigningFailedException() => 'failed',
    };
    expect(name(const WeakKeyException('x')), 'key');
  });

  test('default signBatch is sequential', () async {
    final cred = TestRsaCredential();
    final d = await Cades.prepareEnveloping(document: _doc(), credential: cred);
    final r = await d.signRequest();
    final out = await cred.signBatch([r, r]);
    expect(out, hasLength(2));
    expect(cred.signCalls, 2);
  });
}
