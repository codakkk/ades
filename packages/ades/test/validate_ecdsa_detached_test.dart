// Ticket 07: ECDSA P-256 and detached (.p7s) validation through the public API.
import 'dart:typed_data';

import 'package:ades/ades.dart';
import 'package:test/test.dart';

import 'support/tier1.dart';

Validator _validator(String hierarchy) => Validator(
  trustAnchors: [TrustAnchor.fromDer(tier1('pki/$hierarchy/root.der'))],
);

Future<SignatureDetailedReport> _validate(
  Validator v,
  Uint8List sig, {
  Uint8List? document,
}) async {
  final data = await v.collect(sig, detachedContent: document);
  final report = Validator.decide(
    data,
    validationTime: DateTime.utc(2026, 11, 9),
  );
  expect(report.detailed.signatures, hasLength(1));
  return report.detailed.signatures.single;
}

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
    for (final kind in ['qsign', 'auth']) {
      test('p256-$kind: crypto passes and the chain is built', () async {
        final d = await _validate(
          _validator('p256'),
          tier1('signatures/positive/p256-$kind.p7m'),
        );
        expect(
          d.result(BuildingBlock.cryptographicVerification)!.indication,
          BlockIndication.passed,
        );
        final xcv = d.result(BuildingBlock.x509CertificateValidation)!;
        // The chain (ECDSA links) is built; only revocation is open.
        expect(xcv.subIndication, SubIndication.certificateChainGeneralFailure);
        expect(
          xcv.messages.map((m) => m.code),
          contains(MessageCode.certificateChainBuilt),
        );
      });
    }

    test('the ECDSA chain runs signer, intermediate, root', () async {
      final sig = tier1('signatures/positive/p256-qsign.p7m');
      final data = await _validator('p256').collect(sig);
      expect(data.signatures.single.certificateChain, hasLength(3));
    });

    test('tampered content: HASH_FAILURE', () async {
      final sig = tier1('signatures/positive/p256-qsign.p7m');
      final at = _indexOf(sig, 'fixture content'.codeUnits);
      sig[at] ^= 0x01;
      final d = await _validate(_validator('p256'), sig);
      expect(d.indication, Indication.totalFailed);
      expect(d.subIndication, SubIndication.hashFailure);
    });

    test('altered signature value: SIG_CRYPTO_FAILURE', () async {
      final sig = tier1('signatures/positive/p256-qsign.p7m');
      sig[sig.length - 1] ^= 0x01;
      final d = await _validate(_validator('p256'), sig);
      expect(d.indication, Indication.totalFailed);
      expect(d.subIndication, SubIndication.sigCryptoFailure);
    });

    test(
      'a signature checked against the wrong curve key fails, not crashes',
      () async {
        // RSA anchor cannot build a chain for a P-256 signer.
        final d = await _validate(
          _validator('rsa2048'),
          tier1('signatures/positive/p256-qsign.p7m'),
        );
        expect(d.subIndication, SubIndication.noCertificateChainFound);
      },
    );
  });

  group('detached signatures', () {
    final doc = tier1('content/hello.txt');
    for (final name in [
      'rsa2048-qsign',
      'rsa2048-auth',
      'p256-qsign',
      'p256-auth',
    ]) {
      test('$name.p7s validates against the supplied document', () async {
        final v = _validator(name.split('-').first);
        final d = await _validate(
          v,
          tier1('signatures/positive/$name.p7s'),
          document: doc,
        );
        expect(
          d.result(BuildingBlock.cryptographicVerification)!.indication,
          BlockIndication.passed,
        );
        expect(d.subIndication, SubIndication.certificateChainGeneralFailure);
      });
    }

    test('the scope names the detached document', () async {
      final v = _validator('rsa2048');
      final data = await v.collect(
        tier1('signatures/positive/rsa2048-qsign.p7s'),
        detachedContent: doc,
      );
      final report = Validator.decide(
        data,
        validationTime: DateTime.utc(2026, 11, 9),
      );
      final scope = report.simple.signatures.single.scope.single;
      expect(scope.kind, SignatureScopeKind.detachedDocument);
      expect(scope.length, doc.length);
      expect(scope.digest, isNotNull);
    });

    test('a wrong document: TOTAL-FAILED / HASH_FAILURE', () async {
      for (final name in ['rsa2048-qsign', 'p256-qsign']) {
        final d = await _validate(
          _validator(name.split('-').first),
          tier1('signatures/positive/$name.p7s'),
          document: tier1('content/hello-tampered.txt'),
        );
        expect(d.indication, Indication.totalFailed);
        expect(d.subIndication, SubIndication.hashFailure);
      }
    });

    test(
      'no document: INDETERMINATE / SIGNED_DATA_NOT_FOUND, no exception',
      () async {
        final d = await _validate(
          _validator('rsa2048'),
          tier1('signatures/positive/rsa2048-qsign.p7s'),
        );
        expect(d.indication, Indication.indeterminate);
        expect(d.subIndication, SubIndication.signedDataNotFound);
      },
    );

    test(
      'a document supplied for an enveloping signature is ignored',
      () async {
        final d = await _validate(
          _validator('rsa2048'),
          tier1('signatures/positive/rsa2048-qsign.p7m'),
          document: tier1('content/hello-tampered.txt'),
        );
        expect(
          d.result(BuildingBlock.cryptographicVerification)!.indication,
          BlockIndication.passed,
        );
      },
    );
  });
}
