// Tracer (ticket 04): validate RSA enveloping .p7m through the public API.
import 'dart:typed_data';

import 'package:ades/ades.dart';
import 'package:crypto/crypto.dart' as hash;
import 'package:test/test.dart';

import 'support/tier1.dart';

const _qsign = 'signatures/positive/rsa2048-qsign.p7m';

Validator _validator() => Validator(
  trustAnchors: [TrustAnchor.fromDer(tier1('pki/rsa2048/leaf-qsign.der'))],
);

Future<SignatureDetailedReport> _validate(Uint8List bytes) async {
  final report = await _validator().validate(bytes);
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
  group('positive fixture', () {
    test(
      'every block passes when the signer is itself the trust anchor (as in DSS)',
      () async {
        final d = await _validate(tier1(_qsign));
        expect(
          d.result(BuildingBlock.formatChecking)!.indication,
          BlockIndication.passed,
        );
        expect(
          d
              .result(BuildingBlock.identificationOfSigningCertificate)!
              .indication,
          BlockIndication.passed,
        );
        expect(
          d.result(BuildingBlock.cryptographicVerification)!.indication,
          BlockIndication.passed,
        );
        expect(
          d.result(BuildingBlock.signatureAcceptanceValidation)!.indication,
          BlockIndication.passed,
        );
        expect(
          d.result(BuildingBlock.x509CertificateValidation)!.indication,
          BlockIndication.passed,
        );
        expect(d.indication, Indication.totalPassed);
      },
    );

    test('simple report states the signature scope', () async {
      final report = await _validator().validate(tier1(_qsign));
      final s = report.simple.signatures.single;
      expect(s.scope, hasLength(1));
      expect(s.scope.single.kind, SignatureScopeKind.envelopedContent);
      expect(s.scope.single.length, tier1('content/hello.txt').length);
      expect(
        s.scope.single.digest,
        hash.sha256.convert(tier1('content/hello.txt')).bytes,
      );
      expect(s.signedBy, contains('TESTSURNAME'));
      expect(s.signingTime, isNotNull);
    });

    test('enum names match EN 319 102-1', () {
      expect(Indication.totalPassed.etsi, 'TOTAL-PASSED');
      expect(SubIndication.hashFailure.etsi, 'HASH_FAILURE');
      expect(SubIndication.sigCryptoFailure.etsi, 'SIG_CRYPTO_FAILURE');
      expect(BuildingBlock.cryptographicVerification.clause, '5.2.7');
    });

    test('without a trust anchor no certificate chain is found', () async {
      final r = await Validator().validate(tier1(_qsign));
      final d = r.detailed.signatures.single;
      expect(d.indication, Indication.indeterminate);
      expect(d.subIndication, SubIndication.noCertificateChainFound);
    });

    test('decide is deterministic over collected diagnostic data', () async {
      final data = await _validator().collect(tier1(_qsign));
      final a = Validator.decide(data);
      final b = Validator.decide(data);
      expect(
        a.simple.signatures.single.subIndication,
        b.simple.signatures.single.subIndication,
      );
    });
  });

  group('negative fixtures', () {
    test('tampered content: TOTAL-FAILED / HASH_FAILURE', () async {
      final d = await _validate(
        tier1('signatures/negative/rsa2048-tampered-content.p7m'),
      );
      expect(d.indication, Indication.totalFailed);
      expect(d.subIndication, SubIndication.hashFailure);
    });

    test('wrong messageDigest with valid signature: HASH_FAILURE', () async {
      final d = await _validate(
        tier1('signatures/negative/rsa2048-wrong-message-digest.p7m'),
      );
      expect(d.indication, Indication.totalFailed);
      expect(d.subIndication, SubIndication.hashFailure);
    });

    test('wrong signature value: TOTAL-FAILED / SIG_CRYPTO_FAILURE', () async {
      final bytes = tier1(_qsign);
      bytes[bytes.length - 1] ^= 0x01;
      final d = await _validate(bytes);
      expect(d.indication, Indication.totalFailed);
      expect(d.subIndication, SubIndication.sigCryptoFailure);
    });

    test('non-DER signed attributes fail', () async {
      final d = await _validate(
        tier1('signatures/negative/rsa2048-non-der-signed-attrs.p7m'),
      );
      expect(d.indication, Indication.totalFailed);
      expect(d.subIndication, SubIndication.sigCryptoFailure);
      expect(
        d.result(BuildingBlock.cryptographicVerification)!.messages.single.code,
        MessageCode.signedAttributesNotDer,
      );
    });

    test('mismatched SigningCertificateV2 hash is detected', () async {
      final bytes = tier1(_qsign);
      final certHash = hash.sha256
          .convert(tier1('pki/rsa2048/leaf-qsign.der'))
          .bytes;
      final at = _indexOf(bytes, certHash);
      expect(at, greaterThan(0), reason: 'certHash present in fixture');
      bytes[at] ^= 0xff;
      final d = await _validate(bytes);
      expect(d.indication, Indication.indeterminate);
      expect(d.subIndication, SubIndication.noSigningCertificateFound);
      expect(
        d
            .result(BuildingBlock.identificationOfSigningCertificate)!
            .messages
            .single
            .code,
        MessageCode.signingCertificateReferenceMismatch,
      );
    });

    test('missing SigningCertificateV2 is detected', () async {
      final bytes = tier1(_qsign);
      // id-aa-signingCertificateV2 -> unknown sibling OID of equal length.
      const oid = [
        0x2a,
        0x86,
        0x48,
        0x86,
        0xf7,
        0x0d,
        0x01,
        0x09,
        0x10,
        0x02,
        0x2f,
      ];
      final at = _indexOf(bytes, oid);
      expect(at, greaterThan(0));
      bytes[at + oid.length - 1] = 0x30;
      final d = await _validate(bytes);
      expect(d.subIndication, SubIndication.noSigningCertificateFound);
      expect(
        d
            .result(BuildingBlock.identificationOfSigningCertificate)!
            .messages
            .map((m) => m.code),
        contains(MessageCode.missingSigningCertificate),
      );
    });
  });

  group('malformed input never throws', () {
    Future<void> expectFormatFailure(Uint8List bytes) async {
      final r = await _validator().validate(bytes);
      final s = r.simple.signatures.single;
      expect(s.indication, Indication.totalFailed);
      expect(s.subIndication, SubIndication.formatFailure);
      expect(
        r.detailed.signatures.single.blocks.single.block,
        BuildingBlock.formatChecking,
      );
    }

    test('empty input', () => expectFormatFailure(Uint8List(0)));
    test(
      'garbage',
      () => expectFormatFailure(Uint8List.fromList([1, 2, 3, 4])),
    );
    test(
      'not a SignedData',
      () => expectFormatFailure(tier1('pki/rsa2048/root.der')),
    );
    test('truncated fixture', () async {
      final b = tier1(_qsign);
      await expectFormatFailure(Uint8List.sublistView(b, 0, b.length - 7));
    });
    test('trailing garbage', () async {
      final b = tier1(_qsign);
      await expectFormatFailure(Uint8List.fromList([...b, 0]));
    });
    test(
      'every prefix and many single-byte mutations yield a report',
      () async {
        final b = tier1(_qsign);
        for (var n = 0; n < b.length; n += 7) {
          final r = await _validator().validate(Uint8List.sublistView(b, 0, n));
          expect(r.simple.signatures, isNotEmpty);
        }
        for (var i = 0; i < b.length; i += 5) {
          final m = Uint8List.fromList(b)..[i] ^= 0x5a;
          final r = await _validator().validate(m);
          expect(r.simple.signatures, isNotEmpty);
        }
      },
    );
  });

  test('a custom CryptoProvider is the only path to crypto', () async {
    final spy = _SpyProvider();
    final v = Validator(
      crypto: spy,
      trustAnchors: [TrustAnchor.fromDer(tier1('pki/rsa2048/leaf-qsign.der'))],
    );
    final r = await v.validate(tier1(_qsign));
    expect(spy.verifyCalls, 1);
    expect(spy.digestCalls, greaterThan(0));
    // The spy accepts everything, so the signature check passes.
    expect(
      r.detailed.signatures.single
          .result(BuildingBlock.cryptographicVerification)!
          .indication,
      BlockIndication.passed,
    );
  });
}

class _SpyProvider implements CryptoProvider {
  final _inner = const DefaultCryptoProvider();
  int verifyCalls = 0;
  int digestCalls = 0;

  @override
  Future<Uint8List> digest(DigestAlgorithm algorithm, Uint8List data) {
    digestCalls++;
    return _inner.digest(algorithm, data);
  }

  @override
  Future<Uint8List> digestStream(
    DigestAlgorithm algorithm,
    Stream<List<int>> data,
  ) => _inner.digestStream(algorithm, data);

  @override
  Future<bool> verify({
    required SignatureAlgorithm algorithm,
    required PublicKey key,
    required Uint8List message,
    required Uint8List signature,
  }) async {
    verifyCalls++;
    return true;
  }
}
