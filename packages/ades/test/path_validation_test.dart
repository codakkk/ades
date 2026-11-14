// Ticket 05: path building and X.509 certificate validation (EN 319 102-1
// 5.2.6) through the public API, with tier-1 fixtures.
import 'dart:typed_data';

import 'package:ades/ades.dart';
import 'package:test/test.dart';

import 'support/tier1.dart';

const _qsign = 'signatures/positive/rsa2048-qsign.p7m';
const _neg = 'signatures/negative/rsa2048-';

/// Revocation is never satisfied yet; this isolates the other constraints.
const _noRevocation = ValidationPolicy(
  revocationDataAvailable: ConstraintLevel.ignore,
);

Validator _validator({List<Uint8List> pool = const []}) => Validator(
  trustAnchors: [TrustAnchor.fromDer(tier1('pki/rsa2048/root.der'))],
  certificatePool: pool,
);

Future<SignatureDetailedReport> _validate(
  String fixture, {
  Validator? validator,
  DateTime? at,
  ValidationPolicy policy = const ValidationPolicy(),
}) async {
  final v = validator ?? _validator();
  final data = await v.collect(tier1(fixture));
  final report = Validator.decide(data, validationTime: at, policy: policy);
  return report.detailed.signatures.single;
}

BuildingBlockResult _xcv(SignatureDetailedReport d) =>
    d.result(BuildingBlock.x509CertificateValidation)!;

Set<MessageCode> _codes(BuildingBlockResult r) =>
    r.messages.map((m) => m.code).toSet();

void main() {
  group('path building', () {
    test(
      'root anchor with embedded intermediate builds and validates',
      () async {
        final d = await _validate(_qsign);
        final xcv = _xcv(d);
        expect(_codes(xcv), contains(MessageCode.certificateChainBuilt));
        // Revocation is the only reason left.
        expect(xcv.indication, BlockIndication.indeterminate);
        expect(xcv.subIndication, SubIndication.certificateChainGeneralFailure);
        expect(_codes(xcv), contains(MessageCode.revocationNotChecked));
        expect(
          d.result(BuildingBlock.cryptographicVerification)!.indication,
          BlockIndication.passed,
        );
      },
    );

    test(
      'missing intermediate: no chain without the pool, ok with it',
      () async {
        const f = '${_neg}missing-intermediate.p7m';
        final without = _xcv(await _validate(f));
        expect(without.indication, BlockIndication.indeterminate);
        expect(without.subIndication, SubIndication.noCertificateChainFound);

        final d = await _validate(
          f,
          validator: _validator(pool: [tier1('pki/rsa2048/intermediate.der')]),
        );
        expect(_codes(_xcv(d)), contains(MessageCode.certificateChainBuilt));
        expect(
          _xcv(d).subIndication,
          SubIndication.certificateChainGeneralFailure,
        );
      },
    );

    test('untrusted root: NO_CERTIFICATE_CHAIN_FOUND', () async {
      final d = await _validate('${_neg}untrusted-root.p7m');
      expect(d.indication, Indication.indeterminate);
      expect(d.subIndication, SubIndication.noCertificateChainFound);
    });

    test('untrusted root is accepted when it is the anchor', () async {
      final v = Validator(
        trustAnchors: [
          TrustAnchor.fromDer(tier1('pki/untrusted-rsa2048/root.der')),
        ],
      );
      final d = await _validate('${_neg}untrusted-root.p7m', validator: v);
      expect(_codes(_xcv(d)), contains(MessageCode.certificateChainBuilt));
    });

    test(
      'a pool certificate not issued by the trusted root is not used',
      () async {
        // Same subject name as the real intermediate, but the trusted root
        // never signed it, so the link is rejected.
        final v = _validator(
          pool: [tier1('pki/untrusted-rsa2048/intermediate.der')],
        );
        final d = await _validate(
          '${_neg}missing-intermediate.p7m',
          validator: v,
        );
        expect(_xcv(d).subIndication, SubIndication.noCertificateChainFound);
      },
    );

    test('a pool entry that is not a certificate is a caller error', () {
      expect(
        () => Validator(
          certificatePool: [
            Uint8List.fromList([1, 2, 3]),
          ],
        ),
        throwsFormatException,
      );
    });
  });

  group('certificate validation', () {
    test('expired leaf: INDETERMINATE / OUT_OF_BOUNDS_NO_POE', () async {
      final d = await _validate(
        '${_neg}expired-leaf.p7m',
        policy: _noRevocation,
      );
      expect(d.indication, Indication.indeterminate);
      expect(d.subIndication, SubIndication.outOfBoundsNoPoe);
      expect(_codes(_xcv(d)), contains(MessageCode.certificateExpired));
    });

    test('expired leaf is fine when validated within its validity', () async {
      final d = await _validate(
        '${_neg}expired-leaf.p7m',
        at: DateTime.utc(2020, 6, 1),
        policy: _noRevocation,
      );
      expect(_xcv(d).indication, BlockIndication.passed);
    });

    test('validation time before notBefore: NOT_YET_VALID', () async {
      final d = await _validate(
        _qsign,
        at: DateTime.utc(2023, 1, 1),
        policy: _noRevocation,
      );
      expect(d.indication, Indication.indeterminate);
      expect(d.subIndication, SubIndication.notYetValid);
      expect(_codes(_xcv(d)), contains(MessageCode.certificateNotYetValid));
    });

    test('signer without digitalSignature or nonRepudiation', () async {
      final d = await _validate(
        '${_neg}no-signing-key-usage.p7m',
        policy: _noRevocation,
      );
      expect(d.indication, Indication.indeterminate);
      expect(d.subIndication, SubIndication.chainConstraintsFailure);
      expect(_codes(_xcv(d)), contains(MessageCode.signerKeyUsageNotSigning));
    });

    test('authentication certificate (digitalSignature) is accepted', () async {
      final d = await _validate(
        'signatures/positive/rsa2048-auth.p7m',
        policy: _noRevocation,
      );
      expect(d.indication, Indication.totalPassed);
    });

    test('issuer that is not a CA', () async {
      final d = await _validate(
        '${_neg}issuer-not-ca.p7m',
        policy: _noRevocation,
      );
      expect(d.indication, Indication.indeterminate);
      expect(d.subIndication, SubIndication.certificateChainGeneralFailure);
      expect(_codes(_xcv(d)), contains(MessageCode.issuerNotCa));
    });

    test('path length constraint exceeded', () async {
      final d = await _validate(
        '${_neg}path-length-exceeded.p7m',
        policy: _noRevocation,
      );
      expect(d.indication, Indication.indeterminate);
      expect(d.subIndication, SubIndication.certificateChainGeneralFailure);
      expect(_codes(_xcv(d)), contains(MessageCode.pathLengthExceeded));
    });

    test('a chain failure does not hide the cryptographic result', () async {
      final d = await _validate('${_neg}tampered-content.p7m');
      expect(d.indication, Indication.totalFailed);
      expect(d.subIndication, SubIndication.hashFailure);
    });
  });

  group('detailed report', () {
    test(
      'one result per building block, each tagged with its clause',
      () async {
        final d = await _validate(_qsign);
        expect(d.blocks.map((b) => b.block.abbreviation), [
          'FC',
          'ISC',
          'VCI',
          'XCV',
          'CV',
          'SAV',
        ]);
        expect(d.blocks.map((b) => b.block.clause), [
          '5.2.2',
          '5.2.3',
          '5.2.4',
          '5.2.6',
          '5.2.7',
          '5.2.8',
        ]);
      },
    );
  });

  test('diagnostic data lists the certificates of the chain', () async {
    final data = await _validator().collect(tier1(_qsign));
    final names = data.certificates.map((c) => c.subject).join('|');
    expect(names, contains('Root CA'));
    expect(names, contains('Intermediate CA'));
    final anchors = data.certificates.where((c) => c.trustAnchor);
    expect(anchors.map((c) => c.subject), [contains('Root CA')]);
  });
}
