// Ticket 06, seam 2: decide over diagnostic data JSON. Each building block,
// the policy levels and the validation time, with no parsing involved.
import 'package:ades/ades.dart';
import 'package:test/test.dart';

import 'support/golden_diagnostics.dart';

final _now = DateTime.utc(2026, 11, 9);

SignatureDetailedReport _decide(
  DiagnosticData data, {
  ValidationPolicy policy = const ValidationPolicy(),
  DateTime? time,
}) {
  final r = Validator.decide(
    data,
    policy: policy,
    validationTime: time ?? _now,
  );
  return r.detailed.signatures.single;
}

BlockIndication _ind(SignatureDetailedReport d, BuildingBlock b) =>
    d.result(b)!.indication;

Iterable<String> _codes(SignatureDetailedReport d, BuildingBlock b) =>
    d.result(b)!.messages.map((m) => '${m.code.name}/${m.severity.name}');

const _ignoreRevocation = ValidationPolicy(
  revocationDataAvailable: ConstraintLevel.ignore,
);

void main() {
  group('healthy golden data', () {
    test('default policy: only revocation holds it back', () {
      final d = _decide(golden(null));
      expect(d.indication, Indication.indeterminate);
      expect(d.subIndication, SubIndication.certificateChainGeneralFailure);
      for (final b in [
        BuildingBlock.formatChecking,
        BuildingBlock.identificationOfSigningCertificate,
        BuildingBlock.cryptographicVerification,
        BuildingBlock.signatureAcceptanceValidation,
      ]) {
        expect(_ind(d, b), BlockIndication.passed, reason: b.name);
      }
      expect(_codes(d, BuildingBlock.x509CertificateValidation), [
        'certificateChainBuilt/info',
        'revocationNotChecked/error',
      ]);
    });

    test('revocation ignored: TOTAL-PASSED with no XCV complaint', () {
      final d = _decide(golden(null), policy: _ignoreRevocation);
      expect(d.indication, Indication.totalPassed);
      expect(d.subIndication, isNull);
      expect(_codes(d, BuildingBlock.x509CertificateValidation), [
        'certificateChainBuilt/info',
      ]);
    });
  });

  group('policy levels (revocationDataAvailable)', () {
    test('warn reports a warning and passes', () {
      final d = _decide(
        golden(null),
        policy: const ValidationPolicy(
          revocationDataAvailable: ConstraintLevel.warn,
        ),
      );
      expect(d.indication, Indication.totalPassed);
      expect(
        _codes(d, BuildingBlock.x509CertificateValidation),
        contains('revocationNotChecked/warning'),
      );
    });

    test('inform reports an info message and passes', () {
      final d = _decide(
        golden(null),
        policy: const ValidationPolicy(
          revocationDataAvailable: ConstraintLevel.inform,
        ),
      );
      expect(d.indication, Indication.totalPassed);
      expect(
        _codes(d, BuildingBlock.x509CertificateValidation),
        contains('revocationNotChecked/info'),
      );
    });
  });

  group('FC', () {
    test('format issues fail the signature and stop the process', () {
      final d = _decide(
        golden((s, c, ca) => s['formatIssues'] = ['missingMessageDigest']),
      );
      expect(d.indication, Indication.totalFailed);
      expect(d.subIndication, SubIndication.formatFailure);
      expect(d.blocks.map((b) => b.block), [BuildingBlock.formatChecking]);
    });

    test('a format failure of the whole input is one failed FC block', () {
      final data = DiagnosticData.fromJson({
        'formatFailure': 'not a CMS',
        'certificates': <Object?>[],
        'signatures': <Object?>[],
      });
      final r = Validator.decide(data, validationTime: _now);
      expect(r.simple.signatures.single.indication, Indication.totalFailed);
      expect(
        r.simple.signatures.single.subIndication,
        SubIndication.formatFailure,
      );
    });
  });

  group('ISC', () {
    test('signer identifier without a certificate', () {
      final d = _decide(golden((s, c, ca) => s['signingCertificateId'] = null));
      expect(d.indication, Indication.indeterminate);
      expect(d.subIndication, SubIndication.noSigningCertificateFound);
    });

    test('no signing-certificate attribute fails by default', () {
      final d = _decide(
        golden((s, c, ca) {
          s['signingCertificateReference'] = null;
          s['signingCertificateReferenceMatches'] = null;
        }),
      );
      expect(d.subIndication, SubIndication.noSigningCertificateFound);
      expect(
        _codes(d, BuildingBlock.identificationOfSigningCertificate),
        containsAll([
          'missingSigningCertificate/warning',
          'certDigestMissing/error',
        ]),
      );
    });

    test('no signing-certificate attribute tolerated when both relaxed', () {
      final d = _decide(
        golden((s, c, ca) {
          s['signingCertificateReference'] = null;
          s['signingCertificateReferenceMatches'] = null;
        }),
        policy: const ValidationPolicy(
          certDigestPresent: ConstraintLevel.warn,
          revocationDataAvailable: ConstraintLevel.ignore,
        ),
      );
      expect(d.indication, Indication.totalPassed);
    });

    test('certificate digest mismatch fails; warn relaxes it', () {
      void edit(
        Map<String, dynamic> s,
        Map<String, dynamic> c,
        Map<String, dynamic> ca,
      ) => s['signingCertificateReferenceMatches'] = false;
      final strict = _decide(golden(edit));
      expect(strict.subIndication, SubIndication.noSigningCertificateFound);
      final relaxed = _decide(
        golden(edit),
        policy: const ValidationPolicy(
          certDigestMatch: ConstraintLevel.warn,
          revocationDataAvailable: ConstraintLevel.ignore,
        ),
      );
      expect(relaxed.indication, Indication.totalPassed);
      expect(
        _codes(relaxed, BuildingBlock.identificationOfSigningCertificate),
        contains('signingCertificateReferenceMismatch/warning'),
      );
    });

    test('issuer/serial mismatch is a warning by default, fail on request', () {
      void edit(
        Map<String, dynamic> s,
        Map<String, dynamic> c,
        Map<String, dynamic> ca,
      ) =>
          (s['signingCertificateReference']
                  as Map<String, dynamic>)['issuerSerialMatches'] =
              false;
      final byDefault = _decide(golden(edit));
      expect(
        _ind(byDefault, BuildingBlock.identificationOfSigningCertificate),
        BlockIndication.passed,
      );
      expect(
        _codes(byDefault, BuildingBlock.identificationOfSigningCertificate),
        contains('issuerSerialMismatch/warning'),
      );
      final strict = _decide(
        golden(edit),
        policy: const ValidationPolicy(issuerSerialMatch: ConstraintLevel.fail),
      );
      expect(strict.subIndication, SubIndication.noSigningCertificateFound);
    });
  });

  group('XCV and validation time', () {
    test('no path to a trust anchor', () {
      final d = _decide(golden((s, c, ca) => s['certificateChain'] = null));
      expect(d.indication, Indication.indeterminate);
      expect(d.subIndication, SubIndication.noCertificateChainFound);
    });

    test('prospectiveCertificateChain ignore moves on to revocation', () {
      final d = _decide(
        golden((s, c, ca) => s['certificateChain'] = null),
        policy: const ValidationPolicy(
          prospectiveCertificateChain: ConstraintLevel.ignore,
        ),
      );
      expect(d.subIndication, SubIndication.certificateChainGeneralFailure);
    });

    test('issuer that is not a CA breaks the chain constraints', () {
      void edit(
        Map<String, dynamic> s,
        Map<String, dynamic> c,
        Map<String, dynamic> ca,
      ) {
        ca['trustAnchor'] = false;
        ca['basicConstraints'] = {'isCa': false, 'pathLenConstraint': null};
      }

      final d = _decide(golden(edit), policy: _ignoreRevocation);
      expect(d.subIndication, SubIndication.certificateChainGeneralFailure);
      expect(
        _codes(d, BuildingBlock.x509CertificateValidation),
        contains('issuerNotCa/error'),
      );
      final relaxed = _decide(
        golden(edit),
        policy: const ValidationPolicy(
          caCertificateCa: ConstraintLevel.warn,
          revocationDataAvailable: ConstraintLevel.ignore,
        ),
      );
      expect(relaxed.indication, Indication.totalPassed);
      expect(
        _codes(relaxed, BuildingBlock.x509CertificateValidation),
        contains('issuerNotCa/warning'),
      );
    });

    test('CA key usage without keyCertSign', () {
      final d = _decide(
        golden((s, c, ca) {
          ca['trustAnchor'] = false;
          ca['keyUsage'] = ['cRlSign'];
        }),
        policy: _ignoreRevocation,
      );
      expect(d.subIndication, SubIndication.chainConstraintsFailure);
      expect(
        _codes(d, BuildingBlock.x509CertificateValidation),
        contains('issuerKeyUsageNotCertSign/error'),
      );
    });

    test('signer key usage that cannot sign', () {
      final d = _decide(
        golden((s, c, ca) => c['keyUsage'] = ['keyEncipherment']),
      );
      expect(d.subIndication, SubIndication.chainConstraintsFailure);
    });

    test(
      'an expired CA that is not the anchor, per caCertificateNotExpired',
      () {
        void edit(
          Map<String, dynamic> s,
          Map<String, dynamic> c,
          Map<String, dynamic> ca,
        ) {
          ca['trustAnchor'] = false;
          ca['notAfter'] = '2030-01-01T00:00:00.000Z';
        }

        final time = DateTime.utc(2035, 1, 1);
        expect(
          _decide(
            golden(edit),
            time: time,
            policy: _ignoreRevocation,
          ).subIndication,
          SubIndication.outOfBoundsNoPoe,
        );
        expect(
          _decide(
            golden(edit),
            time: time,
            policy: const ValidationPolicy(
              caCertificateNotExpired: ConstraintLevel.ignore,
              revocationDataAvailable: ConstraintLevel.ignore,
            ),
          ).indication,
          Indication.totalPassed,
        );
      },
    );

    test('validation time after notAfter: expired', () {
      final d = _decide(
        golden(null),
        time: DateTime.utc(2050, 1, 1),
        policy: _ignoreRevocation,
      );
      expect(d.indication, Indication.indeterminate);
      expect(d.subIndication, SubIndication.outOfBoundsNoPoe);
      expect(
        _codes(d, BuildingBlock.x509CertificateValidation),
        contains('certificateExpired/error'),
      );
    });

    test('validation time before notBefore: not yet valid', () {
      final d = _decide(
        golden(null),
        time: DateTime.utc(2023, 6, 1),
        policy: _ignoreRevocation,
      );
      expect(d.subIndication, SubIndication.notYetValid);
      expect(
        _codes(d, BuildingBlock.x509CertificateValidation),
        contains('certificateNotYetValid/error'),
      );
    });

    test('same data, valid again at a time inside the validity', () {
      final data = golden(null);
      expect(
        _decide(
          data,
          time: DateTime.utc(2050, 1, 1),
          policy: _ignoreRevocation,
        ).subIndication,
        SubIndication.outOfBoundsNoPoe,
      );
      expect(
        _decide(
          data,
          time: DateTime.utc(2030, 1, 1),
          policy: _ignoreRevocation,
        ).indication,
        Indication.totalPassed,
      );
    });

    test('signingCertificateNotExpired ignore disregards the time', () {
      final d = _decide(
        golden(null),
        time: DateTime.utc(2050, 1, 1),
        policy: const ValidationPolicy(
          signingCertificateNotExpired: ConstraintLevel.ignore,
          revocationDataAvailable: ConstraintLevel.ignore,
        ),
      );
      expect(d.indication, Indication.totalPassed);
    });

    test('validation time is exclusive of the instant just inside', () {
      final d = _decide(
        golden(null),
        time: DateTime.utc(2049, 12, 31, 23, 59, 59),
        policy: _ignoreRevocation,
      );
      expect(d.indication, Indication.totalPassed);
    });
  });

  group('CV', () {
    test('content not available', () {
      final d = _decide(golden((s, c, ca) => s['contentAvailable'] = false));
      expect(d.indication, Indication.indeterminate);
      expect(d.subIndication, SubIndication.signedDataNotFound);
    });

    test('message digest mismatch is HASH_FAILURE; warn lets it pass', () {
      void edit(
        Map<String, dynamic> s,
        Map<String, dynamic> c,
        Map<String, dynamic> ca,
      ) => s['messageDigestMatches'] = false;
      final d = _decide(golden(edit));
      expect(d.indication, Indication.totalFailed);
      expect(d.subIndication, SubIndication.hashFailure);
      final relaxed = _decide(
        golden(edit),
        policy: const ValidationPolicy(
          referenceDataIntact: ConstraintLevel.warn,
          revocationDataAvailable: ConstraintLevel.ignore,
        ),
      );
      expect(relaxed.indication, Indication.totalPassed);
    });

    test('invalid signature value is SIG_CRYPTO_FAILURE', () {
      final d = _decide(golden((s, c, ca) => s['signatureCheck'] = 'invalid'));
      expect(d.indication, Indication.totalFailed);
      expect(d.subIndication, SubIndication.sigCryptoFailure);
    });

    test('signatureIntact warn passes with a warning', () {
      final d = _decide(
        golden((s, c, ca) => s['signatureCheck'] = 'invalid'),
        policy: const ValidationPolicy(
          signatureIntact: ConstraintLevel.warn,
          revocationDataAvailable: ConstraintLevel.ignore,
        ),
      );
      expect(d.indication, Indication.totalPassed);
      expect(
        _codes(d, BuildingBlock.cryptographicVerification),
        contains('signatureInvalid/warning'),
      );
    });

    test('non-DER signed attributes fail CV', () {
      final d = _decide(golden((s, c, ca) => s['signedAttributesDer'] = false));
      expect(d.subIndication, SubIndication.sigCryptoFailure);
    });

    test('unsupported algorithm is indeterminate', () {
      final d = _decide(
        golden((s, c, ca) => s['signatureCheck'] = 'unsupported'),
      );
      expect(d.indication, Indication.indeterminate);
      expect(d.subIndication, SubIndication.cryptoConstraintsFailureNoPoe);
    });
  });

  group('SAV', () {
    test('an indeterminate XCV takes precedence over SAV', () {
      final d = _decide(golden((s, c, ca) => s['signingTime'] = null));
      expect(d.subIndication, SubIndication.certificateChainGeneralFailure);
    });

    test('missing signing time', () {
      final d = _decide(
        golden((s, c, ca) => s['signingTime'] = null),
        policy: _ignoreRevocation,
      );
      expect(d.indication, Indication.indeterminate);
      expect(d.subIndication, SubIndication.sigConstraintsFailure);
    });

    test('signing time outside the certificate validity', () {
      final d = _decide(
        golden((s, c, ca) => s['signingTime'] = '2023-01-01T00:00:00.000Z'),
        policy: _ignoreRevocation,
      );
      expect(d.subIndication, SubIndication.sigConstraintsFailure);
      final relaxed = _decide(
        golden((s, c, ca) => s['signingTime'] = '2023-01-01T00:00:00.000Z'),
        policy: const ValidationPolicy(
          signingTimeInCertRange: ConstraintLevel.ignore,
          revocationDataAvailable: ConstraintLevel.ignore,
        ),
      );
      expect(relaxed.indication, Indication.totalPassed);
    });
  });

  group('cryptographic constraints (DSS Cryptographic)', () {
    const sha1Rsa = '1.2.840.113549.1.1.5';

    test('a SHA-1 certificate signature is expired since 2012', () {
      final d = _decide(
        golden((s, c, ca) => c['signatureAlgorithmOid'] = sha1Rsa),
        policy: _ignoreRevocation,
      );
      expect(d.indication, Indication.indeterminate);
      expect(d.subIndication, SubIndication.cryptoConstraintsFailureNoPoe);
      expect(
        _codes(d, BuildingBlock.x509CertificateValidation),
        contains('cryptographyExpired/error'),
      );
    });

    test(
      'a SHA-1 signature fails SAV; algorithmExpiration warn lets it pass',
      () {
        void edit(Map<String, dynamic> s, c, ca) {
          s['digestAlgorithmOid'] = '1.3.14.3.2.26';
          s['signatureAlgorithmOid'] = sha1Rsa;
        }

        final d = _decide(golden(edit), policy: _ignoreRevocation);
        expect(
          _ind(d, BuildingBlock.signatureAcceptanceValidation),
          BlockIndication.indeterminate,
        );
        expect(d.subIndication, SubIndication.cryptoConstraintsFailureNoPoe);
        final relaxed = _decide(
          golden(edit),
          policy: const ValidationPolicy(
            revocationDataAvailable: ConstraintLevel.ignore,
            algorithmExpiration: ConstraintLevel.warn,
          ),
        );
        expect(relaxed.indication, Indication.totalPassed);
      },
    );

    test('an RSA key below 786 bits is not acceptable', () {
      final d = _decide(
        golden((s, c, ca) => c['publicKeySize'] = 512),
        policy: _ignoreRevocation,
      );
      expect(d.subIndication, SubIndication.cryptoConstraintsFailureNoPoe);
      expect(
        _decide(
          golden((s, c, ca) => c['publicKeySize'] = 512),
          policy: const ValidationPolicy(
            revocationDataAvailable: ConstraintLevel.ignore,
            cryptographic: ConstraintLevel.ignore,
            algorithmExpiration: ConstraintLevel.ignore,
          ),
        ).indication,
        Indication.totalPassed,
      );
    });

    test('an RSA-1024 signing key expired in 2019', () {
      final d = _decide(
        golden((s, c, ca) => c['publicKeySize'] = 1024),
        policy: _ignoreRevocation,
      );
      expect(d.subIndication, SubIndication.cryptoConstraintsFailureNoPoe);
    });

    test('a key expiring after the policy update only warns', () {
      // RSA-2048 expires 2035-01-01 (DSS table), after the update date.
      final d = _decide(
        golden(null),
        time: DateTime.utc(2036, 1, 1),
        policy: const ValidationPolicy(
          revocationDataAvailable: ConstraintLevel.ignore,
          signingCertificateNotExpired: ConstraintLevel.ignore,
          caCertificateNotExpired: ConstraintLevel.ignore,
        ),
      );
      expect(d.indication, Indication.totalPassed);
      expect(
        _codes(d, BuildingBlock.signatureAcceptanceValidation),
        contains('cryptographyExpired/warning'),
      );
    });

    test('SAV cannot vouch for algorithms without a trusted path', () {
      final d = _decide(
        golden((s, c, ca) => s['certificateChain'] = null),
        policy: _ignoreRevocation,
      );
      expect(d.subIndication, SubIndication.noCertificateChainFound);
      final sav = d.result(BuildingBlock.signatureAcceptanceValidation)!;
      expect(sav.indication, BlockIndication.indeterminate);
      expect(sav.subIndication, SubIndication.cryptoConstraintsFailureNoPoe);
    });
  });

  test(
    'every block is evaluated even after cryptographic verification fails',
    () {
      final d = _decide(
        golden((s, c, ca) => s['messageDigestMatches'] = false),
        policy: _ignoreRevocation,
      );
      expect(d.indication, Indication.totalFailed);
      expect(d.subIndication, SubIndication.hashFailure);
      expect(
        _ind(d, BuildingBlock.signatureAcceptanceValidation),
        BlockIndication.passed,
      );
    },
  );
}
