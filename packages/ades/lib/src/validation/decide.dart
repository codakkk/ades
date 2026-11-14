import '../crypto/algorithms.dart';
import '../x509/certificate.dart' show KeyUsageFlag;
import 'cryptographic_constraints.dart';
import 'diagnostic_data.dart';
import 'indication.dart';
import 'policy.dart';
import 'report.dart';

/// Decide stage (ADR-0007): pure and synchronous. Runs the EN 319 102-1
/// basic validation process (clause 5.3) over [data], one function per
/// building block.
///
/// [policy] sets the level of each constraint; [validationTime] is the
/// moment certificates are judged at. Both are explicit: the caller
/// ([Validator]) resolves "now", so this function is pure.
ValidationReport decideReport(
  DiagnosticData data, {
  required ValidationPolicy policy,
  required DateTime validationTime,
}) {
  final time = validationTime.toUtc();
  if (data.formatFailure != null) {
    final block = BuildingBlockResult(
      BuildingBlock.formatChecking,
      BlockIndication.failed,
      subIndication: SubIndication.formatFailure,
      messages: [
        ValidationMessage(MessageCode.malformedInput, data.formatFailure!),
      ],
    );
    return ValidationReport(
      simple: SimpleReport([
        const SimpleSignatureReport(
          index: 0,
          indication: Indication.totalFailed,
          subIndication: SubIndication.formatFailure,
          scope: [],
          signedBy: null,
          signingTime: null,
        ),
      ]),
      detailed: DetailedReport([
        SignatureDetailedReport(
          index: 0,
          blocks: [block],
          indication: Indication.totalFailed,
          subIndication: SubIndication.formatFailure,
        ),
      ]),
    );
  }
  final simple = <SimpleSignatureReport>[];
  final detailed = <SignatureDetailedReport>[];
  for (final s in data.signatures) {
    final d = _decideSignature(data, s, policy, time);
    detailed.add(d);
    String? signedBy;
    for (final c in data.certificates) {
      if (c.id == s.signingCertificateId) signedBy = c.subject;
    }
    simple.add(
      SimpleSignatureReport(
        index: s.index,
        indication: d.indication,
        subIndication: d.subIndication,
        scope: [if (s.scope != null) s.scope!],
        signedBy: signedBy,
        signingTime: s.signingTime,
      ),
    );
  }
  return ValidationReport(
    simple: SimpleReport(simple),
    detailed: DetailedReport(simple.isEmpty ? [] : detailed),
    warnings: data.warnings,
  );
}

SignatureDetailedReport _decideSignature(
  DiagnosticData data,
  SignatureDiagnostic s,
  ValidationPolicy policy,
  DateTime time,
) {
  final blocks = <BuildingBlockResult>[];
  SignatureDetailedReport end(Indication i, SubIndication? sub) =>
      SignatureDetailedReport(
        index: s.index,
        blocks: List.unmodifiable(blocks),
        indication: i,
        subIndication: sub,
      );

  final fc = _checkFormat(s);
  blocks.add(fc);
  if (fc.indication != BlockIndication.passed) {
    return end(Indication.totalFailed, fc.subIndication);
  }
  final isc = _identifySigningCertificate(s, policy);
  blocks.add(isc);
  if (isc.indication != BlockIndication.passed) {
    return end(Indication.indeterminate, isc.subIndication);
  }
  blocks.add(
    const BuildingBlockResult(
      BuildingBlock.validationContextInitialization,
      BlockIndication.passed,
    ),
  );
  // Like DSS, every remaining block is evaluated whatever the others say;
  // the final indication is then picked in the order of EN 319 102-1 5.3.
  final xcv = _validateCertificates(data, s, policy, time);
  final cv = _verifyCryptography(s, policy);
  final sav = _validateAcceptance(data, s, policy, time);
  blocks.addAll([xcv, cv, sav]);
  if (xcv.indication == BlockIndication.failed) {
    return end(Indication.totalFailed, xcv.subIndication);
  }
  if (cv.indication == BlockIndication.failed) {
    return end(Indication.totalFailed, cv.subIndication);
  }
  if (cv.indication == BlockIndication.indeterminate) {
    return end(Indication.indeterminate, cv.subIndication);
  }
  // An indeterminate certificate validation is the more fundamental reason
  // (an expired signing certificate also has a signing time outside its
  // validity, an untrusted one has no trusted algorithms).
  if (xcv.indication == BlockIndication.indeterminate) {
    return end(Indication.indeterminate, xcv.subIndication);
  }
  if (sav.indication != BlockIndication.passed) {
    return end(Indication.indeterminate, sav.subIndication);
  }
  return end(Indication.totalPassed, null);
}

/// Collects the checks of one building block.
final class _Block {
  _Block(this.block);

  final BuildingBlock block;
  BlockIndication _indication = BlockIndication.passed;
  SubIndication? _sub;
  final _messages = <ValidationMessage>[];

  bool get passed => _indication == BlockIndication.passed;
  bool get failed => _indication == BlockIndication.failed;

  void note(MessageCode code, String text) =>
      _messages.add(ValidationMessage(code, text));

  /// Evaluates one constraint. When [ok] is false the policy [level] decides:
  /// fail sets the block to [onFail] with [sub], warn and inform only add a
  /// message, ignore does nothing.
  void check(
    ConstraintLevel level,
    bool ok, {
    required BlockIndication onFail,
    required SubIndication? sub,
    required MessageCode code,
    required String text,
  }) {
    if (ok || level == ConstraintLevel.ignore) return;
    _messages.add(
      ValidationMessage(
        code,
        text,
        severity: switch (level) {
          ConstraintLevel.fail => MessageSeverity.error,
          ConstraintLevel.warn => MessageSeverity.warning,
          _ => MessageSeverity.info,
        },
      ),
    );
    if (level != ConstraintLevel.fail || failed) return;
    if (passed || onFail == BlockIndication.failed) {
      _indication = onFail;
      _sub = sub;
    }
  }

  /// A fixed failure that no policy level can relax.
  void fail(
    BlockIndication onFail,
    SubIndication sub,
    MessageCode code,
    String text,
  ) => check(
    ConstraintLevel.fail,
    false,
    onFail: onFail,
    sub: sub,
    code: code,
    text: text,
  );

  BuildingBlockResult build() => BuildingBlockResult(
    block,
    _indication,
    subIndication: _sub,
    messages: List.unmodifiable(_messages),
  );
}

/// 5.2.2 Format checking.
BuildingBlockResult _checkFormat(SignatureDiagnostic s) {
  if (s.formatIssues.isEmpty) {
    return const BuildingBlockResult(
      BuildingBlock.formatChecking,
      BlockIndication.passed,
    );
  }
  return BuildingBlockResult(
    BuildingBlock.formatChecking,
    BlockIndication.failed,
    subIndication: SubIndication.formatFailure,
    messages: [
      for (final i in s.formatIssues)
        ValidationMessage(i, _formatText(i), severity: MessageSeverity.error),
    ],
  );
}

String _formatText(MessageCode c) => switch (c) {
  MessageCode.missingContentType => 'contentType signed attribute is missing',
  MessageCode.missingMessageDigest =>
    'messageDigest signed attribute is missing',
  MessageCode.duplicateAttribute => 'a signed attribute occurs more than once',
  MessageCode.contentTypeMismatch =>
    'contentType attribute differs from the encapsulated content type',
  _ => 'the signature is malformed (for example no signed attributes)',
};

/// 5.2.3 Identification of the signing certificate.
BuildingBlockResult _identifySigningCertificate(
  SignatureDiagnostic s,
  ValidationPolicy p,
) {
  final b = _Block(BuildingBlock.identificationOfSigningCertificate);
  const indeterminate = BlockIndication.indeterminate;
  const sub = SubIndication.noSigningCertificateFound;
  if (s.signingCertificateId == null) {
    b.fail(
      indeterminate,
      sub,
      MessageCode.signingCertificateNotFound,
      'the certificate named by the signer identifier is not in the signature',
    );
    return b.build();
  }
  final ref = s.signingCertificateReference;
  if (ref == null) {
    b.check(
      p.signingCertificatePresent,
      false,
      onFail: indeterminate,
      sub: sub,
      code: MessageCode.missingSigningCertificate,
      text: 'no signing-certificate or signing-certificate-v2 signed attribute',
    );
    b.check(
      p.certDigestPresent,
      false,
      onFail: indeterminate,
      sub: sub,
      code: MessageCode.certDigestMissing,
      text: 'the signing certificate digest is not present',
    );
    return b.build();
  }
  final digestMatches = s.signingCertificateReferenceMatches == true;
  b.check(
    p.certDigestMatch,
    digestMatches,
    onFail: indeterminate,
    sub: sub,
    code: MessageCode.signingCertificateReferenceMismatch,
    text: 'the signing certificate does not match its signed reference',
  );
  b.check(
    p.issuerSerialMatch,
    ref.issuerSerialMatches != false,
    onFail: indeterminate,
    sub: sub,
    code: MessageCode.issuerSerialMismatch,
    text:
        'the issuer and serial in the signed reference differ from the '
        'signing certificate',
  );
  if (digestMatches) {
    b.note(
      MessageCode.signingCertificateReferenceMatches,
      'signing certificate matches its signed reference',
    );
  }
  return b.build();
}

/// 5.2.6 X.509 certificate validation, in DSS's order: a path to a trust
/// anchor must exist; then each certificate of it, signing certificate
/// first, is judged on its constraints, revocation data, cryptography and
/// validity period. The first failed check gives the block its
/// sub-indication. Trust anchors are not judged. Revocation data is never
/// collected yet, so with the default policy the best outcome is
/// INDETERMINATE / CERTIFICATE_CHAIN_GENERAL_FAILURE.
BuildingBlockResult _validateCertificates(
  DiagnosticData data,
  SignatureDiagnostic s,
  ValidationPolicy p,
  DateTime time,
) {
  final b = _Block(BuildingBlock.x509CertificateValidation);
  const indeterminate = BlockIndication.indeterminate;
  const chainFailure = SubIndication.chainConstraintsFailure;
  const generalFailure = SubIndication.certificateChainGeneralFailure;
  final chainIds = s.certificateChain;
  b.check(
    p.prospectiveCertificateChain,
    chainIds != null,
    onFail: indeterminate,
    sub: SubIndication.noCertificateChainFound,
    code: MessageCode.noCertificateChain,
    text: 'no path from the signing certificate to a trust anchor',
  );
  // Without a path there is nothing more to judge (DSS stops here too).
  if (chainIds == null && !b.passed) return b.build();
  // With the chain requirement relaxed, judge the signing certificate alone.
  final ids = chainIds ?? [s.signingCertificateId!];
  final chain = [
    for (final id in ids) data.certificates.firstWhere((c) => c.id == id),
  ];
  b.note(
    MessageCode.certificateChainBuilt,
    'path of ${chain.length} certificate(s) to a trust anchor: '
    '${chain.map((c) => c.subject).join(' <- ')}',
  );
  if (chain.length == 1) {
    b.note(
      MessageCode.signerIsTrustAnchor,
      'the signing certificate is a trust anchor',
    );
  }

  for (var i = 0; i < chain.length; i++) {
    final cert = chain[i];
    final isSigningCertificate = i == 0;
    if (isSigningCertificate) {
      // Deliberate divergence from DSS (user story 27): a signing
      // certificate that may neither sign data nor give non-repudiation is
      // refused; DSS only warns about nonRepudiation.
      final ku = cert.keyUsage;
      if (ku != null &&
          !ku.contains(KeyUsageFlag.digitalSignature) &&
          !ku.contains(KeyUsageFlag.nonRepudiation)) {
        b.fail(
          indeterminate,
          chainFailure,
          MessageCode.signerKeyUsageNotSigning,
          'the key usage of ${cert.subject} has neither digitalSignature '
          'nor nonRepudiation',
        );
      }
    }
    if (cert.trustAnchor) continue;

    if (!isSigningCertificate) {
      final bc = cert.basicConstraints;
      final isCa = bc != null && bc.isCa;
      b.check(
        p.caCertificateCa,
        isCa,
        onFail: indeterminate,
        sub: generalFailure,
        code: MessageCode.issuerNotCa,
        text: '${cert.subject} is not a CA (basicConstraints cA is not true)',
      );
      if (isCa) {
        final max = bc.pathLenConstraint;
        // i - 1 intermediate certificates sit between this CA and the
        // signing certificate.
        b.check(
          p.caCertificateMaxPathLength,
          max == null || i - 1 <= max,
          onFail: indeterminate,
          sub: generalFailure,
          code: MessageCode.pathLengthExceeded,
          text:
              '${cert.subject} allows $max intermediate CA(s) below it but '
              '${i - 1} are present',
        );
        final caKu = cert.keyUsage;
        b.check(
          p.caCertificateKeyUsage,
          caKu == null || caKu.contains(KeyUsageFlag.keyCertSign),
          onFail: indeterminate,
          sub: chainFailure,
          code: MessageCode.issuerKeyUsageNotCertSign,
          text: 'the key usage of ${cert.subject} lacks keyCertSign',
        );
      }
    }

    b.check(
      p.revocationDataAvailable,
      false,
      onFail: indeterminate,
      sub: generalFailure,
      code: MessageCode.revocationNotChecked,
      text: 'no revocation data was checked for ${cert.subject}',
    );

    // The certificate's signature was made by its issuer's key.
    final issuer = i + 1 < chain.length ? chain[i + 1] : cert;
    final algorithm = SignatureAlgorithm.fromOid(cert.signatureAlgorithmOid);
    _applyCryptography(
      b,
      p,
      algorithm == null
          ? [
              CryptographicFinding(
                CryptographicProblem.notAcceptable,
                '${cert.subject}: signature algorithm '
                '${cert.signatureAlgorithmOid} is not acceptable',
              ),
            ]
          : checkCryptography(
              what: cert.subject,
              digest: algorithm.digest,
              keyAlgorithm: issuer.publicKeyAlgorithm,
              keySize: issuer.publicKeySize,
              time: time,
            ),
    );

    final level = isSigningCertificate
        ? p.signingCertificateNotExpired
        : p.caCertificateNotExpired;
    b.check(
      level,
      !time.isAfter(cert.notAfter),
      onFail: indeterminate,
      sub: SubIndication.outOfBoundsNoPoe,
      code: MessageCode.certificateExpired,
      text: '${cert.subject} expired on ${cert.notAfter.toIso8601String()}',
    );
    b.check(
      level,
      !time.isBefore(cert.notBefore),
      onFail: indeterminate,
      sub: SubIndication.notYetValid,
      code: MessageCode.certificateNotYetValid,
      text: '${cert.subject} is valid from ${cert.notBefore.toIso8601String()}',
    );
  }
  return b.build();
}

/// Turns [findings] into checks at the policy's cryptographic levels. Both
/// kinds end INDETERMINATE / CRYPTO_CONSTRAINTS_FAILURE_NO_POE, as in DSS
/// (no proof of existence is collected that could vouch for a weak
/// algorithm).
void _applyCryptography(
  _Block b,
  ValidationPolicy p,
  List<CryptographicFinding> findings,
) {
  for (final f in findings) {
    final isExpiry = f.problem == CryptographicProblem.expired;
    var level = isExpiry ? p.algorithmExpiration : p.cryptographic;
    if (isExpiry &&
        f.expiresAfterPolicyUpdate &&
        level == ConstraintLevel.fail) {
      level = ConstraintLevel.warn;
    }
    b.check(
      level,
      false,
      onFail: BlockIndication.indeterminate,
      sub: SubIndication.cryptoConstraintsFailureNoPoe,
      code: isExpiry
          ? MessageCode.cryptographyExpired
          : MessageCode.cryptographyNotAcceptable,
      text: f.text,
    );
  }
}

/// 5.2.7 Cryptographic verification.
BuildingBlockResult _verifyCryptography(
  SignatureDiagnostic s,
  ValidationPolicy p,
) {
  final b = _Block(BuildingBlock.cryptographicVerification);
  b.check(
    p.referenceDataExistence,
    s.contentAvailable,
    onFail: BlockIndication.indeterminate,
    sub: SubIndication.signedDataNotFound,
    code: MessageCode.contentNotAvailable,
    text: 'the signed content is not available',
  );
  if (!s.contentAvailable) return b.build();
  b.check(
    p.referenceDataIntact,
    s.messageDigestMatches != false,
    onFail: BlockIndication.failed,
    sub: SubIndication.hashFailure,
    code: MessageCode.messageDigestMismatch,
    text: 'the content digest differs from the messageDigest attribute',
  );
  if (b.failed) return b.build();
  if (!s.signedAttributesDer) {
    b.fail(
      BlockIndication.failed,
      SubIndication.sigCryptoFailure,
      MessageCode.signedAttributesNotDer,
      'the signed attributes are not DER encoded',
    );
    return b.build();
  }
  if (s.signatureCheck == SignatureCheckStatus.unsupported) {
    b.fail(
      BlockIndication.indeterminate,
      SubIndication.cryptoConstraintsFailureNoPoe,
      MessageCode.unsupportedAlgorithm,
      'the signature algorithm or key type is not supported',
    );
    return b.build();
  }
  final verified = s.signatureCheck == SignatureCheckStatus.verified;
  if (verified) {
    b.note(MessageCode.signatureValid, 'the signature value verifies');
  }
  b.check(
    p.signatureIntact,
    verified,
    onFail: BlockIndication.failed,
    sub: SubIndication.sigCryptoFailure,
    code: MessageCode.signatureInvalid,
    text: 'the signature value does not verify',
  );
  return b.build();
}

/// 5.2.8 Signature acceptance validation. Like DSS it also judges the
/// signature's own algorithms, which needs a trusted path to vouch for them.
BuildingBlockResult _validateAcceptance(
  DiagnosticData data,
  SignatureDiagnostic s,
  ValidationPolicy p,
  DateTime time,
) {
  final b = _Block(BuildingBlock.signatureAcceptanceValidation);
  const indeterminate = BlockIndication.indeterminate;
  const sub = SubIndication.sigConstraintsFailure;
  final signingTime = s.signingTime;
  final signingCertificate = data.certificates.firstWhere(
    (c) => c.id == s.signingCertificateId,
  );
  b.check(
    p.signingTime,
    signingTime != null,
    onFail: indeterminate,
    sub: sub,
    code: MessageCode.signingTimeMissing,
    text: 'the signature has no signing-time attribute',
  );
  if (signingTime != null) {
    b.check(
      p.signingTimeInCertRange,
      !signingTime.isBefore(signingCertificate.notBefore) &&
          !signingTime.isAfter(signingCertificate.notAfter),
      onFail: indeterminate,
      sub: sub,
      code: MessageCode.signingTimeOutOfCertRange,
      text:
          'the claimed signing time is outside the signing certificate '
          'validity',
    );
  }
  b.check(
    p.prospectiveCertificateChain,
    s.certificateChain != null,
    onFail: indeterminate,
    sub: SubIndication.cryptoConstraintsFailureNoPoe,
    code: MessageCode.noTrustedChainForCryptography,
    text:
        'without a path to a trust anchor nothing vouches for the '
        'algorithms of the signature',
  );
  final algorithm = SignatureAlgorithm.forCms(
    s.signatureAlgorithmOid,
    DigestAlgorithm.fromOid(s.digestAlgorithmOid),
  );
  // An unsupported algorithm is already reported by CV.
  if (algorithm != null) {
    _applyCryptography(
      b,
      p,
      checkCryptography(
        what: 'the signature',
        digest: algorithm.digest,
        keyAlgorithm: signingCertificate.publicKeyAlgorithm,
        keySize: signingCertificate.publicKeySize,
        time: time,
      ),
    );
  }
  return b.build();
}
