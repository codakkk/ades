import 'dart:typed_data';

import 'package:ades/ades.dart';

/// The one place the CLI calls the core's validation and signing.
final class CoreOutcome {
  CoreOutcome(this.report, {required this.diagnosticJson});
  final ValidationReport report;

  /// The diagnostic data as JSON-encodable objects.
  final Map<String, Object?> diagnosticJson;
}

Future<CoreOutcome> runCoreValidation({
  required Uint8List signature,
  required Uint8List? document,
  required List<TrustAnchor> trustAnchors,
  required List<Uint8List> pool,
  required DateTime? validationTime,
  ValidationPolicy policy = const ValidationPolicy(),
}) async {
  final validator = Validator(
    trustAnchors: trustAnchors,
    certificatePool: pool,
  );
  final data = await validator.collect(signature, detachedContent: document);
  final report = Validator.decide(
    data,
    policy: policy,
    validationTime: validationTime,
  );
  return CoreOutcome(report, diagnosticJson: data.toJson());
}

Future<Uint8List> signWithCore({
  required Uint8List document,
  required SigningCredential credential,
  required bool detached,
  required DateTime? signingTime,
}) async {
  // The credential decides the key type; take its SHA-256 algorithm.
  final supported = credential.supportedAlgorithms;
  final algorithm = supported.firstWhere(
    (a) => a.digest == DigestAlgorithm.sha256,
    orElse: () => supported.first,
  );
  return Cades.sign(
    document: document,
    credential: credential,
    algorithm: algorithm,
    detached: detached,
    signingTime: signingTime,
  );
}
