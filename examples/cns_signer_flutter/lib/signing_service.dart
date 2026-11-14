import 'dart:io';
import 'dart:isolate';
import 'dart:typed_data';

import 'package:ades/ades.dart';

/// Signs a file into an enveloping CAdES-B-B `.p7m`.
abstract interface class FileSigner {
  Future<void> signEnveloping({
    required String inputPath,
    required String outputPath,
    required SigningCredential credential,
  });
}

/// Keeps the UI isolate free: reading and hashing the file (phase 1) and
/// embedding it into the signature (phase 2) run on short-lived isolates.
/// Only the small DTBS digest goes to the credential on the calling isolate,
/// where `Pkcs11Credential` forwards it to its own worker isolate and asks
/// for the PIN through the app's dialog.
///
/// Limit: the whole file is held in memory (twice, on the helper isolates,
/// never on the UI isolate). Streaming for very large files arrives with the
/// streaming BER work (ticket 11).
final class IsolateFileSigner implements FileSigner {
  const IsolateFileSigner({
    this.algorithm = SignatureAlgorithm.rsaPkcs1v15Sha256,
  });

  final SignatureAlgorithm algorithm;

  @override
  Future<void> signEnveloping({
    required String inputPath,
    required String outputPath,
    required SigningCredential credential,
  }) async {
    final certificate = await credential.certificate;
    final chain = await credential.chain;
    final alg = algorithm;

    // Phase 1 off the UI isolate: read + hash. Captures only sendable data.
    final draftJson = await Isolate.run(
      () => _prepare(inputPath, certificate, chain, alg),
    );
    final draft = await SignatureDraft.fromJson(draftJson);

    // The card signs the small DTBSR (PIN dialog happens in here).
    final value = await credential.sign(await draft.signRequest());

    // Phase 2 off the UI isolate: re-read, assemble, write.
    await Isolate.run(
      () => _complete(
        inputPath,
        outputPath,
        draftJson,
        value.bytes,
        value.encoding,
      ),
    );
  }
}

Future<Map<String, Object?>> _prepare(
  String inputPath,
  Uint8List certificate,
  List<Uint8List> chain,
  SignatureAlgorithm algorithm,
) async {
  final draft = await Cades.prepareEnveloping(
    document: await File(inputPath).readAsBytes(),
    credential: _PublicCredential(certificate, chain, algorithm),
    algorithm: algorithm,
  );
  return draft.toJson();
}

Future<void> _complete(
  String inputPath,
  String outputPath,
  Map<String, Object?> draftJson,
  Uint8List signature,
  SignatureValueEncoding encoding,
) async {
  final draft = await SignatureDraft.fromJson(draftJson);
  final p7m = await Cades.complete(
    draft: draft,
    value: SignatureValue(signature, encoding),
    document: await File(inputPath).readAsBytes(),
  );
  final tmp = File('$outputPath.part');
  await tmp.writeAsBytes(p7m, flush: true);
  await tmp.rename(outputPath);
}

/// Certificate-only stand-in used for phase 1 on the helper isolate; it
/// cannot sign.
final class _PublicCredential extends SigningCredential {
  _PublicCredential(this._cert, this._chain, SignatureAlgorithm alg)
    : supportedAlgorithms = [alg];

  final Uint8List _cert;
  final List<Uint8List> _chain;

  @override
  Future<Uint8List> get certificate async => _cert;

  @override
  Future<List<Uint8List>> get chain async => _chain;

  @override
  final List<SignatureAlgorithm> supportedAlgorithms;

  @override
  Future<SignatureValue> sign(SignRequest request) =>
      throw UnsupportedError('certificate-only credential');
}
