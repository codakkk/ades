import 'dart:typed_data';

import '../crypto/algorithms.dart';

/// How a signature value is encoded.
///
/// RSA values are always [raw] (the big-endian integer, modulus length).
/// ECDSA vehicles differ: some return `r||s` ([raw]), some a DER
/// `Ecdsa-Sig-Value` ([der]); the core converts as the format requires
/// (ticket 10).
enum SignatureValueEncoding { raw, der }

/// A signature value tagged with its encoding.
final class SignatureValue {
  SignatureValue(Uint8List bytes, this.encoding)
    : bytes = Uint8List.fromList(bytes).asUnmodifiableView();

  SignatureValue.raw(Uint8List bytes) : this(bytes, SignatureValueEncoding.raw);

  SignatureValue.der(Uint8List bytes) : this(bytes, SignatureValueEncoding.der);

  final Uint8List bytes;
  final SignatureValueEncoding encoding;
}

/// One thing to sign (GLOSSARY: DTBS, DTBSR).
///
/// A credential feeds the device whichever form it needs: [dtbs] for a
/// device that hashes itself, [dtbsr] for one that signs digests (wrap it
/// in a DigestInfo for RSA PKCS#1 v1.5 if the device wants that).
final class SignRequest {
  SignRequest({
    required Uint8List dtbs,
    required Uint8List dtbsr,
    required this.signatureAlgorithm,
  }) : dtbs = Uint8List.fromList(dtbs).asUnmodifiableView(),
       dtbsr = Uint8List.fromList(dtbsr).asUnmodifiableView();

  /// The exact bytes the signature value covers.
  final Uint8List dtbs;

  /// Hash of [dtbs] under [digestAlgorithm].
  final Uint8List dtbsr;

  final SignatureAlgorithm signatureAlgorithm;

  DigestAlgorithm get digestAlgorithm => signatureAlgorithm.digest;

  /// [dtbsr] wrapped in a DER DigestInfo: what an RSA PKCS#1 v1.5 device
  /// signs when it does not hash itself.
  Uint8List get dtbsrDigestInfo => digestAlgorithm.digestInfo(dtbsr);
}

/// A private key the library cannot access, with its certificate (ADR-0005:
/// the core never touches key material).
///
/// Implement by extending (to inherit the default [chain] and [signBatch])
/// or by implementing every member. PIN and OTP prompts stay inside the
/// implementation (injected callbacks); the core never deals with
/// authorization.
abstract class SigningCredential {
  const SigningCredential();

  /// The leaf (signing) certificate, DER. Mandatory; async so a card or
  /// remote service can be asked for it.
  Future<Uint8List> get certificate;

  /// Further certificates (intermediates), DER, leaf excluded. Optional:
  /// B-B needs only the leaf, so cards that store no chain still work.
  Future<List<Uint8List>> get chain async => const [];

  /// The signature algorithms this credential can produce. Checked before
  /// [sign] is ever called.
  List<SignatureAlgorithm> get supportedAlgorithms;

  /// Signs one request. May prompt (PIN) inside the implementation.
  Future<SignatureValue> sign(SignRequest request);

  /// Signs several requests, in order. The default is sequential; remote
  /// vehicles override it to sign many DTBSRs under one authorization.
  Future<List<SignatureValue>> signBatch(List<SignRequest> requests) async => [
    for (final r in requests) await sign(r),
  ];
}
