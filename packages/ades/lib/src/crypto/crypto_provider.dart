import 'dart:typed_data';

import 'algorithms.dart';
import 'public_key.dart';

/// Thrown by a [CryptoProvider] for an algorithm or key it cannot handle.
/// The validator reports it as an indeterminate result, never as a crash.
final class UnsupportedAlgorithmException implements Exception {
  const UnsupportedAlgorithmException(this.message);

  final String message;

  @override
  String toString() => 'UnsupportedAlgorithmException: $message';
}

/// The only path to cryptographic primitives (ADR-0001, ADR-0005).
///
/// It is asynchronous so that a WebCrypto or native provider can be plugged
/// in later without touching formats. It never sees a private key: signing
/// belongs to signing credentials.
abstract interface class CryptoProvider {
  /// Hash of [data].
  Future<Uint8List> digest(DigestAlgorithm algorithm, Uint8List data);

  /// Hash of a byte stream, without buffering it (used for large content).
  Future<Uint8List> digestStream(
    DigestAlgorithm algorithm,
    Stream<List<int>> data,
  );

  /// Whether [signature] is a valid [algorithm] signature of [message]
  /// (the provider hashes [message] itself) under [key].
  ///
  /// Returns false for a signature that does not verify. Throws
  /// [UnsupportedAlgorithmException] when the algorithm or key type is not
  /// supported.
  Future<bool> verify({
    required SignatureAlgorithm algorithm,
    required PublicKey key,
    required Uint8List message,
    required Uint8List signature,
  });
}
