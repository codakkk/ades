import 'dart:typed_data';

import '../crypto/crypto_provider.dart';
import '../crypto/default_crypto_provider.dart';
import '../x509/certificate.dart';
import '../x509/trust_anchor.dart';
import 'collect.dart';
import 'decide.dart';
import 'diagnostic_data.dart';
import 'policy.dart';
import 'report.dart';

/// Validates CAdES signatures in two stages (ADR-0007).
///
/// [collect] is asynchronous, does all parsing and cryptography, and never
/// touches the network. [decide] is synchronous and pure: the same
/// [DiagnosticData] always yields the same report. Neither throws on
/// malformed input; unreadable input yields a FORMAT_FAILURE report.
///
/// Certification paths run from the signing certificate to one of the
/// [trustAnchors], through the certificates embedded in the signature and
/// the caller-supplied [certificatePool] (DER certificates, for example
/// missing intermediates).
///
/// The constructor throws [FormatException] for a malformed pool entry: that
/// is a caller bug, not hostile input (which only ever yields a report).
final class Validator {
  Validator({
    List<TrustAnchor> trustAnchors = const [],
    List<Uint8List> certificatePool = const [],
    CryptoProvider crypto = const DefaultCryptoProvider(),
  }) : _anchors = List.unmodifiable(trustAnchors),
       _pool = List.unmodifiable(_parsePool(certificatePool)),
       _crypto = crypto;

  final List<TrustAnchor> _anchors;
  final List<X509Certificate> _pool;
  final CryptoProvider _crypto;

  /// Parses [signature] (a DER CMS SignedData) and gathers the facts about
  /// every signature in it.
  ///
  /// For a detached signature (`.p7s`) pass the signed document as
  /// [detachedContent]; without it the result is INDETERMINATE with
  /// SIGNED_DATA_NOT_FOUND. It is ignored for enveloping signatures.
  Future<DiagnosticData> collect(
    Uint8List signature, {
    Uint8List? detachedContent,
  }) => collectDiagnosticData(
    signature,
    detachedContent: detachedContent,
    crypto: _crypto,
    trustAnchors: _anchors,
    pool: _pool,
  );

  /// Like [collect] for a stream of bytes. The encapsulated content is hashed
  /// while it is read and never held, so a multi-gigabyte `.p7m` is handled
  /// in bounded memory (the outer structure may use indefinite-length BER,
  /// within limits; ADR-0004). Never throws on bad input; an error from
  /// [signature] itself is reported as a format failure.
  ///
  /// For a detached signature pass the document as [detachedContent], also a
  /// stream: it is hashed while it is read and never held. An error of that
  /// stream is not caught. It is ignored for enveloping signatures.
  Future<DiagnosticData> collectStream(
    Stream<List<int>> signature, {
    Stream<List<int>>? detachedContent,
  }) => collectDiagnosticDataStream(
    signature,
    detachedContent: detachedContent,
    crypto: _crypto,
    trustAnchors: _anchors,
    pool: _pool,
  );

  /// Judges [data] under [policy] (default: DSS's default policy) at
  /// [validationTime] (default: now). Otherwise pure and deterministic.
  static ValidationReport decide(
    DiagnosticData data, {
    ValidationPolicy policy = const ValidationPolicy(),
    DateTime? validationTime,
  }) => decideReport(
    data,
    policy: policy,
    validationTime: validationTime ?? DateTime.now(),
  );

  /// `decide(await collect(signature))`.
  Future<ValidationReport> validate(
    Uint8List signature, {
    Uint8List? detachedContent,
    ValidationPolicy policy = const ValidationPolicy(),
    DateTime? validationTime,
  }) async => decide(
    await collect(signature, detachedContent: detachedContent),
    policy: policy,
    validationTime: validationTime,
  );

  /// `decide(await collectStream(signature))`.
  Future<ValidationReport> validateStream(
    Stream<List<int>> signature, {
    Stream<List<int>>? detachedContent,
    ValidationPolicy policy = const ValidationPolicy(),
    DateTime? validationTime,
  }) async => decide(
    await collectStream(signature, detachedContent: detachedContent),
    policy: policy,
    validationTime: validationTime,
  );
}

List<X509Certificate> _parsePool(List<Uint8List> der) => [
  for (final d in der)
    () {
      try {
        return X509Certificate.parse(Uint8List.fromList(d));
      } on Object catch (e) {
        throw FormatException(
          'Certificate pool entry is not a certificate: $e',
        );
      }
    }(),
];
