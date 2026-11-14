import 'dart:typed_data';

import 'certificate.dart';

/// A certificate the caller trusts without further proof (custom trust
/// anchor, see GLOSSARY).
///
/// In this tracer only the certificate itself is trusted: a signature whose
/// signing certificate is byte-identical to an anchor is trusted. Path
/// building up to an anchor that is a CA arrives with ticket 05, which
/// reuses [certificate] (subject, public key) as the path's end.
final class TrustAnchor {
  TrustAnchor._(this.certificate);

  /// Creates an anchor from a DER certificate.
  ///
  /// Throws [FormatException] if [der] is not a certificate: a bad anchor is
  /// a caller bug, not hostile input, so it is not reported through a
  /// validation report.
  factory TrustAnchor.fromDer(Uint8List der) {
    try {
      return TrustAnchor._(X509Certificate.parse(Uint8List.fromList(der)));
    } on Object catch (e) {
      throw FormatException('Trust anchor is not a valid certificate: $e');
    }
  }

  final X509Certificate certificate;
}
