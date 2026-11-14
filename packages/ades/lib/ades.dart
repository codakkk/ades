/// Pure-Dart AdES signature core. No `dart:io` (ADR-0002).
library;

export 'src/crypto/algorithms.dart';
export 'src/crypto/crypto_provider.dart';
export 'src/crypto/default_crypto_provider.dart';
export 'src/crypto/public_key.dart';
export 'src/signing/cades.dart' show Cades, SignatureDraft, SignatureDraftKind;
export 'src/signing/credential.dart';
export 'src/signing/exceptions.dart';
export 'src/validation/diagnostic_data.dart';
export 'src/validation/indication.dart';
export 'src/validation/normalized_report.dart'
    show flattenReport, normalizeReport, projectForComparison;
export 'src/validation/policy.dart';
export 'src/validation/report.dart';
export 'src/validation/validator.dart';
export 'src/validation/warning.dart';
export 'src/x509/certificate.dart'
    show BasicConstraints, KeyUsageFlag, X509Certificate, X509Extension;
export 'src/x509/trust_anchor.dart' show TrustAnchor;

/// Package version, kept in sync with pubspec.yaml.
const String adesVersion = '0.0.1';
