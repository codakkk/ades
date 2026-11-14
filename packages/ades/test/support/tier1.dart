import 'dart:convert';
import 'dart:typed_data';

import 'tier1_data.g.dart';

/// Bytes of a tier-1 fixture, by path under `fixtures/tier1/`, for example
/// `signatures/positive/rsa2048-qsign.p7m`. Works on every platform because
/// the files are embedded as constants (see
/// `tool/fixtures/generate_dart_constants.dart`).
Uint8List tier1(String path) {
  final b64 = tier1Base64[path];
  if (b64 == null) throw ArgumentError('no such tier-1 fixture: $path');
  return base64.decode(b64);
}
