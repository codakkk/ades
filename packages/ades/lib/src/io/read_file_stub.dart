import 'dart:typed_data';

/// Reads a file's bytes. Unsupported without `dart:io`.
Future<Uint8List> readFileBytes(String path) =>
    throw UnsupportedError('File access requires dart:io');
