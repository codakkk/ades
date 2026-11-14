import 'dart:io';
import 'dart:typed_data';

/// Reads a file's bytes.
Future<Uint8List> readFileBytes(String path) => File(path).readAsBytes();
