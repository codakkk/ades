import 'dart:convert';
import 'dart:typed_data';

import 'key_material.dart';

/// One PEM block.
final class PemBlock {
  PemBlock(this.label, this.der);

  final String label;
  final Uint8List der;
}

final _block = RegExp(
  r'-----BEGIN ([A-Z0-9 ]+)-----([\s\S]*?)-----END \1-----',
);

/// All PEM blocks in [text], in order. Throws [SoftKeyLoadException] for a
/// block with bad base64 or a traditional encrypted-PEM header.
List<PemBlock> parsePem(String text) {
  final out = <PemBlock>[];
  for (final m in _block.allMatches(text)) {
    final body = m.group(2)!;
    if (body.contains('Proc-Type') || body.contains('DEK-Info')) {
      throw const SoftKeyLoadException(
        SoftKeyLoadFailure.unsupported,
        'traditional encrypted PEM is not supported; convert the key to '
        'PKCS#8 (openssl pkcs8 -topk8)',
      );
    }
    try {
      out.add(
        PemBlock(
          m.group(1)!,
          base64.decode(body.replaceAll(RegExp(r'\s'), '')),
        ),
      );
    } on FormatException {
      throw SoftKeyLoadException(
        SoftKeyLoadFailure.malformed,
        'bad base64 in ${m.group(1)} block',
      );
    }
  }
  return out;
}
