import 'dart:async';
import 'dart:typed_data';

import 'algorithms.dart';
import 'crypto_provider.dart';

/// Hashes data pushed in pieces through [CryptoProvider.digestStream], so a
/// large input is never buffered. The sink is synchronous: each [add] is
/// consumed before it returns.
final class StreamDigester {
  StreamDigester(CryptoProvider crypto, DigestAlgorithm algorithm)
    : _controller = StreamController<List<int>>(sync: true) {
    _result = crypto.digestStream(algorithm, _controller.stream);
    // An error before finish() is reported by whoever aborts; avoid an
    // unhandled-error report for the abandoned future.
    _result.then<void>((_) {}, onError: (Object _) {});
  }

  final StreamController<List<int>> _controller;
  late final Future<Uint8List> _result;

  void add(List<int> chunk) => _controller.add(chunk);

  /// Ends the input and returns the digest.
  Future<Uint8List> finish() {
    unawaited(_controller.close());
    return _result;
  }

  /// Abandons the digest (after an error elsewhere).
  void abort() {
    unawaited(_controller.close());
  }
}
