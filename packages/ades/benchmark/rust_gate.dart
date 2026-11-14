/// Benchmarks for the Rust admission gate (ADR-0006).
///
/// Everything goes through the public [CryptoProvider] seam, so the same code
/// measures the default pure-Dart provider on the VM, AOT, dart2js and
/// dart2wasm, and any future provider (WebCrypto, native) unchanged. No
/// `dart:io`, so it compiles for the web.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:ades/ades.dart';
import 'package:pointycastle/export.dart' as pc;

/// Prefix of the one machine-readable line the runners print.
const benchmarkResultPrefix = 'BENCH_RESULT ';

/// One measurement.
final class BenchResult {
  const BenchResult(this.name, this.unit, this.value, this.detail);

  final String name;
  final String unit;
  final double value;
  final String detail;

  Map<String, Object> toJson() => {
    'name': name,
    'unit': unit,
    'value': double.parse(value.toStringAsFixed(1)),
    'detail': detail,
  };
}

/// Parses the line printed by [formatResults]; throws [FormatException] if
/// [output] has none.
List<BenchResult> parseResults(String output) {
  for (final line in const LineSplitter().convert(output)) {
    final i = line.indexOf(benchmarkResultPrefix);
    if (i < 0) continue;
    final list = jsonDecode(line.substring(i + benchmarkResultPrefix.length));
    return [
      for (final m in list as List)
        BenchResult(
          m['name'] as String,
          m['unit'] as String,
          (m['value'] as num).toDouble(),
          m['detail'] as String,
        ),
    ];
  }
  throw const FormatException('no BENCH_RESULT line');
}

/// Human-readable lines followed by the machine-readable line.
String formatResults(List<BenchResult> results) {
  final b = StringBuffer();
  for (final r in results) {
    b.writeln(
      '${r.name}: ${r.value.toStringAsFixed(1)} ${r.unit} (${r.detail})',
    );
  }
  b.write(
    '$benchmarkResultPrefix${jsonEncode([for (final r in results) r.toJson()])}',
  );
  return b.toString();
}

/// Runs the three gate benchmarks.
///
/// [sha256Bytes] is streamed in 1 MiB chunks through `digestStream`. Each
/// verify loop runs for at least [minVerifySeconds] and at least
/// [minVerifyIterations] verifications.
Future<List<BenchResult>> runRustGate({
  CryptoProvider crypto = const DefaultCryptoProvider(),
  int sha256Bytes = 128 << 20,
  double minVerifySeconds = 2,
  int minVerifyIterations = 50,
  int rsaBits = 2048,
}) async {
  final results = <BenchResult>[];

  // SHA-256 streaming.
  const chunkSize = 1 << 20;
  final chunk = Uint8List(chunkSize);
  for (var i = 0; i < chunkSize; i++) {
    chunk[i] = (i * 31 + 7) & 0xff;
  }
  Stream<List<int>> source(int total) async* {
    var left = total;
    while (left > 0) {
      final n = left < chunkSize ? left : chunkSize;
      yield n == chunkSize ? chunk : Uint8List.sublistView(chunk, 0, n);
      left -= n;
    }
  }

  await crypto.digestStream(DigestAlgorithm.sha256, source(chunkSize));
  final sw = Stopwatch()..start();
  await crypto.digestStream(DigestAlgorithm.sha256, source(sha256Bytes));
  sw.stop();
  final mb = sha256Bytes / (1024 * 1024);
  results.add(
    BenchResult(
      'sha256_stream',
      'MiB/s',
      mb / (sw.elapsedMicroseconds / 1e6),
      '${mb.toStringAsFixed(0)} MiB in ${sw.elapsedMilliseconds} ms, '
          '1 MiB chunks',
    ),
  );

  final message = Uint8List.fromList(utf8.encode('ades benchmark message'));
  final random = _random();

  final rsa = _rsaFixture(random, rsaBits, message);
  results.add(
    await _verifyRate(
      'rsa${rsaBits}_pkcs1v15_sha256_verify',
      crypto,
      SignatureAlgorithm.rsaPkcs1v15Sha256,
      rsa.$1,
      message,
      rsa.$2,
      minVerifySeconds,
      minVerifyIterations,
    ),
  );

  final ec = _ecFixture(random, message);
  results.add(
    await _verifyRate(
      'ecdsa_p256_sha256_verify',
      crypto,
      const SignatureAlgorithm(SignatureScheme.ecdsa, DigestAlgorithm.sha256),
      ec.$1,
      message,
      ec.$2,
      minVerifySeconds,
      minVerifyIterations,
    ),
  );
  return results;
}

Future<BenchResult> _verifyRate(
  String name,
  CryptoProvider crypto,
  SignatureAlgorithm algorithm,
  PublicKey key,
  Uint8List message,
  Uint8List signature,
  double minSeconds,
  int minIterations,
) async {
  Future<bool> once() => crypto.verify(
    algorithm: algorithm,
    key: key,
    message: message,
    signature: signature,
  );
  if (!await once()) throw StateError('$name: fixture signature rejected');
  final bad = Uint8List.fromList(signature)..[signature.length - 1] ^= 1;
  if (await crypto.verify(
    algorithm: algorithm,
    key: key,
    message: message,
    signature: bad,
  )) {
    throw StateError('$name: corrupted signature accepted');
  }
  for (var i = 0; i < 5; i++) {
    await once();
  }
  var n = 0;
  final sw = Stopwatch()..start();
  while (n < minIterations || sw.elapsedMicroseconds < minSeconds * 1e6) {
    await once();
    n++;
  }
  sw.stop();
  return BenchResult(
    name,
    'verifies/s',
    n / (sw.elapsedMicroseconds / 1e6),
    '$n verifications in ${sw.elapsedMilliseconds} ms',
  );
}

pc.SecureRandom _random() {
  final r = pc.FortunaRandom();
  r.seed(
    pc.KeyParameter(Uint8List.fromList(List.generate(32, (i) => i * 7 + 1))),
  );
  return r;
}

(RsaPublicKey, Uint8List) _rsaFixture(
  pc.SecureRandom random,
  int bits,
  Uint8List message,
) {
  final gen = pc.RSAKeyGenerator()
    ..init(
      pc.ParametersWithRandom(
        pc.RSAKeyGeneratorParameters(BigInt.from(65537), bits, 64),
        random,
      ),
    );
  final pair = gen.generateKeyPair();
  final pub = pair.publicKey;
  final signer = pc.RSASigner(pc.SHA256Digest(), '0609608648016503040201')
    ..init(true, pc.PrivateKeyParameter<pc.RSAPrivateKey>(pair.privateKey));
  return (
    RsaPublicKey(pub.modulus!, pub.exponent!),
    signer.generateSignature(message).bytes,
  );
}

(EcPublicKey, Uint8List) _ecFixture(pc.SecureRandom random, Uint8List message) {
  final domain = pc.ECDomainParameters('secp256r1');
  final gen = pc.ECKeyGenerator()
    ..init(
      pc.ParametersWithRandom(pc.ECKeyGeneratorParameters(domain), random),
    );
  final pair = gen.generateKeyPair();
  final pub = pair.publicKey;
  final signer = pc.ECDSASigner(pc.SHA256Digest())
    ..init(
      true,
      pc.ParametersWithRandom(
        pc.PrivateKeyParameter<pc.ECPrivateKey>(pair.privateKey),
        random,
      ),
    );
  final sig = signer.generateSignature(message) as pc.ECSignature;
  final body = [..._derInt(sig.r), ..._derInt(sig.s)];
  final der = Uint8List.fromList([0x30, body.length, ...body]);
  return (
    EcPublicKey(
      EcCurve.p256,
      pub.Q!.x!.toBigInteger()!,
      pub.Q!.y!.toBigInteger()!,
    ),
    der,
  );
}

List<int> _derInt(BigInt v) {
  var bytes = <int>[];
  var x = v;
  while (x > BigInt.zero) {
    bytes.insert(0, (x & BigInt.from(0xff)).toInt());
    x >>= 8;
  }
  if (bytes.isEmpty || bytes.first & 0x80 != 0) bytes = [0, ...bytes];
  return [0x02, bytes.length, ...bytes];
}
