import 'dart:typed_data';

import 'package:crypto/crypto.dart' as hash;
import 'package:pointycastle/ecc/ecc_fp.dart' as fp;
import 'package:pointycastle/export.dart' as pc;

import '../asn1/asn1.dart';
import 'algorithms.dart';
import 'crypto_provider.dart';
import 'public_key.dart';

/// Default provider: `crypto` for hashing, `pointycastle` for RSA.
final class DefaultCryptoProvider implements CryptoProvider {
  const DefaultCryptoProvider();

  static hash.Hash _hash(DigestAlgorithm a) => switch (a) {
    DigestAlgorithm.sha1 => hash.sha1,
    DigestAlgorithm.sha256 => hash.sha256,
    DigestAlgorithm.sha384 => hash.sha384,
    DigestAlgorithm.sha512 => hash.sha512,
  };

  @override
  Future<Uint8List> digest(DigestAlgorithm algorithm, Uint8List data) async =>
      Uint8List.fromList(_hash(algorithm).convert(data).bytes);

  @override
  Future<Uint8List> digestStream(
    DigestAlgorithm algorithm,
    Stream<List<int>> data,
  ) async {
    final d = await _hash(algorithm).bind(data).first;
    return Uint8List.fromList(d.bytes);
  }

  @override
  Future<bool> verify({
    required SignatureAlgorithm algorithm,
    required PublicKey key,
    required Uint8List message,
    required Uint8List signature,
  }) async {
    switch (algorithm.scheme) {
      case SignatureScheme.rsaPkcs1v15:
        if (key is! RsaPublicKey) {
          throw const UnsupportedAlgorithmException(
            'RSA signature with a non-RSA key',
          );
        }
        final h = await digest(algorithm.digest, message);
        return _verifyRsaPkcs1(key, algorithm.digest, h, signature);
      case SignatureScheme.ecdsa:
        if (key is! EcPublicKey) {
          throw const UnsupportedAlgorithmException(
            'ECDSA signature with a non-EC key',
          );
        }
        final h = await digest(algorithm.digest, message);
        return _verifyEcdsa(key, h, signature);
    }
  }
}

/// RSASSA-PKCS1-v1_5 verification (RFC 8017 8.2.2). The padded block is
/// rebuilt and compared byte for byte, so no malleable parsing of the
/// decrypted block is involved.
bool _verifyRsaPkcs1(
  RsaPublicKey key,
  DigestAlgorithm digestAlgorithm,
  Uint8List hashValue,
  Uint8List signature,
) {
  final k = (key.modulus.bitLength + 7) ~/ 8;
  if (signature.length != k || key.modulus.bitLength < 512) return false;
  if (key.exponent < BigInt.from(3) || key.exponent.isEven) return false;
  final digestInfo = digestAlgorithm.digestInfo(hashValue);
  if (k < digestInfo.length + 11) return false;
  final expected = Uint8List(k)
    ..fillRange(0, k, 0xff)
    ..[0] = 0
    ..[1] = 1
    ..[k - digestInfo.length - 1] = 0
    ..setRange(k - digestInfo.length, k, digestInfo);

  final Uint8List decrypted;
  try {
    final engine = pc.RSAEngine()
      ..init(
        false,
        pc.PublicKeyParameter<pc.RSAPublicKey>(
          pc.RSAPublicKey(key.modulus, key.exponent),
        ),
      );
    final raw = engine.process(signature);
    if (raw.length > k) return false;
    decrypted = Uint8List(k)..setRange(k - raw.length, k, raw);
  } on Object {
    // Signature value >= modulus or similar: not a valid signature.
    return false;
  }
  var diff = 0;
  for (var i = 0; i < k; i++) {
    diff |= decrypted[i] ^ expected[i];
  }
  return diff == 0;
}

/// ECDSA verification (X9.62). [signature] must be a strict DER
/// `Ecdsa-Sig-Value`; r and s must lie in [1, n-1] and the public point must
/// be on the curve.
bool _verifyEcdsa(EcPublicKey key, Uint8List hashValue, Uint8List signature) {
  try {
    final params = pc.ECDomainParameters(key.curve.registryName);
    final curve = params.curve;
    final p = (curve as fp.ECCurve).q!;
    final a = curve.a!.toBigInteger()!;
    final b = curve.b!.toBigInteger()!;
    if (key.x >= p || key.y >= p || key.x.isNegative || key.y.isNegative) {
      return false;
    }
    if ((key.y * key.y - (key.x * key.x * key.x + a * key.x + b)) % p !=
        BigInt.zero) {
      return false;
    }
    final seq = decodeDer(signature);
    final parts = seq.children;
    if (seq.tag != Asn1Tag.sequence || parts == null || parts.length != 2) {
      return false;
    }
    final r = parts[0].asInteger;
    final s = parts[1].asInteger;
    if (r < BigInt.one || s < BigInt.one || r >= params.n || s >= params.n) {
      return false;
    }
    final signer = pc.ECDSASigner()
      ..init(
        false,
        pc.PublicKeyParameter<pc.ECPublicKey>(
          pc.ECPublicKey(curve.createPoint(key.x, key.y), params),
        ),
      );
    return signer.verifySignature(hashValue, pc.ECSignature(r, s));
  } on Object {
    return false;
  }
}
