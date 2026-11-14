// Parsing of private keys and password-based encryption (PKCS#8, PBES2 and
// the legacy PKCS#12 3DES scheme). This is the only place in the workspace
// that touches private key bytes (ADR-0005). ASN.1 is read with
// pointycastle's parser (see asn1_read.dart): the core's DER codec is not
// public.
import 'dart:convert';
import 'dart:typed_data';

import 'package:collection/collection.dart';
import 'package:pointycastle/asn1.dart';
import 'package:pointycastle/export.dart' as pc;

import 'asn1_read.dart';

/// Why a key store could not be loaded.
enum SoftKeyLoadFailure {
  /// The data is not a well-formed PKCS#12 / PEM / PKCS#8 structure.
  malformed,

  /// The password is wrong (or the data was altered: MAC mismatch).
  wrongPassword,

  /// Well formed, but uses something this package does not implement
  /// (non-RSA key, RC2 encryption, traditional encrypted PEM, ...).
  unsupported,

  /// No private key, no certificate, or no certificate matching the key.
  incomplete,
}

/// Thrown by `ades_soft` loaders.
final class SoftKeyLoadException implements Exception {
  const SoftKeyLoadException(this.failure, this.message);

  final SoftKeyLoadFailure failure;
  final String message;

  @override
  String toString() => 'SoftKeyLoadException(${failure.name}): $message';
}

/// A private key this package can sign with.
sealed class SoftKey {
  const SoftKey();
}

/// An ECDSA private key on P-256.
final class EcKeyMaterial extends SoftKey {
  EcKeyMaterial(this.d, this.x, this.y);

  final BigInt d;

  /// The public point, derived from [d].
  final BigInt x;
  final BigInt y;
}

/// An RSA private key with CRT parameters.
final class RsaKeyMaterial extends SoftKey {
  RsaKeyMaterial(this.n, this.e, this.d, this.p, this.q);

  final BigInt n;
  final BigInt e;
  final BigInt d;
  final BigInt p;
  final BigInt q;
}

const _rsaEncryption = '1.2.840.113549.1.1.1';
const _ecPublicKey = '1.2.840.10045.2.1';
const _p256Oid = '1.2.840.10045.3.1.7';
const _pbes2 = '1.2.840.113549.1.5.13';
const _pbkdf2 = '1.2.840.113549.1.5.12';
const _pbeSha1TripleDes = '1.2.840.113549.1.12.1.3';

const _prfs = <String, String>{
  '1.2.840.113549.2.7': 'SHA-1/HMAC',
  '1.2.840.113549.2.9': 'SHA-256/HMAC',
  '1.2.840.113549.2.10': 'SHA-384/HMAC',
  '1.2.840.113549.2.11': 'SHA-512/HMAC',
};

/// Largest PBKDF2 / PKCS#12 iteration count accepted (guards against a
/// hostile file making loading take forever).
const _maxIterations = 10000000;

/// Parses a PKCS#8 PrivateKeyInfo (DER) holding an RSA or P-256 key.
SoftKey parsePkcs8(Uint8List der) {
  final f = asn1Sequence(parseAsn1(der, 'PrivateKeyInfo'), 'PrivateKeyInfo');
  if (f.length < 3) throw malformed('PrivateKeyInfo too short');
  final alg = asn1Sequence(f[1], 'algorithm');
  final algOid = asn1Oid(alg[0], 'algorithm');
  if (algOid == _ecPublicKey) {
    if (alg.length < 2 || asn1Oid(alg[1], 'curve') != _p256Oid) {
      throw const SoftKeyLoadException(
        SoftKeyLoadFailure.unsupported,
        'only the P-256 curve is supported for EC keys',
      );
    }
    return parseSec1(asn1Octets(f[2], 'privateKey'));
  }
  if (algOid != _rsaEncryption) {
    throw SoftKeyLoadException(
      SoftKeyLoadFailure.unsupported,
      'only RSA and P-256 private keys are supported (found $algOid)',
    );
  }
  return parsePkcs1(asn1Octets(f[2], 'privateKey'));
}

/// Parses a SEC1 ECPrivateKey (DER) on P-256 (RFC 5915). The public point is
/// recomputed from the scalar; a stored one that disagrees is malformed.
EcKeyMaterial parseSec1(Uint8List der, {bool checkCurve = false}) {
  final k = asn1Sequence(parseAsn1(der, 'ECPrivateKey'), 'ECPrivateKey');
  if (k.length < 2) throw malformed('ECPrivateKey too short');
  var d = BigInt.zero;
  for (final b in asn1Octets(k[1], 'EC scalar')) {
    d = (d << 8) | BigInt.from(b);
  }
  for (final e in k.skip(2)) {
    if (isContext(e, 0) && checkCurve) {
      final curve = asn1Oid(asn1Children(e, 'EC parameters').single, 'curve');
      if (curve != _p256Oid) {
        throw const SoftKeyLoadException(
          SoftKeyLoadFailure.unsupported,
          'only the P-256 curve is supported for EC keys',
        );
      }
    }
  }
  final params = pc.ECDomainParameters('secp256r1');
  if (d < BigInt.one || d >= params.n) throw malformed('bad EC scalar');
  final q = (params.G * d)!;
  final key = EcKeyMaterial(d, q.x!.toBigInteger()!, q.y!.toBigInteger()!);
  for (final e in k.skip(2)) {
    if (isContext(e, 1)) {
      final bits = asn1Children(e, 'EC public key').single;
      if (bits is! ASN1BitString) {
        throw malformed('EC public key not a BIT STRING');
      }
      // The stored uncompressed point, without the unused-bits byte.
      final stored = Uint8List.fromList(bits.stringValues ?? const []);
      final expected = q.getEncoded(false);
      if (!const ListEquality<int>().equals(stored, expected)) {
        throw malformed('stored EC public key does not match');
      }
    }
  }
  return key;
}

/// Parses a PKCS#1 RSAPrivateKey (DER).
RsaKeyMaterial parsePkcs1(Uint8List der) {
  final k = asn1Sequence(parseAsn1(der, 'RSAPrivateKey'), 'RSAPrivateKey');
  if (k.length < 9) throw malformed('RSAPrivateKey too short');
  BigInt i(int n) => asn1Integer(k[n], 'RSA integer');
  final key = RsaKeyMaterial(i(1), i(2), i(3), i(4), i(5));
  if (key.p * key.q != key.n) throw malformed('RSA key is inconsistent');
  return key;
}

/// Decrypts an EncryptedPrivateKeyInfo and parses the key.
SoftKey parseEncryptedPkcs8(Uint8List der, String password) {
  final f = asn1Sequence(
    parseAsn1(der, 'EncryptedPrivateKeyInfo'),
    'EncryptedPrivateKeyInfo',
  );
  if (f.length < 2) throw malformed('EncryptedPrivateKeyInfo too short');
  final plain = decryptWithAlgorithm(
    f[0],
    asn1Octets(f[1], 'encryptedData'),
    password,
  );
  return parsePkcs8(plain);
}

/// The PKCS#12 password encoding: BMPString with a terminating NUL.
Uint8List bmpPassword(String password) {
  final out = <int>[];
  for (final u in password.codeUnits) {
    out
      ..add(u >> 8)
      ..add(u & 0xff);
  }
  out.addAll([0, 0]);
  return Uint8List.fromList(out);
}

/// Decrypts [data] with the PBES2 or PKCS#12 3DES scheme named by the
/// AlgorithmIdentifier [algorithm].
Uint8List decryptWithAlgorithm(
  ASN1Object algorithm,
  Uint8List data,
  String password,
) {
  final a = asn1Sequence(algorithm, 'encryption algorithm');
  final oid = asn1Oid(a[0], 'encryption algorithm');
  if (oid == _pbeSha1TripleDes) {
    final p = asn1Sequence(a[1], 'pbe params');
    final salt = asn1Octets(p[0], 'salt');
    final iterations = _iterations(asn1Integer(p[1], 'iterations'));
    final gen = pc.PKCS12ParametersGenerator(pc.SHA1Digest())
      ..init(bmpPassword(password), salt, iterations);
    final params = gen.generateDerivedParametersWithIV(24, 8);
    return _cbcDecrypt(pc.DESedeEngine(), params, data);
  }
  if (oid != _pbes2) {
    throw SoftKeyLoadException(
      SoftKeyLoadFailure.unsupported,
      'unsupported encryption scheme $oid',
    );
  }
  final p = asn1Sequence(a[1], 'PBES2-params');
  final kdf = asn1Sequence(p[0], 'keyDerivationFunc');
  if (asn1Oid(kdf[0], 'keyDerivationFunc') != _pbkdf2) {
    throw const SoftKeyLoadException(
      SoftKeyLoadFailure.unsupported,
      'only PBKDF2 is supported with PBES2',
    );
  }
  final kp = asn1Sequence(kdf[1], 'PBKDF2-params');
  final salt = asn1Octets(kp[0], 'salt');
  final iterations = _iterations(asn1Integer(kp[1], 'iterations'));
  var prf = 'SHA-1/HMAC';
  var i = 2;
  int? keyLength;
  if (i < kp.length && kp[i] is ASN1Integer) {
    keyLength = asn1Integer(kp[i++], 'keyLength').toInt();
  }
  if (i < kp.length) {
    final prfOid = asn1Oid(asn1Sequence(kp[i], 'prf')[0], 'prf');
    prf =
        _prfs[prfOid] ??
        (throw SoftKeyLoadException(
          SoftKeyLoadFailure.unsupported,
          'unsupported PBKDF2 PRF $prfOid',
        ));
  }
  final scheme = asn1Sequence(p[1], 'encryptionScheme');
  final (cipher, keySize) = switch (asn1Oid(scheme[0], 'encryptionScheme')) {
    '2.16.840.1.101.3.4.1.2' => (pc.AESEngine() as pc.BlockCipher, 16),
    '2.16.840.1.101.3.4.1.22' => (pc.AESEngine(), 24),
    '2.16.840.1.101.3.4.1.42' => (pc.AESEngine(), 32),
    '1.2.840.113549.3.7' => (pc.DESedeEngine(), 24),
    final o => throw SoftKeyLoadException(
      SoftKeyLoadFailure.unsupported,
      'unsupported PBES2 cipher $o',
    ),
  };
  if (keyLength != null && keyLength != keySize) {
    throw malformed('PBKDF2 key length does not match the cipher');
  }
  final iv = asn1Octets(scheme[1], 'IV');
  if (iv.length != cipher.blockSize) throw malformed('bad IV length');
  final kd = pc.PBKDF2KeyDerivator(pc.Mac(prf))
    ..init(pc.Pbkdf2Parameters(salt, iterations, keySize));
  final key = kd.process(Uint8List.fromList(utf8.encode(password)));
  return _cbcDecrypt(
    cipher,
    pc.ParametersWithIV(pc.KeyParameter(key), iv),
    data,
  );
}

int _iterations(BigInt v) {
  if (v < BigInt.one || v > BigInt.from(_maxIterations)) {
    throw malformed('iteration count out of range');
  }
  return v.toInt();
}

Uint8List _cbcDecrypt(
  pc.BlockCipher cipher,
  pc.CipherParameters params,
  Uint8List data,
) {
  if (data.isEmpty || data.length % cipher.blockSize != 0) {
    throw malformed('ciphertext length is not a block multiple');
  }
  final c = pc.PaddedBlockCipherImpl(
    pc.PKCS7Padding(),
    pc.CBCBlockCipher(cipher),
  )..init(false, pc.PaddedBlockCipherParameters(params, null));
  try {
    return c.process(data);
  } on Object {
    // Bad padding: the overwhelmingly likely cause is a wrong password.
    throw const SoftKeyLoadException(
      SoftKeyLoadFailure.wrongPassword,
      'decryption failed: wrong password?',
    );
  }
}
