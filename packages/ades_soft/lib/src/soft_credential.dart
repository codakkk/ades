import 'dart:typed_data';

import 'package:ades/ades.dart';
import 'package:collection/collection.dart';
import 'package:pointycastle/export.dart' as pc;

import 'key_material.dart';
import 'pem.dart';
import 'pkcs12.dart';

/// A signing credential backed by an RSA private key held in memory.
///
/// WARNING: not hardened against side channels (ADR-0005). Signing uses
/// pointycastle RSA with no guaranteed blinding or constant-time
/// arithmetic, and the key lives in ordinary Dart heap memory. Use it for
/// tests and low-risk server-side seals, not for keys that must survive a
/// hostile co-tenant. Qualified keys belong on a card or HSM (`ades_pkcs11`).
final class SoftSigningCredential extends SigningCredential {
  SoftSigningCredential._(this._key, this._certificate, this._chain);

  /// Loads a PKCS#12 file (DER). The leaf is the certificate matching the
  /// private key; the other certificates are ordered into its chain
  /// (self-signed roots excluded).
  ///
  /// Throws [SoftKeyLoadException].
  factory SoftSigningCredential.fromPkcs12(
    Uint8List bytes, {
    required String password,
  }) {
    final c = parsePkcs12(bytes, password);
    return _build(c.key, c.certificates);
  }

  /// Loads a PEM private key (`PRIVATE KEY`, `RSA PRIVATE KEY` or, with
  /// [password], `ENCRYPTED PRIVATE KEY`) and PEM certificates ([certificatesPem]
  /// holds the leaf and, optionally, its chain in any order).
  ///
  /// Throws [SoftKeyLoadException].
  factory SoftSigningCredential.fromPem({
    required String privateKeyPem,
    required String certificatesPem,
    String? password,
  }) {
    SoftKey? key;
    for (final b in parsePem(privateKeyPem)) {
      switch (b.label) {
        case 'PRIVATE KEY':
          key ??= parsePkcs8(b.der);
        case 'RSA PRIVATE KEY':
          key ??= parsePkcs1(b.der);
        case 'EC PRIVATE KEY':
          key ??= parseSec1(b.der, checkCurve: true);
        case 'ENCRYPTED PRIVATE KEY':
          if (password == null) {
            throw const SoftKeyLoadException(
              SoftKeyLoadFailure.wrongPassword,
              'the key is encrypted and no password was given',
            );
          }
          key ??= parseEncryptedPkcs8(b.der, password);
      }
    }
    if (key == null) {
      throw const SoftKeyLoadException(
        SoftKeyLoadFailure.incomplete,
        'no private key found in the PEM',
      );
    }
    return _build(key, [
      for (final b in parsePem(certificatesPem))
        if (b.label == 'CERTIFICATE') b.der,
    ]);
  }

  static SoftSigningCredential _build(SoftKey key, List<Uint8List> certs) {
    final parsed = <X509Certificate>[];
    for (final der in certs) {
      try {
        parsed.add(X509Certificate.parse(der));
      } on Object catch (e) {
        throw SoftKeyLoadException(
          SoftKeyLoadFailure.malformed,
          'bad certificate: $e',
        );
      }
    }
    final leaf = parsed.where((c) {
      final k = c.publicKey;
      return switch (key) {
        RsaKeyMaterial() =>
          k is RsaPublicKey && k.modulus == key.n && k.exponent == key.e,
        EcKeyMaterial() =>
          k is EcPublicKey &&
              k.curve == EcCurve.p256 &&
              k.x == key.x &&
              k.y == key.y,
      };
    }).toList();
    if (leaf.isEmpty) {
      throw const SoftKeyLoadException(
        SoftKeyLoadFailure.incomplete,
        'no certificate matches the private key',
      );
    }
    // Walk issuer links from the leaf; skip self-signed roots.
    final chain = <Uint8List>[];
    var current = leaf.first;
    final seen = <X509Certificate>{current};
    while (true) {
      final next = parsed.where(
        (c) => !seen.contains(c) && _equal(c.subjectDer, current.issuerDer),
      );
      if (next.isEmpty) break;
      current = next.first;
      seen.add(current);
      if (_equal(current.subjectDer, current.issuerDer)) break;
      chain.add(current.der);
    }
    return SoftSigningCredential._(key, leaf.first.der, chain);
  }

  final SoftKey _key;
  final Uint8List _certificate;
  final List<Uint8List> _chain;

  @override
  Future<Uint8List> get certificate async => Uint8List.fromList(_certificate);

  @override
  Future<List<Uint8List>> get chain async => [
    for (final c in _chain) Uint8List.fromList(c),
  ];

  @override
  List<SignatureAlgorithm> get supportedAlgorithms => switch (_key) {
    RsaKeyMaterial() => const [
      SignatureAlgorithm(SignatureScheme.rsaPkcs1v15, DigestAlgorithm.sha256),
      SignatureAlgorithm(SignatureScheme.rsaPkcs1v15, DigestAlgorithm.sha384),
      SignatureAlgorithm(SignatureScheme.rsaPkcs1v15, DigestAlgorithm.sha512),
    ],
    EcKeyMaterial() => const [
      SignatureAlgorithm(SignatureScheme.ecdsa, DigestAlgorithm.sha256),
      SignatureAlgorithm(SignatureScheme.ecdsa, DigestAlgorithm.sha384),
      SignatureAlgorithm(SignatureScheme.ecdsa, DigestAlgorithm.sha512),
    ],
  };

  @override
  Future<SignatureValue> sign(SignRequest request) async {
    if (!supportedAlgorithms.contains(request.signatureAlgorithm)) {
      throw UnsupportedCredentialAlgorithmException(
        'ades_soft cannot sign ${request.signatureAlgorithm}',
      );
    }
    return switch (_key) {
      final RsaKeyMaterial k => _signRsa(k, request),
      final EcKeyMaterial k => _signEcdsa(k, request),
    };
  }

  /// ECDSA over the DTBSR (the digest is the message hash, no re-hashing).
  /// Returns raw `r||s`; the core converts it to DER.
  SignatureValue _signEcdsa(EcKeyMaterial key, SignRequest request) {
    final params = pc.ECDomainParameters('secp256r1');
    final signer = pc.ECDSASigner(null, pc.HMac(pc.SHA256Digest(), 64))
      ..init(
        true,
        pc.PrivateKeyParameter<pc.ECPrivateKey>(pc.ECPrivateKey(key.d, params)),
      );
    final sig = signer.generateSignature(request.dtbsr) as pc.ECSignature;
    Uint8List fixed(BigInt v) {
      final out = Uint8List(32);
      var x = v;
      for (var i = 31; i >= 0; i--) {
        out[i] = (x & BigInt.from(0xff)).toInt();
        x >>= 8;
      }
      return out;
    }

    return SignatureValue.raw(
      Uint8List.fromList([...fixed(sig.r), ...fixed(sig.s)]),
    );
  }

  SignatureValue _signRsa(RsaKeyMaterial key, SignRequest request) {
    final digestInfo = request.dtbsrDigestInfo;
    final priv = pc.RSAPrivateKey(key.n, key.d, key.p, key.q);
    final engine = pc.PKCS1Encoding(pc.RSAEngine())
      ..init(true, pc.PrivateKeyParameter<pc.RSAPrivateKey>(priv));
    final sig = engine.process(digestInfo);
    // Cheap fault-attack guard: a bad CRT result must never leave here.
    final check = pc.PKCS1Encoding(pc.RSAEngine())
      ..init(
        false,
        pc.PublicKeyParameter<pc.RSAPublicKey>(pc.RSAPublicKey(key.n, key.e)),
      );
    if (!_equal(check.process(sig), digestInfo)) {
      throw StateError('RSA self-check failed; refusing to return a signature');
    }
    return SignatureValue.raw(sig);
  }
}

final _equal = const ListEquality<int>().equals;
