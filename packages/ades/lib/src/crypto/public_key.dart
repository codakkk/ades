/// A certificate's subject public key as far as the validator understands it.
///
/// Sealed so that adding a key type (ECDSA, ticket 07) makes every `switch`
/// over keys fail to compile until it is handled.
sealed class PublicKey {
  const PublicKey();
}

/// An RSA public key.
final class RsaPublicKey extends PublicKey {
  const RsaPublicKey(this.modulus, this.exponent);

  final BigInt modulus;
  final BigInt exponent;

  int get modulusBitLength => modulus.bitLength;
}

/// Elliptic curves the default provider verifies.
enum EcCurve {
  p256('1.2.840.10045.3.1.7', 'secp256r1', 'P-256', 256),
  p384('1.3.132.0.34', 'secp384r1', 'P-384', 384),
  p521('1.3.132.0.35', 'secp521r1', 'P-521', 521);

  const EcCurve(this.oid, this.registryName, this.displayName, this.bits);

  final String oid;
  final String registryName;
  final String displayName;

  /// Size of the curve's field in bits (the key size policy judges).
  final int bits;

  static EcCurve? fromOid(String oid) {
    for (final c in values) {
      if (c.oid == oid) return c;
    }
    return null;
  }
}

/// An ECDSA public key: an affine point [x], [y] on [curve].
final class EcPublicKey extends PublicKey {
  const EcPublicKey(this.curve, this.x, this.y);

  final EcCurve curve;
  final BigInt x;
  final BigInt y;
}

/// A key whose algorithm this version does not support (kept so that such
/// certificates still parse; verifying with it is reported as unsupported).
final class UnsupportedPublicKey extends PublicKey {
  const UnsupportedPublicKey(this.algorithmOid);

  final String algorithmOid;
}
