import 'dart:typed_data';

import 'package:ades/ades.dart' show DigestAlgorithm;
import 'package:pointycastle/asn1.dart';
import 'package:pointycastle/export.dart' as pc;

import 'asn1_read.dart';
import 'key_material.dart';

const _data = '1.2.840.113549.1.7.1';
const _encryptedData = '1.2.840.113549.1.7.6';
const _keyBag = '1.2.840.113549.1.12.10.1.1';
const _shroudedKeyBag = '1.2.840.113549.1.12.10.1.2';
const _certBag = '1.2.840.113549.1.12.10.1.3';
const _x509Cert = '1.2.840.113549.1.9.22.1';

/// What a PKCS#12 file holds: one RSA or P-256 key and certificates, DER.
final class Pkcs12Contents {
  Pkcs12Contents(this.key, this.certificates);

  final SoftKey key;
  final List<Uint8List> certificates;
}

/// Parses a PKCS#12 (PFX) file, DER, password-based integrity and
/// encryption (the OpenSSL and Java defaults: PBES2/AES, or legacy 3DES).
/// Verifies the MAC, so a wrong password is reported as such.
Pkcs12Contents parsePkcs12(Uint8List bytes, String password) {
  try {
    return _parse(bytes, password);
  } on SoftKeyLoadException {
    rethrow;
  } on Object catch (e) {
    // pointycastle reports truncated or inconsistent input in many ways.
    throw malformed('not a valid PKCS#12 file ($e)');
  }
}

Pkcs12Contents _parse(Uint8List bytes, String password) {
  final pfx = asn1Sequence(parseAsn1(bytes, 'PFX'), 'PFX');
  if (pfx.length < 2) throw malformed('PFX too short');
  if (asn1Integer(pfx[0], 'version') != BigInt.from(3)) {
    throw malformed('PFX version must be 3');
  }
  final authSafe = asn1Sequence(pfx[1], 'authSafe');
  if (asn1Oid(authSafe[0], 'authSafe') != _data || !isContext(authSafe[1], 0)) {
    throw const SoftKeyLoadException(
      SoftKeyLoadFailure.unsupported,
      'only password-integrity PKCS#12 (data authSafe) is supported',
    );
  }
  final authSafeBytes = asn1Octets(
    asn1Children(authSafe[1], 'authSafe content').single,
    'authSafe content',
  );
  if (pfx.length > 2) {
    _verifyMac(pfx[2], authSafeBytes, password);
  }
  SoftKey? key;
  final certs = <Uint8List>[];
  final safes = asn1Sequence(
    parseAsn1(authSafeBytes, 'AuthenticatedSafe'),
    'AuthenticatedSafe',
  );
  for (final ci in safes) {
    final c = asn1Sequence(ci, 'ContentInfo');
    final Uint8List safeContents;
    final type = asn1Oid(c[0], 'content type');
    if (type == _data) {
      safeContents = asn1Octets(
        asn1Children(c[1], 'content').single,
        'SafeContents',
      );
    } else if (type == _encryptedData) {
      final ed = asn1Sequence(
        asn1Children(c[1], 'content').single,
        'EncryptedData',
      );
      final eci = asn1Sequence(ed[1], 'EncryptedContentInfo');
      // encryptedContent is [0] IMPLICIT OCTET STRING.
      safeContents = decryptWithAlgorithm(
        eci[1],
        eci[2].valueBytes ?? (throw malformed('empty encryptedContent')),
        password,
      );
    } else {
      continue;
    }
    final bags = asn1Sequence(
      parseAsn1(safeContents, 'SafeContents'),
      'SafeContents',
    );
    for (final bag in bags) {
      final b = asn1Sequence(bag, 'SafeBag');
      final value = asn1Children(b[1], 'bag value').single;
      switch (asn1Oid(b[0], 'bag type')) {
        case _keyBag:
          key ??= parsePkcs8(value.encodedBytes!);
        case _shroudedKeyBag:
          key ??= parseEncryptedPkcs8(value.encodedBytes!, password);
        case _certBag:
          final cb = asn1Sequence(value, 'CertBag');
          if (asn1Oid(cb[0], 'cert type') == _x509Cert) {
            certs.add(
              Uint8List.fromList(
                asn1Octets(asn1Children(cb[1], 'cert').single, 'certificate'),
              ),
            );
          }
      }
    }
  }
  if (key == null) {
    throw const SoftKeyLoadException(
      SoftKeyLoadFailure.incomplete,
      'the PKCS#12 file holds no private key',
    );
  }
  return Pkcs12Contents(key, certs);
}

void _verifyMac(ASN1Object macData, Uint8List content, String password) {
  final m = asn1Sequence(macData, 'MacData');
  final digestInfo = asn1Sequence(m[0], 'DigestInfo');
  final oid = asn1Oid(
    asn1Sequence(digestInfo[0], 'digestAlgorithm')[0],
    'digestAlgorithm',
  );
  final expected = asn1Octets(digestInfo[1], 'digest');
  final salt = asn1Octets(m[1], 'macSalt');
  final iterations = m.length > 2 ? asn1Integer(m[2], 'iterations').toInt() : 1;
  if (iterations < 1 || iterations > 10000000) {
    throw malformed('MAC iteration count out of range');
  }
  final algorithm = DigestAlgorithm.fromOid(oid);
  final pc.Digest Function() mk = switch (algorithm) {
    DigestAlgorithm.sha1 => () => pc.SHA1Digest(),
    DigestAlgorithm.sha256 => () => pc.SHA256Digest(),
    DigestAlgorithm.sha384 => () => pc.SHA384Digest(),
    DigestAlgorithm.sha512 => () => pc.SHA512Digest(),
    null => throw SoftKeyLoadException(
      SoftKeyLoadFailure.unsupported,
      'unsupported PKCS#12 MAC digest $oid',
    ),
  };
  final digest = mk();
  final gen = pc.PKCS12ParametersGenerator(mk())
    ..init(bmpPassword(password), salt, iterations);
  final key = gen.generateDerivedMacParameters(digest.digestSize);
  final hmac = pc.HMac(digest, digest.byteLength)..init(key);
  final actual = hmac.process(content);
  var diff = actual.length ^ expected.length;
  for (var i = 0; i < actual.length && i < expected.length; i++) {
    diff |= actual[i] ^ expected[i];
  }
  if (diff != 0) {
    throw SoftKeyLoadException(
      SoftKeyLoadFailure.wrongPassword,
      'PKCS#12 MAC (${algorithm!.displayName}) mismatch: wrong password or altered file',
    );
  }
}
