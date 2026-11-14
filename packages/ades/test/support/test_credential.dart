// Signing credentials for core tests only (they run on every platform). The
// core library holds no private keys (ADR-0005); keys in tests are the public
// tier-1 fixture keys, and the signing itself is `ades_soft` (which is pure
// Dart and runs on the VM, dart2js and dart2wasm). These wrappers only add what
// tests need on top of it: call counters, a settable certificate/chain/
// algorithm list, and the DER form of an ECDSA signature value.
// ignore_for_file: lines_longer_than_80_chars
import 'dart:convert';
import 'dart:typed_data';

import 'package:ades/ades.dart';
import 'package:ades_soft/ades_soft.dart';

import 'tier1.dart';

/// PKCS#8 of fixtures/tier1/pki/rsa2048/leaf-qsign.key (base64 body).
const _qsignKey =
    'MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCWZrbL2Zo9jMp9eeIwAmn7rOBZNjrBHqZtDJpzqBqOoYvMWW/i/ayRqupvqBMlRpGPnGzUXAuPnAtzM5u6i6ZUTOq4WVgs2e8hCpUX5zHDlWAwPa1mIv4Xb7bsq1mvK5/HsfUJkEth5+ObvJdWbS/adrBy7VmVEQYkKaU+AESXacxJbKnMj3hUag1/CHYWlWOfaOadmUxN9IGUK1rtOYslFrMAyfYr6AVhxXJlqx6JbEI+ZA/5vAKgkKxOyX7ekCVfiUhbSCa72cQe48e0U/UmHkynei52gygfbvunmvubvodXN71Tbj3iDhXyrn+8b1pKbxLLNLSbs9cWeswkvKbvAgMBAAECggEABvXf9dUvPzP51w7B+gjSkNQyWc6Zr4BUoW1Y5IteF0XAq4dkFzQ4PVGUofA8WphGekf5/WX5Hv9QxFcaGOsHmpUos7lmzESVvYi4169abTvHhNQF51ktOzZvV8qiTuoM7ff9aCDmbDSIIxf6RQSul0Sw69CyOaTdDOVkgVcP1ZX8tFWiEu7g1hEWKXdvxnPRs8JqAc7Y4R2Ca552Ew86s0RmlOlyIcWW6UZPeGNXkNI7oXke2XElOT75v4gLbKyy50tX5Hi7Rff3YioXBgKQA3A7R7wDDmpPf+windCDSh67J3IKa5DmGfBl++b7SEulz44fo+Edl13O4j2wbLr/GQKBgQDJO200UOp0oWnkjeYrsrls1nEmiMxFCOLHFbenDvtXDudjAgihfZNS+//V/KESY9Mn8eIFFjsniIw1u+dU87Yqs1uMiF877j9DUdNU2B5qTCK2S6Aij3s1evcp9ll8/ikAb3c/E/TKF9HZjL7sme8QFrlT1FVRAyScj/O+0VCOuwKBgQC/Vbaq3Q1GIWiiRPtcCkFn1rdI4gBfed+3MPpwTN9ErCnsXvl00iRcEBUOuE+vdN8JRh08YwogW3CrtL9O6RGNnz5uGkOBUoVfSACQj/EsJi4ANJQtSm3U6YrDxRR/fZfIY3kZFGaoeOlFveN9QCIVxPntuXJMWAparfsNdZIXXQKBgGw/cXExDc4LfmEaC/T5wVFQ0bE+6VNBgmxBvHc7Uez08XeLAoWMfZGoSWkc6rBvzoiwTzsZSFzt0S6ek8RZDWdO8DJasZAViyZ1f88mKsZXilyxtcShlk+ghBComl7ogbngPC9MVuPXiGUUlyfDbpwi/TKhB/v6StmFfkLpagI9AoGAE4LPFM9j2iHwBJQaOcGF9+vKVvFM7m+EI68n6qm8HsmboNHyiDohoQ22yAB9h7vYPp7avlyvHKuWarwMwiQ8OP/jIuEkvxxGI3g5LoSvKDxgdn7mGVQ8rPh/wQTo2TNadgHGyIrvCQEDcKwzdYNDtoqWnepKQIS90Y9qSW4SzrUCgYBy2D3klt7PLtSW80pftmKcwtdj2ZOB5/sK+KtfTg4OyaQ4K1AKhUud3ShlCKS4sGU4Rul5gA6pRASafy/zCml//8omMOduVR7ExeNPyXp+tany5hAoK5Q1DX7vwOlLVgcyA/2DlbxDqk163QRtjoHco+jWZRx0llxw+MnVHUsRCg==';

/// PKCS#8 of fixtures/tier1/pki/p256/leaf-qsign.key (base64 body).
const _p256Key =
    'MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQggDi01yMxhvkHo9kGsIdtiBxulBUkUxX2Clvmtjh912GhRANCAARPp/ACs4PA6ZQS5Dn5g8/tLcOxPNXECt9aXfdwQ+7U17xAbt2UgSKM7WrY0fVn6aCvJ7/lmwf6W4C5gIx0c+Gf';

String _pem(String label, List<int> der) =>
    '-----BEGIN $label-----\n${base64.encode(der)}\n-----END $label-----\n';

SoftSigningCredential _soft(String keyBase64, String leafPath) =>
    SoftSigningCredential.fromPem(
      privateKeyPem: _pem('PRIVATE KEY', base64.decode(keyBase64)),
      certificatesPem: _pem('CERTIFICATE', tier1(leafPath)),
    );

/// Signs with the tier-1 rsa2048 qualified-signing leaf key. Records calls.
/// [certificatePath] may name a different (even invalid) file to test how
/// the core treats the certificate a credential reports.
final class TestRsaCredential extends SigningCredential {
  TestRsaCredential({
    List<SignatureAlgorithm> algorithms = const [
      SignatureAlgorithm.rsaPkcs1v15Sha256,
    ],
    this.certificatePath = 'pki/rsa2048/leaf-qsign.der',
    this.chainPaths = const [],
  }) : supportedAlgorithms = algorithms;

  final _key = _soft(_qsignKey, 'pki/rsa2048/leaf-qsign.der');
  final String certificatePath;
  final List<String> chainPaths;
  int signCalls = 0;

  @override
  final List<SignatureAlgorithm> supportedAlgorithms;

  @override
  Future<Uint8List> get certificate async => tier1(certificatePath);

  @override
  Future<List<Uint8List>> get chain async => [
    for (final p in chainPaths) tier1(p),
  ];

  @override
  Future<SignatureValue> sign(SignRequest request) {
    signCalls++;
    return _key.sign(request);
  }
}

/// Signs with the tier-1 p256 qualified-signing leaf key. Returns either a
/// raw `r||s` or a DER `Ecdsa-Sig-Value`, as a real vehicle might.
final class TestEcCredential extends SigningCredential {
  TestEcCredential({
    this.derOutput = false,
    this.certificatePath = 'pki/p256/leaf-qsign.der',
    this.chainPaths = const [],
  });

  final _key = _soft(_p256Key, 'pki/p256/leaf-qsign.der');
  final bool derOutput;
  final String certificatePath;
  final List<String> chainPaths;
  int signCalls = 0;
  int batchCalls = 0;

  @override
  final List<SignatureAlgorithm> supportedAlgorithms = const [
    SignatureAlgorithm(SignatureScheme.ecdsa, DigestAlgorithm.sha256),
  ];

  @override
  Future<Uint8List> get certificate async => tier1(certificatePath);

  @override
  Future<List<Uint8List>> get chain async => [
    for (final p in chainPaths) tier1(p),
  ];

  @override
  Future<List<SignatureValue>> signBatch(List<SignRequest> requests) {
    batchCalls++;
    return super.signBatch(requests);
  }

  @override
  Future<SignatureValue> sign(SignRequest request) async {
    signCalls++;
    final raw = await _key.sign(request);
    return derOutput ? SignatureValue.der(_derFromRaw(raw.bytes)) : raw;
  }
}

/// `r||s` (two equal halves) as a DER `Ecdsa-Sig-Value`.
Uint8List _derFromRaw(Uint8List raw) {
  Uint8List integer(Uint8List half) {
    var i = 0;
    while (i < half.length - 1 && half[i] == 0) {
      i++;
    }
    final body = [if (half[i] & 0x80 != 0) 0, ...half.sublist(i)];
    return Uint8List.fromList([0x02, body.length, ...body]);
  }

  final n = raw.length ~/ 2;
  final r = integer(raw.sublist(0, n));
  final s = integer(raw.sublist(n));
  return Uint8List.fromList([0x30, r.length + s.length, ...r, ...s]);
}
