import 'dart:typed_data';

import '../asn1/asn1.dart';
import '../bytes.dart';
import '../asn1/structure.dart';
import '../cms/signed_data.dart';
import '../crypto/algorithms.dart';
import '../crypto/crypto_provider.dart';
import '../crypto/public_key.dart';
import '../crypto/stream_digester.dart';
import '../x509/certificate.dart';
import '../x509/time.dart';
import '../x509/trust_anchor.dart';
import 'diagnostic_data.dart';
import 'indication.dart';
import 'warning.dart';

/// Collect stage: parses [bytes] and gathers every fact decide needs.
/// Never throws on bad input; reports it in [DiagnosticData.formatFailure].
Future<DiagnosticData> collectDiagnosticData(
  Uint8List bytes, {
  required CryptoProvider crypto,
  required List<TrustAnchor> trustAnchors,
  List<X509Certificate> pool = const [],
  Uint8List? detachedContent,
}) => _collect(
  () async => CmsSignedData.parse(bytes),
  detachedContent: detachedContent,
  crypto: crypto,
  trustAnchors: trustAnchors,
  pool: pool,
);

/// Like [collectDiagnosticData] for a stream: the encapsulated content is
/// hashed while it is read and never held in memory.
Future<DiagnosticData> collectDiagnosticDataStream(
  Stream<List<int>> input, {
  required CryptoProvider crypto,
  required List<TrustAnchor> trustAnchors,
  List<X509Certificate> pool = const [],
  Stream<List<int>>? detachedContent,
}) => _collect(
  () => CmsSignedData.parseStream(input, crypto: crypto),
  detachedContent: null,
  detachedStream: detachedContent,
  crypto: crypto,
  trustAnchors: trustAnchors,
  pool: pool,
);

Future<DiagnosticData> _collect(
  Future<CmsSignedData> Function() read, {
  required CryptoProvider crypto,
  required List<TrustAnchor> trustAnchors,
  required List<X509Certificate> pool,
  required Uint8List? detachedContent,
  Stream<List<int>>? detachedStream,
}) async {
  final CmsSignedData cms;
  try {
    cms = await read();
  } on Asn1Exception catch (e) {
    return _failure('invalid encoding: $e');
  } on StructureException catch (e) {
    return _failure(e.message);
  } on Object catch (e) {
    // Hostile input must never escape as an exception.
    return _failure('unreadable input: $e');
  }
  if (cms.signerInfos.isEmpty) return _failure('no SignerInfo present');

  final certs = <X509Certificate>[];
  final certDiags = <CertificateDiagnostic>[];
  for (final der in cms.certificates) {
    try {
      final c = X509Certificate.parse(der);
      certs.add(c);
      certDiags.add(_certDiag('C-${certDiags.length}', c, trustAnchors));
    } on Object {
      // An unparseable certificate is ignored; if it was the signer's, ISC
      // reports the signing certificate as not found.
    }
  }

  // A streamed detached document is read once, here, hashed for every digest
  // algorithm the signatures use. A document for an enveloping signature is
  // ignored (and not read). An error of the document stream propagates: it
  // is the caller's I/O, not a malformed signature.
  _StreamedDocument? streamed;
  if (cms.contentLength == null && detachedStream != null) {
    streamed = await _digestDocument(detachedStream, cms, crypto);
  }

  final signatures = <SignatureDiagnostic>[];
  for (var i = 0; i < cms.signerInfos.length; i++) {
    signatures.add(
      await _collectSignature(
        i,
        cms,
        cms.signerInfos[i],
        certs,
        certDiags,
        crypto,
        trustAnchors,
        pool,
        detachedContent,
        streamed,
      ),
    );
  }
  return DiagnosticData(
    formatFailure: null,
    certificates: List.unmodifiable(certDiags),
    signatures: List.unmodifiable(signatures),
    warnings: List.unmodifiable([for (final d in cms.deviations) _warning(d)]),
  );
}

/// A detached document that was hashed while it was read.
final class _StreamedDocument {
  _StreamedDocument(this.length, this.digests);

  final int length;
  final Map<DigestAlgorithm, Uint8List> digests;
}

Future<_StreamedDocument> _digestDocument(
  Stream<List<int>> document,
  CmsSignedData cms,
  CryptoProvider crypto,
) async {
  final algorithms = {
    for (final si in cms.signerInfos)
      if (DigestAlgorithm.fromOid(si.digestAlgorithmOid)
          case final DigestAlgorithm a)
        a,
  };
  final digesters = {for (final a in algorithms) a: StreamDigester(crypto, a)};
  var length = 0;
  try {
    await for (final chunk in document) {
      length += chunk.length;
      for (final d in digesters.values) {
        d.add(chunk);
      }
    }
  } on Object {
    for (final d in digesters.values) {
      d.abort();
    }
    rethrow;
  }
  return _StreamedDocument(length, {
    for (final e in digesters.entries) e.key: await e.value.finish(),
  });
}

ValidationWarning _warning(BerDeviation d) {
  final code = switch (d.kind) {
    Asn1ErrorKind.indefiniteLength => WarningCode.indefiniteLength,
    Asn1ErrorKind.nonMinimalLength ||
    Asn1ErrorKind.nonMinimalTag ||
    Asn1ErrorKind.nonMinimalInteger => WarningCode.nonMinimalEncoding,
    Asn1ErrorKind.constructedNotAllowed => WarningCode.constructedString,
    Asn1ErrorKind.unsortedSet => WarningCode.unsortedSet,
    _ => WarningCode.nonDerEncoding,
  };
  return ValidationWarning(code, '${d.message} (offset ${d.offset})');
}

DiagnosticData _failure(String why) => DiagnosticData(
  formatFailure: why,
  certificates: const [],
  signatures: const [],
);

Future<SignatureDiagnostic> _collectSignature(
  int index,
  CmsSignedData cms,
  CmsSignerInfo si,
  List<X509Certificate> certs,
  List<CertificateDiagnostic> certDiags,
  CryptoProvider crypto,
  List<TrustAnchor> trustAnchors,
  List<X509Certificate> pool,
  Uint8List? detachedContent,
  _StreamedDocument? streamedDocument,
) async {
  final issues = <MessageCode>[];
  final attrs = si.signedAttributes;
  final digestAlg = DigestAlgorithm.fromOid(si.digestAlgorithmOid);

  Asn1Element? single(String oid, MessageCode missing) {
    final v = attrs?.byOid[oid];
    if (v == null || v.isEmpty) {
      issues.add(missing);
      return null;
    }
    if (v.length > 1) {
      issues.add(MessageCode.duplicateAttribute);
      return null;
    }
    return v.single;
  }

  String? contentTypeAttr;
  Uint8List? messageDigestAttr;
  DateTime? signingTime;
  try {
    final ct = single(CmsOids.contentType, MessageCode.missingContentType);
    contentTypeAttr = ct?.asOid;
    final md = single(CmsOids.messageDigest, MessageCode.missingMessageDigest);
    messageDigestAttr = md?.asOctetString;
    final st = attrs?.byOid[CmsOids.signingTime];
    if (st != null && st.length == 1) {
      signingTime = parseAsn1Time(st.single, 'signingTime');
    }
  } on Object {
    issues.add(MessageCode.malformedInput);
  }
  if (contentTypeAttr != null && contentTypeAttr != cms.contentType) {
    issues.add(MessageCode.contentTypeMismatch);
  }
  if (attrs == null) {
    issues
      ..clear()
      ..add(MessageCode.malformedInput);
  }

  // Signing certificate identification.
  int? certIdx;
  for (var i = 0; i < certs.length; i++) {
    if (_matchesSid(si.identifier, certs[i])) {
      certIdx = i;
      break;
    }
  }

  // Signing certificate reference.
  SigningCertificateReference? ref;
  bool? refMatches;
  try {
    ref = await _parseReference(
      attrs,
      certIdx == null ? null : certs[certIdx],
      crypto,
    );
  } on Object {
    issues.add(MessageCode.malformedInput);
  }
  if (ref != null && certIdx != null) {
    final alg = ref.hashAlgorithm;
    if (alg == null) {
      refMatches = false;
    } else {
      final h = await crypto.digest(alg, certs[certIdx].der);
      refMatches = bytesEqual(h, ref.certHash);
    }
  }

  // Content and message digest. In-memory input is hashed here; streamed
  // input was hashed while reading, for the algorithms the SignedData lists.
  // A document supplied for an enveloping signature is ignored.
  final isDetached = cms.contentLength == null;
  final content = cms.content ?? detachedContent;
  final contentLength =
      cms.contentLength ?? detachedContent?.length ?? streamedDocument?.length;
  final scopeKind = isDetached
      ? SignatureScopeKind.detachedDocument
      : SignatureScopeKind.envelopedContent;
  final scopeName = isDetached ? 'Detached document' : 'Enveloped content';
  final scopeDescription = isDetached
      ? 'The document supplied alongside the detached signature'
      : 'The content encapsulated in the CMS SignedData';
  bool? mdMatches;
  SignatureScope? scope;
  if (contentLength != null) {
    Uint8List? h;
    if (digestAlg != null) {
      h = content != null
          ? await crypto.digest(digestAlg, content)
          : cms.contentDigests[digestAlg] ??
                streamedDocument?.digests[digestAlg];
      if (messageDigestAttr != null) {
        mdMatches = h != null && bytesEqual(h, messageDigestAttr);
      }
    }
    scope = SignatureScope(
      kind: scopeKind,
      name: scopeName,
      description: scopeDescription,
      length: contentLength,
      digestAlgorithm: h == null ? null : digestAlg,
      digest: h,
    );
  }

  // Cryptographic check.
  SignatureCheckStatus? check;
  if (certIdx != null && attrs != null) {
    check = await _checkSignature(
      si,
      attrs.dtbs,
      digestAlg,
      certs[certIdx],
      crypto,
    );
  }

  List<String>? chain;
  if (certIdx != null) {
    chain = await _buildPath(
      certs[certIdx],
      certs,
      certDiags,
      trustAnchors,
      pool,
      crypto,
    );
  }

  return SignatureDiagnostic(
    index: index,
    formatIssues: List.unmodifiable(issues),
    digestAlgorithmOid: si.digestAlgorithmOid,
    signatureAlgorithmOid: si.signatureAlgorithmOid,
    signedAttributesPresent: attrs != null,
    signedAttributesDer: attrs?.isDer ?? false,
    signingTime: signingTime,
    signingCertificateReference: ref,
    signingCertificateId: certIdx == null ? null : certDiags[certIdx].id,
    signingCertificateReferenceMatches: refMatches,
    contentAvailable: contentLength != null,
    messageDigestMatches: mdMatches,
    signatureCheck: check,
    scope: scope,
    certificateChain: chain,
  );
}

CertificateDiagnostic _certDiag(
  String id,
  X509Certificate c,
  List<TrustAnchor> anchors,
) => CertificateDiagnostic(
  id: id,
  der: c.der,
  subject: c.subject,
  issuer: c.issuer,
  serialNumber: c.serialNumber.toRadixString(16),
  notBefore: c.notBefore,
  notAfter: c.notAfter,
  trustAnchor: anchors.any((a) => bytesEqual(a.certificate.der, c.der)),
  keyUsage: c.keyUsage,
  basicConstraints: c.basicConstraints,
  signatureAlgorithmOid: c.signatureAlgorithmOid,
  publicKeyAlgorithm: switch (c.publicKey) {
    RsaPublicKey() => PublicKeyAlgorithm.rsa,
    EcPublicKey() => PublicKeyAlgorithm.ecdsa,
    UnsupportedPublicKey() => PublicKeyAlgorithm.unsupported,
  },
  publicKeySize: switch (c.publicKey) {
    final RsaPublicKey k => k.modulusBitLength,
    final EcPublicKey k => k.curve.bits,
    UnsupportedPublicKey() => null,
  },
);

const _maxPathLength = 10;
const _maxSignatureChecks = 64;

/// Builds a certification path (RFC 5280 6.1 style) from [signer] to a trust
/// anchor: candidates are matched on issuer/subject name bytes and kept only
/// when the issuer's key verifies the certificate signature. Anchors are
/// tried first. Returns the certificate ids, signer first, anchor last, and
/// registers certificates taken from the pool or the anchors in [certDiags].
/// Validity, key usage and constraints are judged later by decide.
Future<List<String>?> _buildPath(
  X509Certificate signer,
  List<X509Certificate> embedded,
  List<CertificateDiagnostic> certDiags,
  List<TrustAnchor> anchors,
  List<X509Certificate> pool,
  CryptoProvider crypto,
) async {
  final candidates = <X509Certificate>[];
  for (final c in [
    ...anchors.map((a) => a.certificate),
    ...embedded,
    ...pool,
  ]) {
    if (!candidates.any((o) => bytesEqual(o.der, c.der))) candidates.add(c);
  }
  var budget = _maxSignatureChecks;

  bool isAnchor(X509Certificate c) =>
      anchors.any((a) => bytesEqual(a.certificate.der, c.der));

  Future<List<X509Certificate>?> extend(List<X509Certificate> path) async {
    final cur = path.last;
    if (isAnchor(cur)) return path;
    if (path.length >= _maxPathLength) return null;
    for (final cand in candidates) {
      if (!bytesEqual(cand.subjectDer, cur.issuerDer)) continue;
      if (path.any((p) => bytesEqual(p.der, cand.der))) continue;
      if (budget-- <= 0) return null;
      if (!await _issuedBy(cur, cand, crypto)) continue;
      final found = await extend([...path, cand]);
      if (found != null) return found;
    }
    return null;
  }

  final path = await extend([signer]);
  if (path == null) return null;
  final ids = <String>[];
  for (final c in path) {
    var idx = certDiags.indexWhere((d) => bytesEqual(d.der, c.der));
    if (idx < 0) {
      certDiags.add(
        _certDiag('${isAnchor(c) ? 'A' : 'P'}-${certDiags.length}', c, anchors),
      );
      idx = certDiags.length - 1;
    }
    ids.add(certDiags[idx].id);
  }
  return ids;
}

/// Whether [issuer]'s public key verifies the signature on [cert].
Future<bool> _issuedBy(
  X509Certificate cert,
  X509Certificate issuer,
  CryptoProvider crypto,
) async {
  final algorithm = SignatureAlgorithm.fromOid(cert.signatureAlgorithmOid);
  if (algorithm == null) return false;
  try {
    return await crypto.verify(
      algorithm: algorithm,
      key: issuer.publicKey,
      message: cert.tbsBytes,
      signature: cert.signatureValue,
    );
  } on Object {
    return false;
  }
}

bool _matchesSid(SignerIdentifier sid, X509Certificate c) => switch (sid) {
  IssuerAndSerial() =>
    bytesEqual(sid.issuerDer, c.issuerDer) &&
        sid.serialNumber == c.serialNumber,
  SubjectKeyId() =>
    c.subjectKeyIdentifier != null &&
        bytesEqual(sid.keyId, c.subjectKeyIdentifier!),
};

Future<SigningCertificateReference?> _parseReference(
  CmsSignedAttributes? attrs,
  X509Certificate? signer,
  CryptoProvider crypto,
) async {
  if (attrs == null) return null;
  final v2 = attrs.byOid[CmsOids.signingCertificateV2];
  final v1 = attrs.byOid[CmsOids.signingCertificate];
  final isV2 = v2 != null && v2.isNotEmpty;
  final values = isV2 ? v2 : v1;
  if (values == null || values.isEmpty) return null;
  if (values.length != 1) throw const StructureException('duplicate attribute');
  final sc = values.single.sequenceOf('SigningCertificate');
  final certs = sc.first.sequenceOf('certs');
  if (certs.isEmpty) throw const StructureException('empty certs');
  final id = certs.first.sequenceOf('ESSCertID');
  var i = 0;
  DigestAlgorithm? alg = isV2 ? DigestAlgorithm.sha256 : DigestAlgorithm.sha1;
  if (isV2 && id[i].tag == Asn1Tag.sequence) {
    final p = id[i++].sequenceOf('hashAlgorithm');
    alg = DigestAlgorithm.fromOid(p[0].asOid);
  }
  final hash = id[i++].asOctetString;
  bool? issuerSerial;
  if (i < id.length && signer != null) {
    final is_ = id[i].sequenceOf('IssuerSerial');
    final gns = is_[0].sequenceOf('GeneralNames');
    final serial = is_[1].expect(Asn1Tag.integer, 'serialNumber').asInteger;
    final dir = gns.where((g) => g.isContext(4)).toList();
    issuerSerial =
        serial == signer.serialNumber &&
        dir.length == 1 &&
        bytesEqual(dir.single.children!.single.encoded, signer.issuerDer);
  }
  return SigningCertificateReference(
    version: isV2 ? 2 : 1,
    hashAlgorithm: alg,
    certHash: hash,
    issuerSerialMatches: issuerSerial,
  );
}

Future<SignatureCheckStatus> _checkSignature(
  CmsSignerInfo si,
  Uint8List dtbs,
  DigestAlgorithm? digestAlg,
  X509Certificate signingCertificate,
  CryptoProvider crypto,
) async {
  final algorithm = SignatureAlgorithm.forCms(
    si.signatureAlgorithmOid,
    digestAlg,
  );
  if (algorithm == null) return SignatureCheckStatus.unsupported;
  try {
    final ok = await crypto.verify(
      algorithm: algorithm,
      key: signingCertificate.publicKey,
      message: dtbs,
      signature: si.signature,
    );
    return ok ? SignatureCheckStatus.verified : SignatureCheckStatus.invalid;
  } on UnsupportedAlgorithmException {
    return SignatureCheckStatus.unsupported;
  }
}
