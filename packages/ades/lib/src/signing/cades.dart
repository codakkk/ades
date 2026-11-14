import 'dart:convert';
import 'dart:typed_data';

import '../asn1/asn1.dart';
import '../cms/signed_data.dart';
import '../crypto/algorithms.dart';
import '../crypto/crypto_provider.dart';
import '../crypto/default_crypto_provider.dart';
import '../crypto/stream_digester.dart';
import '../crypto/public_key.dart';
import '../x509/certificate.dart';
import 'credential.dart';
import 'exceptions.dart';
import 'signed_attributes.dart';

/// What a [SignatureDraft] will become. Closed; further formats add values.
enum SignatureDraftKind {
  /// CAdES-B-B, enveloping (`.p7m`): the document is inside the signature.
  cadesEnveloping('cades-enveloping'),

  /// CAdES-B-B, detached (`.p7s`): the document stays outside.
  cadesDetached('cades-detached');

  const SignatureDraftKind(this.id);

  /// Stable name used in the serialized form.
  final String id;
}

/// The immutable result of the first phase of signing (GLOSSARY): chosen
/// parameters, frozen signing time, document digest and DTBS.
///
/// It does not hold the document, so completion needs the document again.
/// It holds no secret, so it can be stored or sent between server and
/// client while the signature value is produced elsewhere or later.
///
/// Serialized form (see [toJson]): a JSON object with `format`
/// (`ades.signature-draft`), `version` (1), `kind`, `signatureAlgorithm`
/// (`scheme`, `digest`), `signingTime` (ISO 8601 UTC), `signingCertificate`,
/// `chain`, `documentDigest` and `dtbs` (all base64). [fromJson] re-derives
/// the DTBS from the other fields and rejects a draft that disagrees, so a
/// tampered or corrupted draft cannot reach the credential.
final class SignatureDraft {
  SignatureDraft._({
    required this.kind,
    required this.signatureAlgorithm,
    required Uint8List signingCertificate,
    required List<Uint8List> chain,
    required this.signingTime,
    required Uint8List documentDigest,
    required Uint8List dtbs,
  }) : signingCertificate = _frozen(signingCertificate),
       chain = List.unmodifiable([for (final c in chain) _frozen(c)]),
       documentDigest = _frozen(documentDigest),
       dtbs = _frozen(dtbs);

  /// Reads a draft produced by [toJson].
  ///
  /// Throws [InvalidDraftException] for a wrong format or version, bad
  /// values, a policy-violating algorithm or a DTBS that does not match the
  /// other fields.
  static Future<SignatureDraft> fromJson(
    Map<String, Object?> json, {
    CryptoProvider crypto = const DefaultCryptoProvider(),
  }) async {
    try {
      if (json['format'] != _format || json['version'] != _version) {
        throw const InvalidDraftException('not a version 1 signature draft');
      }
      final kind = SignatureDraftKind.values.firstWhere(
        (k) => k.id == json['kind'],
        orElse: () => throw const InvalidDraftException('unknown draft kind'),
      );
      final alg = json['signatureAlgorithm'] as Map<String, Object?>;
      final scheme = SignatureScheme.values.firstWhere(
        (s) => s.name == alg['scheme'],
        orElse: () => throw const InvalidDraftException('unknown scheme'),
      );
      final digest = DigestAlgorithm.values.firstWhere(
        (d) => d.name == alg['digest'],
        orElse: () => throw const InvalidDraftException('unknown digest'),
      );
      final time = DateTime.parse(json['signingTime'] as String);
      if (!time.isUtc) {
        throw const InvalidDraftException('signingTime must be UTC');
      }
      Uint8List b64(Object? v) => base64.decode(v as String);
      final draft = SignatureDraft._(
        kind: kind,
        signatureAlgorithm: SignatureAlgorithm(scheme, digest),
        signingCertificate: b64(json['signingCertificate']),
        chain: [for (final c in json['chain'] as List<Object?>) b64(c)],
        signingTime: time,
        documentDigest: b64(json['documentDigest']),
        dtbs: b64(json['dtbs']),
      );
      _checkPolicy(draft.signatureAlgorithm);
      final cert = _parseCertificate(draft.signingCertificate);
      _checkKey(cert);
      _checkFits(draft.signatureAlgorithm, cert);
      final expected = buildSignedAttributesDtbs(
        contentTypeOid: CmsOids.data,
        messageDigest: draft.documentDigest,
        signingTime: time,
        signingCertificateSha256: await crypto.digest(
          DigestAlgorithm.sha256,
          draft.signingCertificate,
        ),
        signingCertificate: cert,
      );
      if (!_equal(expected, draft.dtbs)) {
        throw const InvalidDraftException(
          'dtbs does not match the draft fields',
        );
      }
      return draft;
    } on AdesException catch (e) {
      if (e is InvalidDraftException) rethrow;
      throw InvalidDraftException(e.message);
    } on Object catch (e) {
      throw InvalidDraftException('malformed signature draft: $e');
    }
  }

  static const _format = 'ades.signature-draft';
  static const _version = 1;

  final SignatureDraftKind kind;
  final SignatureAlgorithm signatureAlgorithm;

  /// The signing (leaf) certificate, DER.
  final Uint8List signingCertificate;

  /// Further certificates to embed, DER, leaf excluded.
  final List<Uint8List> chain;

  /// The claimed signing time, frozen at the first phase, whole seconds UTC.
  final DateTime signingTime;

  /// Hash of the document under the signature's digest algorithm.
  final Uint8List documentDigest;

  /// The data to be signed: the DER signed attributes.
  final Uint8List dtbs;

  /// What a signing credential is asked to sign for this draft.
  Future<SignRequest> signRequest({
    CryptoProvider crypto = const DefaultCryptoProvider(),
  }) async => SignRequest(
    dtbs: dtbs,
    dtbsr: await crypto.digest(signatureAlgorithm.digest, dtbs),
    signatureAlgorithm: signatureAlgorithm,
  );

  /// JSON-ready map (strings, numbers, lists, maps only).
  Map<String, Object?> toJson() => {
    'format': _format,
    'version': _version,
    'kind': kind.id,
    'signatureAlgorithm': {
      'scheme': signatureAlgorithm.scheme.name,
      'digest': signatureAlgorithm.digest.name,
    },
    'signingTime': signingTime.toIso8601String(),
    'signingCertificate': base64.encode(signingCertificate),
    'chain': [for (final c in chain) base64.encode(c)],
    'documentDigest': base64.encode(documentDigest),
    'dtbs': base64.encode(dtbs),
  };
}

/// CAdES-B-B creation (two-phase signing).
///
/// Phase 1 ([prepareEnveloping]) returns a [SignatureDraft]; a signing
/// credential signs [SignatureDraft.signRequest]; phase 2 ([complete])
/// assembles the signature. Ticket 10 adds detached, ECDSA and the one-call
/// sign; ticket 11 adds streams.
abstract final class Cades {
  /// Phase 1 for an enveloping CAdES-B-B signature over [document].
  ///
  /// Checks, in this order and before [credential] is asked to sign
  /// anything: digest policy, certificate, key policy, credential support.
  /// The signing time is [signingTime] or now, truncated to whole seconds
  /// UTC, and frozen in the draft.
  ///
  /// Throws:
  /// - [WeakDigestException] for SHA-1;
  /// - [InvalidCertificateException] when the credential's certificate or
  ///   chain is not parsable;
  /// - [WeakKeyException] for RSA below 2048 bits;
  /// - [UnsupportedCredentialAlgorithmException] when [algorithm] is not in
  ///   `credential.supportedAlgorithms` or does not fit the certificate key.
  static Future<SignatureDraft> prepareEnveloping({
    required Uint8List document,
    required SigningCredential credential,
    SignatureAlgorithm algorithm = SignatureAlgorithm.rsaPkcs1v15Sha256,
    DateTime? signingTime,
    CryptoProvider crypto = const DefaultCryptoProvider(),
  }) => _prepare(
    SignatureDraftKind.cadesEnveloping,
    document,
    credential,
    algorithm,
    signingTime,
    crypto,
  );

  /// Phase 1 for a detached CAdES-B-B signature (`.p7s`) over [document].
  /// Same checks and exceptions as [prepareEnveloping]; the completed
  /// signature does not contain the document, so validation needs it again.
  static Future<SignatureDraft> prepareDetached({
    required Uint8List document,
    required SigningCredential credential,
    SignatureAlgorithm algorithm = SignatureAlgorithm.rsaPkcs1v15Sha256,
    DateTime? signingTime,
    CryptoProvider crypto = const DefaultCryptoProvider(),
  }) => _prepare(
    SignatureDraftKind.cadesDetached,
    document,
    credential,
    algorithm,
    signingTime,
    crypto,
  );

  /// One call: [prepareEnveloping] (or [prepareDetached] when [detached]),
  /// the credential's `sign`, then [complete]. A failure inside the
  /// credential is wrapped in [SigningFailedException].
  static Future<Uint8List> sign({
    required Uint8List document,
    required SigningCredential credential,
    SignatureAlgorithm algorithm = SignatureAlgorithm.rsaPkcs1v15Sha256,
    bool detached = false,
    DateTime? signingTime,
    CryptoProvider crypto = const DefaultCryptoProvider(),
  }) async {
    final draft = await _prepare(
      detached
          ? SignatureDraftKind.cadesDetached
          : SignatureDraftKind.cadesEnveloping,
      document,
      credential,
      algorithm,
      signingTime,
      crypto,
    );
    final SignatureValue value;
    try {
      value = await credential.sign(await draft.signRequest(crypto: crypto));
    } on AdesException {
      rethrow;
    } on Object catch (e) {
      throw SigningFailedException('the credential failed to sign', cause: e);
    }
    return complete(
      draft: draft,
      value: value,
      document: document,
      crypto: crypto,
    );
  }

  /// Signs each of [documents] with one `credential.signBatch` call (the
  /// credential may sign them under a single authorization). All drafts are
  /// prepared, and so all checks pass, before the credential is called.
  /// Results are in the order of [documents].
  static Future<List<Uint8List>> signBatch({
    required List<Uint8List> documents,
    required SigningCredential credential,
    SignatureAlgorithm algorithm = SignatureAlgorithm.rsaPkcs1v15Sha256,
    bool detached = false,
    DateTime? signingTime,
    CryptoProvider crypto = const DefaultCryptoProvider(),
  }) async {
    final kind = detached
        ? SignatureDraftKind.cadesDetached
        : SignatureDraftKind.cadesEnveloping;
    final drafts = [
      for (final d in documents)
        await _prepare(kind, d, credential, algorithm, signingTime, crypto),
    ];
    final requests = [
      for (final d in drafts) await d.signRequest(crypto: crypto),
    ];
    final List<SignatureValue> values;
    try {
      values = await credential.signBatch(requests);
    } on AdesException {
      rethrow;
    } on Object catch (e) {
      throw SigningFailedException('the credential failed to sign', cause: e);
    }
    if (values.length != drafts.length) {
      throw const SigningFailedException(
        'the credential returned the wrong number of signature values',
      );
    }
    return [
      for (var i = 0; i < drafts.length; i++)
        await complete(
          draft: drafts[i],
          value: values[i],
          document: documents[i],
          crypto: crypto,
        ),
    ];
  }

  /// [prepareEnveloping] for a document that does not fit in memory: it is
  /// read once from [document] and hashed on the fly, never buffered. The
  /// checks (and their order) are the same and run before the stream is
  /// listened to. The result is identical to [prepareEnveloping] over the
  /// same bytes.
  ///
  /// Completion needs the document again with its exact length: see
  /// [completeEnvelopingStream].
  static Future<SignatureDraft> prepareEnvelopingStream({
    required Stream<List<int>> document,
    required SigningCredential credential,
    SignatureAlgorithm algorithm = SignatureAlgorithm.rsaPkcs1v15Sha256,
    DateTime? signingTime,
    CryptoProvider crypto = const DefaultCryptoProvider(),
  }) => _prepareWith(
    SignatureDraftKind.cadesEnveloping,
    () => crypto.digestStream(algorithm.digest, document),
    credential,
    algorithm,
    signingTime,
    crypto,
  );

  static Future<SignatureDraft> _prepare(
    SignatureDraftKind kind,
    Uint8List document,
    SigningCredential credential,
    SignatureAlgorithm algorithm,
    DateTime? signingTime,
    CryptoProvider crypto,
  ) => _prepareWith(
    kind,
    () => crypto.digest(algorithm.digest, document),
    credential,
    algorithm,
    signingTime,
    crypto,
  );

  static Future<SignatureDraft> _prepareWith(
    SignatureDraftKind kind,
    Future<Uint8List> Function() digestDocument,
    SigningCredential credential,
    SignatureAlgorithm algorithm,
    DateTime? signingTime,
    CryptoProvider crypto,
  ) async {
    _checkPolicy(algorithm);
    final certDer = Uint8List.fromList(await credential.certificate);
    final chain = [
      for (final c in await credential.chain) Uint8List.fromList(c),
    ];
    final cert = _parseCertificate(certDer);
    for (final c in chain) {
      _parseCertificate(c);
    }
    _checkKey(cert);
    _checkFits(algorithm, cert);
    if (!credential.supportedAlgorithms.contains(algorithm)) {
      throw UnsupportedCredentialAlgorithmException(
        'the credential does not support $algorithm',
      );
    }
    final time = _wholeSecondsUtc(signingTime ?? DateTime.now());
    final documentDigest = await digestDocument();
    final dtbs = buildSignedAttributesDtbs(
      contentTypeOid: CmsOids.data,
      messageDigest: documentDigest,
      signingTime: time,
      signingCertificateSha256: await crypto.digest(
        DigestAlgorithm.sha256,
        certDer,
      ),
      signingCertificate: cert,
    );
    return SignatureDraft._(
      kind: kind,
      signatureAlgorithm: algorithm,
      signingCertificate: certDer,
      chain: chain,
      signingTime: time,
      documentDigest: documentDigest,
      dtbs: dtbs,
    );
  }

  /// Phase 2: assembles the signature (DER CMS ContentInfo, `.p7m`) from
  /// [draft], the [document] it was prepared for and the [value] a signing
  /// credential produced for [SignatureDraft.signRequest].
  ///
  /// The value is verified against the draft's signing certificate and DTBS
  /// before anything is assembled, so a mix-up cannot yield a wrong
  /// signature.
  ///
  /// Throws [DraftMismatchException] when [document] is not the document the
  /// draft was prepared for, when [value] is not in the encoding the
  /// algorithm needs, or when [value] is not a valid signature over the
  /// draft's DTBS.
  static Future<Uint8List> complete({
    required SignatureDraft draft,
    required SignatureValue value,
    required Uint8List document,
    CryptoProvider crypto = const DefaultCryptoProvider(),
  }) async {
    final alg = draft.signatureAlgorithm;
    final actual = await crypto.digest(alg.digest, document);
    if (!_equal(actual, draft.documentDigest)) {
      throw const DraftMismatchException(
        'the document is not the one the draft was prepared for',
      );
    }
    final (cert, signature) = await _checkValue(draft, value, crypto);
    final frame = _frame(draft, cert, signature, document.length);
    final withDocument = draft.kind == SignatureDraftKind.cadesEnveloping;
    final out = Uint8List(
      frame.prefix.length +
          (withDocument ? document.length : 0) +
          frame.suffix.length,
    );
    out.setRange(0, frame.prefix.length, frame.prefix);
    var p = frame.prefix.length;
    if (withDocument) {
      out.setRange(p, p + document.length, document);
      p += document.length;
    }
    out.setRange(p, out.length, frame.suffix);
    return out;
  }

  /// Phase 2 as a stream, for an enveloping signature over a document that
  /// does not fit in memory: emits the same bytes as [complete] (DER,
  /// definite lengths) in chunks while reading [document] once, in bounded
  /// memory.
  ///
  /// Definite lengths need the size up front: [documentLength] must be the
  /// exact number of bytes [document] yields. The signature [value] is
  /// verified before the first byte is emitted. The document itself can only
  /// be checked as it flows: if it does not match the draft (digest or
  /// length), the stream ends with a [DraftMismatchException] before the
  /// final bytes are emitted, so the output is truncated and must be
  /// discarded.
  static Stream<Uint8List> completeEnvelopingStream({
    required SignatureDraft draft,
    required SignatureValue value,
    required Stream<List<int>> document,
    required int documentLength,
    CryptoProvider crypto = const DefaultCryptoProvider(),
  }) async* {
    if (documentLength < 0) {
      throw ArgumentError.value(documentLength, 'documentLength');
    }
    if (draft.kind != SignatureDraftKind.cadesEnveloping) {
      throw const DraftMismatchException(
        'only an enveloping draft can be completed as a stream',
      );
    }
    final (cert, signature) = await _checkValue(draft, value, crypto);
    final frame = _frame(draft, cert, signature, documentLength);
    final digester = StreamDigester(crypto, draft.signatureAlgorithm.digest);
    var count = 0;
    var finished = false;
    try {
      yield frame.prefix;
      await for (final chunk in document) {
        count += chunk.length;
        if (count > documentLength) {
          throw const DraftMismatchException(
            'the document is longer than documentLength',
          );
        }
        digester.add(chunk);
        yield chunk is Uint8List ? chunk : Uint8List.fromList(chunk);
      }
      if (count != documentLength) {
        throw const DraftMismatchException(
          'the document is shorter than documentLength',
        );
      }
      finished = true;
      if (!_equal(await digester.finish(), draft.documentDigest)) {
        throw const DraftMismatchException(
          'the document is not the one the draft was prepared for',
        );
      }
      yield frame.suffix;
    } finally {
      if (!finished) digester.abort();
    }
  }

  /// Everything about [value] that does not involve the document: the
  /// signing certificate and the value in the encoding CMS needs.
  static Future<(X509Certificate, SignatureValue)> _checkValue(
    SignatureDraft draft,
    SignatureValue value,
    CryptoProvider crypto,
  ) async {
    final alg = draft.signatureAlgorithm;
    final cert = X509Certificate.parse(draft.signingCertificate);
    var signature = value;
    switch (alg.scheme) {
      case SignatureScheme.rsaPkcs1v15:
        if (value.encoding != SignatureValueEncoding.raw) {
          throw const DraftMismatchException(
            'an RSA signature value must be raw, not DER',
          );
        }
      case SignatureScheme.ecdsa:
        // CMS wants a DER Ecdsa-Sig-Value; credentials may return r||s.
        signature = SignatureValue.der(
          _ecdsaToDer(value, cert.publicKey as EcPublicKey),
        );
    }
    bool valid;
    try {
      valid = await crypto.verify(
        algorithm: alg,
        key: cert.publicKey,
        message: draft.dtbs,
        signature: signature.bytes,
      );
    } on UnsupportedAlgorithmException catch (e) {
      throw DraftMismatchException('cannot check the signature value: $e');
    }
    if (!valid) {
      throw const DraftMismatchException(
        'the signature value does not match the draft',
      );
    }
    return (cert, signature);
  }
}

/// Normalizes an ECDSA value (raw `r||s` or DER) to canonical DER.
Uint8List _ecdsaToDer(SignatureValue value, EcPublicKey key) {
  final BigInt r;
  final BigInt s;
  switch (value.encoding) {
    case SignatureValueEncoding.raw:
      final n = _coordinateBytes(key.curve);
      if (value.bytes.length != 2 * n) {
        throw DraftMismatchException(
          'a raw ECDSA value must be ${2 * n} bytes (r||s), '
          'got ${value.bytes.length}',
        );
      }
      r = _bigInt(value.bytes.sublist(0, n));
      s = _bigInt(value.bytes.sublist(n));
    case SignatureValueEncoding.der:
      try {
        final seq = decodeDer(Uint8List.fromList(value.bytes));
        final parts = seq.children;
        if (seq.tag != Asn1Tag.sequence || parts == null || parts.length != 2) {
          throw const FormatException('not a SEQUENCE of two INTEGERs');
        }
        r = parts[0].asInteger;
        s = parts[1].asInteger;
      } on Object catch (e) {
        throw DraftMismatchException('malformed DER ECDSA value: $e');
      }
  }
  return Asn1Element.sequence([
    Asn1Element.integer(r),
    Asn1Element.integer(s),
  ]).encode();
}

int _coordinateBytes(EcCurve curve) => switch (curve) {
  EcCurve.p256 => 32,
  EcCurve.p384 => 48,
  EcCurve.p521 => 66,
};

BigInt _bigInt(List<int> bytes) {
  var v = BigInt.zero;
  for (final b in bytes) {
    v = (v << 8) | BigInt.from(b);
  }
  return v;
}

/// The bytes of a `.p7m` / `.p7s` around the document, which is never held
/// here: `prefix + document + suffix` is the whole DER ContentInfo for an
/// enveloping draft ([documentLength] bytes of document); for a detached
/// draft `prefix + suffix` is. The in-memory and the streaming completion
/// both use this, so they cannot disagree.
({Uint8List prefix, Uint8List suffix}) _frame(
  SignatureDraft draft,
  X509Certificate cert,
  SignatureValue value,
  int documentLength,
) {
  const contextAttrs = Asn1Tag(Asn1Class.contextSpecific, true, 0);
  final digestAlgorithm = Asn1Element.sequence([
    Asn1Element.oid(draft.signatureAlgorithm.digest.oid),
  ]);
  // The signed attributes are the DTBS with the SET tag replaced by [0].
  final attrs = decodeDer(draft.dtbs);
  final signerInfo = Asn1Element.sequence([
    Asn1Element.integer(BigInt.one),
    Asn1Element.sequence([
      decodeDer(cert.issuerDer),
      Asn1Element.integer(cert.serialNumber),
    ]),
    digestAlgorithm,
    Asn1Element.constructed(contextAttrs, attrs.children!),
    Asn1Element.sequence([
      Asn1Element.oid(draft.signatureAlgorithm.cmsOid),
      if (draft.signatureAlgorithm.scheme == SignatureScheme.rsaPkcs1v15)
        Asn1Element.nullValue(),
    ]),
    Asn1Element.octetString(Uint8List.fromList(value.bytes)),
  ]);
  final certs = [
    for (final der in [draft.signingCertificate, ...draft.chain])
      decodeDer(der),
  ]..sort((a, b) => compareSetOfEncodings(a.encoded, b.encoded));
  final enveloping = draft.kind == SignatureDraftKind.cadesEnveloping;
  const context0 = Asn1Tag(Asn1Class.contextSpecific, true, 0);
  final version = Asn1Element.integer(BigInt.one).encoded;
  final algorithms = Asn1Element.setOf([digestAlgorithm]).encoded;
  final dataOid = Asn1Element.oid(CmsOids.data).encoded;
  final signedDataOid = Asn1Element.oid(CmsOids.signedData).encoded;
  final suffix = Uint8List.fromList([
    ...Asn1Element.constructed(context0, certs).encoded,
    ...Asn1Element.setOf([signerInfo]).encoded,
  ]);

  // Lengths from the inside out; the document is the only unknown content.
  final octetHeader = enveloping
      ? derHeader(Asn1Tag.octetString, documentLength)
      : Uint8List(0);
  final explicitLength = enveloping ? octetHeader.length + documentLength : 0;
  final explicitHeader = enveloping
      ? derHeader(context0, explicitLength)
      : Uint8List(0);
  final eciLength = dataOid.length + explicitHeader.length + explicitLength;
  final eciHeader = derHeader(Asn1Tag.sequence, eciLength);
  final sdLength =
      version.length +
      algorithms.length +
      eciHeader.length +
      eciLength +
      suffix.length;
  final sdHeader = derHeader(Asn1Tag.sequence, sdLength);
  final wrapLength = sdHeader.length + sdLength;
  final wrapHeader = derHeader(context0, wrapLength);
  final ciLength = signedDataOid.length + wrapHeader.length + wrapLength;
  final ciHeader = derHeader(Asn1Tag.sequence, ciLength);

  final prefix = BytesBuilder(copy: false)
    ..add(ciHeader)
    ..add(signedDataOid)
    ..add(wrapHeader)
    ..add(sdHeader)
    ..add(version)
    ..add(algorithms)
    ..add(eciHeader)
    ..add(dataOid)
    ..add(explicitHeader)
    ..add(octetHeader);
  return (prefix: prefix.takeBytes(), suffix: suffix);
}

/// New signatures use SHA-256 only (spec, out of scope: other digests).
/// SHA-1 is refused as weak; SHA-384 and SHA-512 as not offered.
void _checkPolicy(SignatureAlgorithm algorithm) {
  switch (algorithm.digest) {
    case DigestAlgorithm.sha256:
      return;
    case DigestAlgorithm.sha1:
      throw const WeakDigestException(
        'SHA-1 is not allowed for new signatures',
      );
    case DigestAlgorithm.sha384:
    case DigestAlgorithm.sha512:
      throw UnsupportedCredentialAlgorithmException(
        '${algorithm.digest.displayName} is not offered for new signatures '
        '(SHA-256 only)',
      );
  }
}

X509Certificate _parseCertificate(Uint8List der) {
  try {
    return X509Certificate.parse(der);
  } on Object catch (e) {
    throw InvalidCertificateException('not a valid certificate: $e');
  }
}

void _checkKey(X509Certificate cert) {
  final key = cert.publicKey;
  switch (key) {
    case RsaPublicKey():
      if (key.modulusBitLength < 2048) {
        throw WeakKeyException(
          'RSA key of ${key.modulusBitLength} bits is below 2048',
        );
      }
    case EcPublicKey():
      if (key.curve != EcCurve.p256) {
        throw UnsupportedCredentialAlgorithmException(
          'ECDSA signing supports P-256 only, not ${key.curve.displayName}',
        );
      }
    case UnsupportedPublicKey():
      throw UnsupportedCredentialAlgorithmException(
        'unsupported key algorithm ${key.algorithmOid}',
      );
  }
  // A key that may not make signatures is refused before any signing.
  final usage = cert.keyUsage;
  if (usage != null &&
      !usage.contains(KeyUsageFlag.digitalSignature) &&
      !usage.contains(KeyUsageFlag.nonRepudiation)) {
    throw const InvalidCertificateException(
      'the certificate allows neither digitalSignature nor nonRepudiation',
    );
  }
}

/// The algorithm's scheme must match the certificate's key type.
void _checkFits(SignatureAlgorithm algorithm, X509Certificate cert) {
  final fits = switch (cert.publicKey) {
    RsaPublicKey() => algorithm.scheme == SignatureScheme.rsaPkcs1v15,
    EcPublicKey() => algorithm.scheme == SignatureScheme.ecdsa,
    UnsupportedPublicKey() => false,
  };
  if (!fits) {
    throw UnsupportedCredentialAlgorithmException(
      '$algorithm does not fit the certificate key',
    );
  }
}

DateTime _wholeSecondsUtc(DateTime t) {
  final u = t.toUtc();
  return DateTime.utc(u.year, u.month, u.day, u.hour, u.minute, u.second);
}

Uint8List _frozen(Uint8List b) => Uint8List.fromList(b).asUnmodifiableView();

bool _equal(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  var d = 0;
  for (var i = 0; i < a.length; i++) {
    d |= a[i] ^ b[i];
  }
  return d == 0;
}
