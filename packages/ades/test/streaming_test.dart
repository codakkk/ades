// Ticket 11: streaming validation and signing, BER outer structures.
// Seam 1 (public API); runs on VM, dart2js and dart2wasm (no dart:io).
import 'dart:typed_data';

import 'package:ades/ades.dart';
import 'package:test/test.dart';

import 'support/test_credential.dart';
import 'support/tier1.dart';

const _der = 'signatures/positive/rsa2048-qsign.p7m';
const _indef = 'signatures/ber/rsa2048-qsign-indef.p7m';
const _indefChunked = 'signatures/ber/rsa2048-qsign-indef-chunked.p7m';

Validator _validator() => Validator(
  trustAnchors: [TrustAnchor.fromDer(tier1('pki/rsa2048/leaf-qsign.der'))],
);

/// [bytes] as a stream of [size]-byte chunks.
Stream<List<int>> _chunks(Uint8List bytes, int size) async* {
  for (var i = 0; i < bytes.length; i += size) {
    yield Uint8List.sublistView(
      bytes,
      i,
      i + size > bytes.length ? bytes.length : i + size,
    );
  }
}

/// Everything a report says, as comparable text.
String _summary(ValidationReport r) {
  final b = StringBuffer();
  for (final s in r.simple.signatures) {
    b.writeln(
      '${s.index} ${s.indication.etsi} ${s.subIndication?.name} '
      '${s.signedBy} ${s.signingTime}',
    );
    for (final sc in s.scope) {
      b.writeln('scope ${sc.length} ${sc.digestAlgorithm} ${sc.digest}');
    }
  }
  for (final s in r.detailed.signatures) {
    for (final bl in s.blocks) {
      b.writeln(
        '${bl.block.abbreviation} ${bl.indication.name} '
        '${bl.subIndication?.name} ${bl.messages.map((m) => m.code.name)}',
      );
    }
  }
  b.writeln(r.warnings.map((w) => w.code.name).toList());
  return b.toString();
}

Uint8List _patch(Uint8List b, int at, int value) =>
    Uint8List.fromList(b)..[at] = value;

int _indexOf(Uint8List haystack, List<int> needle) {
  for (var i = 0; i <= haystack.length - needle.length; i++) {
    var ok = true;
    for (var j = 0; j < needle.length && ok; j++) {
      ok = haystack[i + j] == needle[j];
    }
    if (ok) return i;
  }
  return -1;
}

void main() {
  group('detached signature, streamed (US29, US47)', () {
    const sig = 'signatures/positive/rsa2048-qsign.p7s';
    final doc = tier1('content/hello.txt');
    const noRevocation = ValidationPolicy(
      revocationDataAvailable: ConstraintLevel.ignore,
    );

    test('a streamed signature and a streamed document validate', () async {
      final report = await _validator().validateStream(
        _chunks(tier1(sig), 100),
        detachedContent: _chunks(doc, 3),
        policy: noRevocation,
      );
      final s = report.simple.signatures.single;
      expect(s.indication, Indication.totalPassed);
      expect(s.scope.single.kind, SignatureScopeKind.detachedDocument);
      expect(s.scope.single.length, doc.length);
    });

    test('same report as the in-memory validation', () async {
      final streamed = await _validator().validateStream(
        _chunks(tier1(sig), 100),
        detachedContent: _chunks(doc, 5),
      );
      final inMemory = await _validator().validate(
        tier1(sig),
        detachedContent: doc,
      );
      expect(_summary(streamed), _summary(inMemory));
    });

    test('a changed document is a hash failure', () async {
      final report = await _validator().validateStream(
        _chunks(tier1(sig), 100),
        detachedContent: _chunks(tier1('content/hello-tampered.txt'), 4),
      );
      final s = report.simple.signatures.single;
      expect(s.indication, Indication.totalFailed);
      expect(s.subIndication, SubIndication.hashFailure);
    });

    test('without the document: SIGNED_DATA_NOT_FOUND', () async {
      final report = await _validator().validateStream(
        _chunks(tier1(sig), 100),
      );
      expect(
        report.simple.signatures.single.subIndication,
        SubIndication.signedDataNotFound,
      );
    });

    test('a document given for an enveloping signature is ignored', () async {
      final report = await _validator().validateStream(
        _chunks(tier1(_der), 100),
        detachedContent: _chunks(Uint8List.fromList([1, 2, 3]), 1),
        policy: noRevocation,
      );
      expect(
        report.simple.signatures.single.indication,
        Indication.totalPassed,
      );
    });
  });

  group('indefinite-length BER from OpenSSL -stream', () {
    for (final name in [_indef, _indefChunked]) {
      test('$name validates like DER, with warnings', () async {
        final report = await _validator().validate(tier1(name));
        final d = report.detailed.signatures.single;
        for (final b in [
          BuildingBlock.formatChecking,
          BuildingBlock.identificationOfSigningCertificate,
          BuildingBlock.cryptographicVerification,
          BuildingBlock.signatureAcceptanceValidation,
        ]) {
          expect(d.result(b)!.indication, BlockIndication.passed, reason: '$b');
        }
        // Same verdict as the DER fixture (revocation is not checked yet).
        final der = await _validator().validate(tier1(_der));
        expect(
          report.simple.signatures.single.indication,
          der.simple.signatures.single.indication,
        );
        expect(
          report.simple.signatures.single.subIndication,
          der.simple.signatures.single.subIndication,
        );
        final codes = report.warnings.map((w) => w.code).toSet();
        expect(codes, contains(WarningCode.indefiniteLength));
        expect(codes, contains(WarningCode.constructedString));
      });
    }

    test('the DER fixture has no warnings', () async {
      final report = await _validator().validate(tier1(_der));
      expect(report.warnings, isEmpty);
    });

    test('the scope covers the whole segmented content', () async {
      final report = await _validator().validate(tier1(_indefChunked));
      final scope = report.simple.signatures.single.scope.single;
      expect(scope.length, 20000);
      expect(scope.digest, hasLength(32));
    });

    test('a changed content byte is a hash failure', () async {
      final bytes = tier1(_indefChunked);
      final at = _indexOf(bytes, 'BER chunking'.codeUnits);
      expect(at, greaterThan(0));
      final report = await _validator().validate(_patch(bytes, at, 0x58));
      final s = report.simple.signatures.single;
      expect(s.indication, Indication.totalFailed);
      expect(s.subIndication, SubIndication.hashFailure);
    });

    test('non-DER signed attributes still fail', () async {
      final bytes = tier1(
        'signatures/negative/rsa2048-non-der-signed-attrs.p7m',
      );
      final r1 = await _validator().validate(bytes);
      final r2 = await _validator().validateStream(_chunks(bytes, 100));
      for (final r in [r1, r2]) {
        expect(r.simple.signatures.single.indication, Indication.totalFailed);
      }
    });

    test(
      'limits: nesting beyond the depth limit is a format failure',
      () async {
        final bomb = Uint8List.fromList([
          for (var i = 0; i < 200; i++) ...[0x30, 0x80],
        ]);
        final r1 = await _validator().validate(bomb);
        final r2 = await _validator().validateStream(_chunks(bomb, 7));
        for (final r in [r1, r2]) {
          expect(
            r.simple.signatures.single.subIndication,
            SubIndication.formatFailure,
          );
        }
      },
    );
  });

  group('validateStream', () {
    for (final name in [_der, _indef, _indefChunked]) {
      for (final size in [1, 7, 1000, 1 << 20]) {
        test(
          '$name in $size-byte chunks equals the in-memory report',
          () async {
            final bytes = tier1(name);
            final mem = await _validator().validate(bytes);
            final streamed = await _validator().validateStream(
              _chunks(bytes, size),
            );
            expect(_summary(streamed), _summary(mem));
          },
        );
      }
    }

    test('truncated and trailing input never throw', () async {
      final bytes = tier1(_indef);
      final cut = await _validator().validateStream(
        _chunks(Uint8List.sublistView(bytes, 0, bytes.length - 5), 64),
      );
      expect(
        cut.simple.signatures.single.subIndication,
        SubIndication.formatFailure,
      );
      final extra = await _validator().validateStream(
        _chunks(Uint8List.fromList([...bytes, 0]), 64),
      );
      expect(
        extra.simple.signatures.single.subIndication,
        SubIndication.formatFailure,
      );
    });

    test('an error in the input stream is a format failure', () async {
      Stream<List<int>> failing() async* {
        yield tier1(_der).sublist(0, 20);
        throw StateError('disk gone');
      }

      final r = await _validator().validateStream(failing());
      expect(
        r.simple.signatures.single.subIndication,
        SubIndication.formatFailure,
      );
    });
  });

  group('signing as a stream', () {
    Future<(Uint8List, Uint8List)> sign(Uint8List doc, int chunk) async {
      final cred = TestRsaCredential();
      final time = DateTime.utc(2026, 11, 9, 12);
      final draft = await Cades.prepareEnveloping(
        document: doc,
        credential: cred,
        signingTime: time,
      );
      final value = await cred.sign(await draft.signRequest());
      final inMemory = await Cades.complete(
        draft: draft,
        value: value,
        document: doc,
      );
      final sDraft = await Cades.prepareEnvelopingStream(
        document: _chunks(doc, chunk),
        credential: cred,
        signingTime: time,
      );
      expect(sDraft.toJson(), draft.toJson());
      final out = BytesBuilder();
      await for (final c in Cades.completeEnvelopingStream(
        draft: sDraft,
        value: value,
        document: _chunks(doc, chunk),
        documentLength: doc.length,
      )) {
        out.add(c);
      }
      return (inMemory, out.takeBytes());
    }

    for (final length in [0, 1, 127, 128, 70000]) {
      test('$length-byte document: same bytes as the in-memory path', () async {
        final doc = Uint8List.fromList([
          for (var i = 0; i < length; i++) i * 31 % 251,
        ]);
        final (mem, streamed) = await sign(doc, 4096);
        expect(streamed, mem);
      });
    }

    test('streamed output validates through the stream path', () async {
      final doc = Uint8List.fromList([
        for (var i = 0; i < 100000; i++) i % 256,
      ]);
      final (_, streamed) = await sign(doc, 1000);
      final r = await _validator().validateStream(_chunks(streamed, 333));
      final s = r.detailed.signatures.single;
      expect(
        s.result(BuildingBlock.cryptographicVerification)!.indication,
        BlockIndication.passed,
      );
      expect(r.simple.signatures.single.scope.single.length, 100000);
    });

    test('a different document or length fails the stream', () async {
      final cred = TestRsaCredential();
      final doc = Uint8List.fromList(List.filled(5000, 7));
      final draft = await Cades.prepareEnvelopingStream(
        document: _chunks(doc, 100),
        credential: cred,
      );
      final value = await cred.sign(await draft.signRequest());
      Future<void> run(Uint8List other, int length) =>
          Cades.completeEnvelopingStream(
            draft: draft,
            value: value,
            document: _chunks(other, 100),
            documentLength: length,
          ).drain<void>();
      await expectLater(
        run(Uint8List.fromList(List.filled(5000, 8)), 5000),
        throwsA(isA<DraftMismatchException>()),
      );
      await expectLater(run(doc, 4999), throwsA(isA<DraftMismatchException>()));
      await expectLater(run(doc, 5001), throwsA(isA<DraftMismatchException>()));
    });

    test('credential checks run before the document stream is read', () async {
      var listened = false;
      final doc = Stream<List<int>>.multi((c) {
        listened = true;
        c.close();
      });
      await expectLater(
        Cades.prepareEnvelopingStream(
          document: doc,
          credential: TestRsaCredential(),
          algorithm: const SignatureAlgorithm(
            SignatureScheme.rsaPkcs1v15,
            DigestAlgorithm.sha1,
          ),
        ),
        throwsA(isA<WeakDigestException>()),
      );
      expect(listened, isFalse);
    });
  });
}
