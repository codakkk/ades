// Seam 4: the bounded-BER decoder and the incremental reader.
import 'dart:typed_data';

import 'package:ades/src/asn1/asn1.dart';
import 'package:test/test.dart';

Uint8List b(List<int> x) => Uint8List.fromList(x);

Stream<List<int>> chunks(Uint8List bytes, int size) async* {
  for (var i = 0; i < bytes.length; i += size) {
    yield bytes.sublist(i, i + size > bytes.length ? bytes.length : i + size);
  }
}

void main() {
  group('decodeBer', () {
    test('indefinite SEQUENCE keeps its end-of-contents in encoded', () {
      final dev = BerDeviations();
      final e = decodeBer(
        b([0x30, 0x80, 0x02, 0x01, 0x05, 0x00, 0x00]),
        deviations: dev,
      );
      expect(e.children, hasLength(1));
      expect(e.encoded, hasLength(7));
      expect(dev.items.single.kind, Asn1ErrorKind.indefiniteLength);
    });

    test('non-minimal length and unsorted SET are deviations, not errors', () {
      final dev = BerDeviations();
      decodeBer(
        b([0x31, 0x81, 0x06, 0x02, 0x01, 0x09, 0x02, 0x01, 0x01]),
        deviations: dev,
      );
      expect(
        dev.items.map((d) => d.kind),
        containsAll([
          Asn1ErrorKind.nonMinimalLength,
          Asn1ErrorKind.unsortedSet,
        ]),
      );
    });

    test('DER input has no deviations', () {
      final dev = BerDeviations();
      decodeBer(b([0x30, 0x03, 0x02, 0x01, 0x05]), deviations: dev);
      expect(dev.isEmpty, isTrue);
    });

    test('constructed OCTET STRING concatenates its segments', () {
      final e = decodeBer(
        b([0x24, 0x80, 0x04, 0x01, 0x41, 0x04, 0x02, 0x42, 0x43, 0x00, 0x00]),
      );
      expect(octetStringBytes(e), [0x41, 0x42, 0x43]);
    });

    test('depth and truncation are errors', () {
      final bomb = b([
        for (var i = 0; i < 100; i++) ...[0x30, 0x80],
      ]);
      expect(
        () => decodeBer(bomb, limits: const Asn1Limits(maxDepth: 10)),
        throwsA(
          isA<Asn1Exception>().having(
            (e) => e.kind,
            'kind',
            Asn1ErrorKind.depthLimit,
          ),
        ),
      );
      expect(
        () => decodeBer(b([0x30, 0x80, 0x02, 0x01, 0x05])),
        throwsA(
          isA<Asn1Exception>().having(
            (e) => e.kind,
            'kind',
            Asn1ErrorKind.truncated,
          ),
        ),
      );
    });

    test('a stray end-of-contents is an error', () {
      expect(
        () => decodeBer(b([0x30, 0x02, 0x00, 0x00])),
        throwsA(isA<Asn1Exception>()),
      );
    });
  });

  group('incremental reader', () {
    test('reads headers and elements across 1-byte chunks', () async {
      final bytes = b([0x30, 0x80, 0x02, 0x01, 0x05, 0x00, 0x00]);
      final r = ByteStreamReader(chunks(bytes, 1), maxBytes: 100);
      final dev = BerDeviations();
      final h = await readStreamHeader(r, dev);
      expect(h.isIndefinite, isTrue);
      final e = await readStreamElement(r, h, dev, Asn1Limits.defaults);
      expect(e.children!.single.asInteger, BigInt.from(5));
      expect(await r.atEnd(), isTrue);
    });

    test('maxBytes and maxBufferedElement are enforced', () async {
      final bytes = b([0x04, 0x05, 1, 2, 3, 4, 5]);
      final r = ByteStreamReader(chunks(bytes, 3), maxBytes: 4);
      final dev = BerDeviations();
      final h = await readStreamHeader(r, dev);
      await expectLater(
        readStreamElement(r, h, dev, Asn1Limits.defaults),
        throwsA(isA<Asn1Exception>()),
      );
      final r2 = ByteStreamReader(chunks(bytes, 3), maxBytes: 100);
      final h2 = await readStreamHeader(r2, dev);
      await expectLater(
        readStreamElement(r2, h2, dev, const Asn1Limits(maxBufferedElement: 4)),
        throwsA(
          isA<Asn1Exception>().having(
            (e) => e.kind,
            'kind',
            Asn1ErrorKind.sizeLimit,
          ),
        ),
      );
    });
  });

  test('derHeader matches the DER encoder', () {
    for (final n in [0, 1, 127, 128, 255, 256, 65535, 65536, 1 << 24]) {
      final e = Asn1Element.octetString(Uint8List(n));
      expect(
        derHeader(Asn1Tag.octetString, n),
        e.encoded.sublist(0, e.headerLength),
      );
    }
  });
}
