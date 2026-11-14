// Seam 4 (spec): the DER codec, imported from the private source tree.
import 'dart:math';
import 'dart:typed_data';

import 'package:ades/src/asn1/asn1.dart';
import 'package:test/test.dart';

Uint8List b(List<int> v) => Uint8List.fromList(v);

void expectKind(List<int> bytes, Asn1ErrorKind kind, {Asn1Limits? limits}) {
  try {
    decodeDer(b(bytes), limits: limits ?? Asn1Limits.defaults);
  } on Asn1Exception catch (e) {
    expect(e.kind, kind, reason: e.toString());
    return;
  }
  fail('expected $kind but decode succeeded');
}

void main() {
  group('decoding valid DER', () {
    test('SEQUENCE { INTEGER 5, BOOLEAN true }', () {
      final e = decodeDer(b([0x30, 6, 2, 1, 5, 1, 1, 0xff]));
      expect(e.tag, Asn1Tag.sequence);
      expect(e.children, hasLength(2));
      expect(e.children![0].asInteger, BigInt.from(5));
      expect(e.children![1].asBoolean, isTrue);
    });

    test('long-form length', () {
      final content = List<int>.filled(200, 0x41);
      final e = decodeDer(b([0x04, 0x81, 200, ...content]));
      expect(e.contentBytes, hasLength(200));
      expect(e.headerLength, 3);
    });

    test('OID decodes to dotted form, including a big arc', () {
      expect(
        decodeDer(
          b([6, 9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 1, 0x0b]),
        ).asOid,
        '1.2.840.113549.1.1.11',
      );
      const big = '2.25.329800735698586629295641978511506172918';
      expect(decodeDer(Asn1Element.oid(big).encode()).asOid, big);
    });

    test('high tag number, context class', () {
      final e = decodeDer(b([0xbf, 0x1f, 0]));
      expect(e.tag.number, 31);
      expect(e.tag.tagClass, Asn1Class.contextSpecific);
      expect(e.tag.constructed, isTrue);
    });

    test('every element exposes its original encoded bytes', () {
      final input = b([0x30, 8, 0x31, 6, 2, 1, 1, 2, 1, 2]);
      final root = decodeDer(input);
      final set = root.children![0];
      expect(set.encoded, [0x31, 6, 2, 1, 1, 2, 1, 2]);
      expect(set.children![1].encoded, [2, 1, 2]);
      expect(set.children![1].offset, 7);
      expect(root.encoded, input);
    });

    test('SET OF with equal and sorted elements is accepted', () {
      decodeDer(b([0x31, 6, 2, 1, 1, 2, 1, 1]));
      decodeDer(b([0x31, 6, 2, 1, 1, 2, 1, 2]));
    });

    test('BIT STRING keeps unused-bits count', () {
      final e = decodeDer(b([3, 3, 4, 0xab, 0xa0]));
      expect(e.asBitString.unusedBits, 4);
      expect(e.asBitString.bytes, [0xab, 0xa0]);
    });
  });

  group('DER violations are rejected with typed errors', () {
    test('truncated', () {
      expectKind([0x30, 5, 2, 1], Asn1ErrorKind.truncated);
      expectKind([], Asn1ErrorKind.truncated);
      expectKind([0x30], Asn1ErrorKind.truncated);
      expectKind([0x04, 0x82, 0x01], Asn1ErrorKind.truncated);
    });
    test('trailing data', () {
      expectKind([5, 0, 0], Asn1ErrorKind.trailingData);
    });
    test('non-minimal length', () {
      expectKind([4, 0x81, 1, 0x41], Asn1ErrorKind.nonMinimalLength);
      expectKind([
        4,
        0x82,
        0,
        200,
        ...List.filled(200, 0),
      ], Asn1ErrorKind.nonMinimalLength);
    });
    test('indefinite and reserved length', () {
      expectKind([0x30, 0x80, 0, 0], Asn1ErrorKind.indefiniteLength);
      expectKind([4, 0xff], Asn1ErrorKind.invalidLength);
    });
    test('length overflowing int', () {
      expectKind([4, 0x89, 1, 0, 0, 0, 0, 0, 0, 0, 0], Asn1ErrorKind.truncated);
    });
    test('non-minimal tag number / EOC', () {
      expectKind([0x9f, 0x80, 0x01, 0], Asn1ErrorKind.nonMinimalTag);
      expectKind([0x9f, 0x1e, 0], Asn1ErrorKind.nonMinimalTag);
      expectKind([0, 0], Asn1ErrorKind.endOfContents);
    });
    test('BOOLEAN encoding', () {
      expectKind([1, 1, 1], Asn1ErrorKind.invalidBoolean);
      expectKind([1, 2, 0xff, 0xff], Asn1ErrorKind.invalidBoolean);
    });
    test('INTEGER minimality', () {
      expectKind([2, 0], Asn1ErrorKind.invalidInteger);
      expectKind([2, 2, 0, 1], Asn1ErrorKind.nonMinimalInteger);
      expectKind([2, 2, 0xff, 0x80], Asn1ErrorKind.nonMinimalInteger);
      decodeDer(b([2, 2, 0, 0x80])); // 128, minimal
      decodeDer(b([2, 1, 0x80])); // -128, minimal
    });
    test('NULL must be empty', () {
      expectKind([5, 1, 0], Asn1ErrorKind.invalidNull);
    });
    test('BIT STRING', () {
      expectKind([3, 0], Asn1ErrorKind.invalidBitString);
      expectKind([3, 2, 8, 0], Asn1ErrorKind.invalidBitString);
      expectKind([3, 2, 4, 0xab], Asn1ErrorKind.invalidBitString);
    });
    test('OID', () {
      expectKind([6, 0], Asn1ErrorKind.invalidOid);
      expectKind([6, 2, 0x2a, 0x86], Asn1ErrorKind.invalidOid);
      expectKind([6, 3, 0x2a, 0x80, 0x01], Asn1ErrorKind.invalidOid);
    });
    test('constructed encoding of string types', () {
      expectKind([0x24, 3, 4, 1, 0x41], Asn1ErrorKind.constructedNotAllowed);
      expectKind([0x23, 0], Asn1ErrorKind.constructedNotAllowed);
    });
    test('primitive SEQUENCE/SET', () {
      expectKind([0x10, 0], Asn1ErrorKind.primitiveNotAllowed);
    });
    test('unsorted SET OF', () {
      expectKind([0x31, 6, 2, 1, 2, 2, 1, 1], Asn1ErrorKind.unsortedSet);
    });
  });

  group('limits', () {
    Uint8List nested(int depth) {
      var cur = b([5, 0]);
      for (var i = 0; i < depth; i++) {
        final len = cur.length;
        final hdr = len < 128
            ? [0x30, len]
            : len < 256
            ? [0x30, 0x81, len]
            : [0x30, 0x82, len >> 8, len & 0xff];
        cur = b([...hdr, ...cur]);
      }
      return cur;
    }

    test('depth limit is enforced and configurable', () {
      final input = nested(10);
      expectKind(
        input,
        Asn1ErrorKind.depthLimit,
        limits: const Asn1Limits(maxDepth: 5),
      );
      decodeDer(input, limits: const Asn1Limits(maxDepth: 11));
      expectKind(
        input,
        Asn1ErrorKind.depthLimit,
        limits: const Asn1Limits(maxDepth: 10),
      );
    });

    test('total-size limit is enforced and configurable', () {
      final input = b([4, 3, 1, 2, 3]);
      expectKind(
        input,
        Asn1ErrorKind.sizeLimit,
        limits: const Asn1Limits(maxTotalSize: 4),
      );
      decodeDer(input, limits: const Asn1Limits(maxTotalSize: 5));
    });

    test('default limits survive hostile nesting without stack overflow', () {
      final input = Uint8List.fromList(
        List.generate(100000, (i) => i.isEven ? 0x30 : 0x80),
      );
      expect(() => decodeDer(input), throwsA(isA<Asn1Exception>()));
    });
  });

  group('encoding', () {
    test('known vectors', () {
      expect(Asn1Element.integer(BigInt.from(128)).encode(), [2, 2, 0, 0x80]);
      expect(Asn1Element.integer(BigInt.from(-128)).encode(), [2, 1, 0x80]);
      expect(Asn1Element.integer(BigInt.from(-129)).encode(), [
        2,
        2,
        0xff,
        0x7f,
      ]);
      expect(Asn1Element.integer(BigInt.zero).encode(), [2, 1, 0]);
      expect(Asn1Element.boolean(true).encode(), [1, 1, 0xff]);
      expect(Asn1Element.oid('1.2.840.113549').encode(), [
        6,
        6,
        0x2a,
        0x86,
        0x48,
        0x86,
        0xf7,
        0x0d,
      ]);
      expect(Asn1Element.nullValue().encode(), [5, 0]);
    });
    test('SET OF is sorted on encode', () {
      final s = Asn1Element.setOf([
        Asn1Element.integer(BigInt.two),
        Asn1Element.integer(BigInt.one),
      ]);
      expect(s.encode(), [0x31, 6, 2, 1, 1, 2, 1, 2]);
    });
    test('long length', () {
      final e = Asn1Element.octetString(Uint8List(70000));
      final enc = e.encode();
      expect(enc.sublist(0, 5), [4, 0x83, 1, 0x11, 0x70]);
      expect(decodeDer(enc).contentBytes, hasLength(70000));
    });
  });

  group('properties', () {
    Asn1Element gen(Random r, int depth) {
      final k = r.nextInt(depth > 0 ? 9 : 6);
      switch (k) {
        case 0:
          return Asn1Element.integer(
            BigInt.from(r.nextInt(0x7fffffff) - 0x40000000) *
                BigInt.from(r.nextInt(1 << 20) + 1),
          );
        case 1:
          return Asn1Element.boolean(r.nextBool());
        case 2:
          return Asn1Element.octetString(
            Uint8List.fromList(
              List.generate(r.nextInt(300), (_) => r.nextInt(256)),
            ),
          );
        case 3:
          return Asn1Element.nullValue();
        case 4:
          return Asn1Element.oid(
            '${r.nextInt(3)}.${r.nextInt(40)}.${r.nextInt(1 << 30)}.${r.nextInt(300)}',
          );
        case 5:
          return Asn1Element.utf8String(
            String.fromCharCodes(
              List.generate(r.nextInt(20), (_) => 0x61 + r.nextInt(26)),
            ),
          );
        case 6:
          return Asn1Element.sequence(
            List.generate(r.nextInt(5), (_) => gen(r, depth - 1)),
          );
        case 7:
          return Asn1Element.setOf(
            List.generate(r.nextInt(5), (_) => gen(r, depth - 1)),
          );
        default:
          return Asn1Element.constructed(
            Asn1Tag(Asn1Class.contextSpecific, true, r.nextInt(100)),
            List.generate(r.nextInt(4), (_) => gen(r, depth - 1)),
          );
      }
    }

    void sameStructure(Asn1Element a, Asn1Element c) {
      expect(a.tag, c.tag);
      expect(a.encode(), c.encoded);
      expect(a.children?.length, c.children?.length);
      for (var i = 0; i < (a.children?.length ?? 0); i++) {
        sameStructure(a.children![i], c.children![i]);
      }
    }

    test('encode -> decode round-trips; decoded.encoded is the input', () {
      final r = Random(42);
      for (var i = 0; i < 400; i++) {
        final v = gen(r, 4);
        final bytes = v.encode();
        final d = decodeDer(bytes);
        sameStructure(v, d);
        expect(d.encoded, bytes);
        expect(d.encode(), bytes);
      }
    });

    test('mutated inputs only ever raise Asn1Exception', () {
      final r = Random(7);
      for (var i = 0; i < 1500; i++) {
        final bytes = Uint8List.fromList(gen(r, 3).encode());
        for (var m = 0; m < 1 + r.nextInt(3); m++) {
          if (bytes.isEmpty) break;
          bytes[r.nextInt(bytes.length)] = r.nextInt(256);
        }
        try {
          final d = decodeDer(bytes);
          expect(d.encoded, bytes);
        } on Asn1Exception {
          // expected
        }
      }
    });
  });
}
