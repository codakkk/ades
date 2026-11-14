import 'package:ades_pkcs11/ades_pkcs11.dart';
import 'package:test/test.dart';

void main() {
  group('knownCnsMiddleware', () {
    test('has entries for every desktop OS', () {
      for (final os in CnsOs.values) {
        final list = knownCnsMiddleware(os);
        expect(list, isNotEmpty, reason: '$os');
        expect(
          list.every((c) => c.name.isNotEmpty && c.path.isNotEmpty),
          isTrue,
        );
      }
    });

    test('returns a fresh modifiable list', () {
      final a = knownCnsMiddleware(CnsOs.linux)..clear();
      expect(knownCnsMiddleware(CnsOs.linux), isNotEmpty);
      expect(a, isEmpty);
    });
  });

  group('discoverPkcs11Modules', () {
    const present = MiddlewareCandidate(name: 'A', path: '/fake/a.so');
    const broken = MiddlewareCandidate(name: 'B', path: '/fake/b.so');
    const absent = MiddlewareCandidate(name: 'C', path: '/fake/c.so');

    test('classifies found, failed (with reason) and absent', () async {
      final r = await discoverPkcs11Modules(
        os: CnsOs.linux,
        candidates: [present, broken, absent],
        includeKnown: false,
        fileExists: (p) => p != '/fake/c.so',
        probe: (p) async {
          if (p == '/fake/b.so') {
            throw const Pkcs11ModuleLoadException('cannot open b.so');
          }
        },
      );
      expect(r.found.map((f) => f.candidate), [present]);
      expect(r.failed.single.candidate, broken);
      expect(r.failed.single.reason, contains('cannot open b.so'));
      expect(r.absent, [absent]);
      expect(r.foundPaths, ['/fake/a.so']);
    });

    test('includeKnown (default) appends the built-in list', () async {
      final r = await discoverPkcs11Modules(
        os: CnsOs.linux,
        candidates: [present],
        fileExists: (_) => false,
        probe: (_) async {},
      );
      expect(r.absent.length, 1 + knownCnsMiddleware(CnsOs.linux).length);
      expect(r.absent.first, present);
    });

    test('duplicate paths are probed once', () async {
      var calls = 0;
      final r = await discoverPkcs11Modules(
        os: CnsOs.linux,
        candidates: [present, present],
        includeKnown: false,
        fileExists: (_) => true,
        probe: (_) async => calls++,
      );
      expect(calls, 1);
      expect(r.found, hasLength(1));
    });

    test('any probe error is reported as a failure', () async {
      final r = await discoverPkcs11Modules(
        os: CnsOs.linux,
        candidates: [present],
        includeKnown: false,
        fileExists: (_) => true,
        probe: (_) async => throw StateError('boom'),
      );
      expect(r.failed.single.reason, contains('boom'));
    });
  });
}
