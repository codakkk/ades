import 'dart:io';

import 'exceptions.dart';
import 'module.dart';

/// Desktop operating systems with a known CNS middleware layout.
enum CnsOs {
  windows,
  macos,
  linux;

  /// The OS this process runs on; throws [UnsupportedError] on mobile/other.
  static CnsOs get current {
    if (Platform.isWindows) return windows;
    if (Platform.isMacOS) return macos;
    if (Platform.isLinux) return linux;
    throw UnsupportedError(
      'CNS signing via PKCS#11 is supported on Windows, macOS and Linux only',
    );
  }
}

/// A PKCS#11 library that may be installed on a machine.
final class MiddlewareCandidate {
  const MiddlewareCandidate({required this.name, required this.path});

  /// Human-readable vendor/product name.
  final String name;

  /// Absolute path of the library.
  final String path;

  @override
  String toString() => '$name ($path)';
}

const _linuxDirs = [
  '/usr/lib',
  '/usr/lib64',
  '/usr/local/lib',
  '/usr/lib/x86_64-linux-gnu',
  '/usr/lib/aarch64-linux-gnu',
  '/usr/lib/x86_64-linux-gnu/pkcs11',
];

const _winDir = r'C:\Windows\System32';

/// Known middleware locations for Italian CNS (and generic) smart cards, in
/// the order they are tried. The list is a best-effort catalogue (see
/// `docs`/notes): vendors change install paths between versions, so callers
/// can pass their own candidates to [discoverPkcs11Modules].
List<MiddlewareCandidate> knownCnsMiddleware(CnsOs os) {
  // (product, windows dll, unix base name)
  const products = <(String, String, String)>[
    ('Bit4id', 'bit4ipki.dll', 'libbit4ipki'),
    ('Bit4id (universal)', 'bit4xpki.dll', 'libbit4xpki'),
    ('Incard / InfoCert Incryptoki2', 'incryptoki2.dll', 'libincryptoki2'),
    ('IDEMIA / Oberthur OCS', 'OcsCryptoki.dll', 'libOcsCryptoki'),
    ('IDEMIA IDPrime', 'IDPrimePKCS11.dll', 'libidprimepkcs11'),
    ('Athena ASEPKCS', 'asepkcs.dll', 'libasepkcs'),
    ('Athena ASEP11', 'ASEP11.dll', 'libASEP11'),
    ('Thales / Gemalto', 'gclib.dll', 'libgclib'),
    ('OpenSC', 'opensc-pkcs11.dll', 'opensc-pkcs11'),
  ];
  switch (os) {
    case CnsOs.windows:
      return [
        for (final p in products)
          MiddlewareCandidate(name: p.$1, path: '$_winDir\\${p.$2}'),
        const MiddlewareCandidate(
          name: 'OpenSC',
          path:
              r'C:\Program Files\OpenSC Project\OpenSC\pkcs11\opensc-pkcs11.dll',
        ),
      ];
    case CnsOs.macos:
      return [
        const MiddlewareCandidate(
          name: 'Bit4id',
          path: '/Library/bit4id/pkcs11/libbit4ipki.dylib',
        ),
        const MiddlewareCandidate(
          name: 'Bit4id',
          path: '/usr/local/lib/libbit4ipki.dylib',
        ),
        for (final p in products.where((p) => !p.$3.startsWith('libbit4')))
          if (p.$3 != 'opensc-pkcs11')
            MiddlewareCandidate(
              name: p.$1,
              path: '/usr/local/lib/${p.$3}.dylib',
            ),
        const MiddlewareCandidate(
          name: 'OpenSC',
          path: '/Library/OpenSC/lib/opensc-pkcs11.so',
        ),
        const MiddlewareCandidate(
          name: 'OpenSC (Homebrew)',
          path: '/opt/homebrew/lib/opensc-pkcs11.so',
        ),
      ];
    case CnsOs.linux:
      return [
        for (final p in products)
          for (final d in _linuxDirs)
            MiddlewareCandidate(
              name: p.$1,
              path: p.$3 == 'opensc-pkcs11'
                  ? '$d/opensc-pkcs11.so'
                  : '$d/${p.$3}.so',
            ),
      ];
  }
}

/// A candidate whose library exists and was loaded successfully.
final class DiscoveredModule {
  const DiscoveredModule(this.candidate);
  final MiddlewareCandidate candidate;
  String get path => candidate.path;
}

/// A candidate whose library exists but could not be loaded.
final class DiscoveryFailure {
  const DiscoveryFailure(this.candidate, this.reason);
  final MiddlewareCandidate candidate;
  final String reason;

  @override
  String toString() => '${candidate.path}: $reason';
}

/// Outcome of [discoverPkcs11Modules].
final class DiscoveryReport {
  const DiscoveryReport({
    required this.found,
    required this.failed,
    required this.absent,
  });

  /// Present and loadable, in candidate order. Pass these to
  /// `Pkcs11Module.load`.
  final List<DiscoveredModule> found;

  /// Present but failed to load, each with a reason (wrong architecture,
  /// missing dependency, `C_Initialize` failure, ...).
  final List<DiscoveryFailure> failed;

  /// Candidates with no file at that path (the normal case for most).
  final List<MiddlewareCandidate> absent;

  List<String> get foundPaths => [for (final f in found) f.path];
}

Future<void> _defaultProbe(String path) async {
  final m = await Pkcs11Module.load(path, onPin: (_) async => null);
  await m.close();
}

/// Looks for installed PKCS#11 middleware.
///
/// [candidates] (caller-supplied) are tried first, then, unless
/// [includeKnown] is false, [knownCnsMiddleware] for [os] (default: the
/// current OS). Each distinct path is checked for existence; existing files
/// are loaded (and closed again) to prove they work. Nothing is ever thrown
/// for a bad candidate: it lands in [DiscoveryReport.failed] with a reason.
///
/// [fileExists] and [probe] are test seams.
Future<DiscoveryReport> discoverPkcs11Modules({
  CnsOs? os,
  List<MiddlewareCandidate> candidates = const [],
  bool includeKnown = true,
  bool Function(String path)? fileExists,
  Future<void> Function(String path)? probe,
}) async {
  final exists = fileExists ?? (p) => File(p).existsSync();
  final load = probe ?? _defaultProbe;
  final all = [
    ...candidates,
    if (includeKnown) ...knownCnsMiddleware(os ?? CnsOs.current),
  ];
  final seen = <String>{};
  final found = <DiscoveredModule>[];
  final failed = <DiscoveryFailure>[];
  final absent = <MiddlewareCandidate>[];
  for (final c in all) {
    if (!seen.add(c.path)) continue;
    if (!exists(c.path)) {
      absent.add(c);
      continue;
    }
    try {
      await load(c.path);
      found.add(DiscoveredModule(c));
    } on Pkcs11Exception catch (e) {
      failed.add(DiscoveryFailure(c, e.message));
    } on Object catch (e) {
      failed.add(DiscoveryFailure(c, '$e'));
    }
  }
  return DiscoveryReport(found: found, failed: failed, absent: absent);
}
