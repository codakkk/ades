// Enforces ADR-0002: no core library imports `dart:io`, except the helper
// under `lib/src/io/`. Usage: `dart run tool/check_no_dart_io.dart [pkgDir]`
// (default: packages/ades). Exits 1 on violations.
import 'dart:io';

final _dartIo = RegExp(r'''['"]dart:io['"]''');

/// Returns `path:line` for every `dart:io` reference in `<pkgDir>/lib`
/// outside `lib/src/io/`. Comment-only lines are ignored.
List<String> findDartIoViolations(String pkgDir) {
  final lib = Directory('$pkgDir/lib');
  if (!lib.existsSync()) return [];
  final out = <String>[];
  for (final e in lib.listSync(recursive: true)) {
    if (e is! File || !e.path.endsWith('.dart')) continue;
    final rel = e.path.replaceAll('\\', '/');
    if (rel.contains('/lib/src/io/')) continue;
    final lines = e.readAsLinesSync();
    for (var i = 0; i < lines.length; i++) {
      final l = lines[i].trimLeft();
      if (l.startsWith('//')) continue;
      if (_dartIo.hasMatch(l)) out.add('${e.path}:${i + 1}');
    }
  }
  return out;
}

void main(List<String> args) {
  final v = findDartIoViolations(args.isEmpty ? 'packages/ades' : args.first);
  if (v.isEmpty) return;
  stderr.writeln('dart:io is forbidden in core libraries (ADR-0002):');
  v.forEach(stderr.writeln);
  exit(1);
}
