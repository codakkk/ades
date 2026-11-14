// VM only: the committed copy of DSS's default policy XML agrees with the
// table that pins ValidationPolicy's defaults (packages/ades tests).
import 'dart:io';

import 'package:test/test.dart';

import '../packages/ades/test/support/dss_default_levels.dart';

/// element path (below ConstraintsParameters) -> lower-case Level.
Map<String, String> _levels(String xml) {
  final text = xml.replaceAll(RegExp(r'<!--.*?-->', dotAll: true), '');
  final out = <String, String>{};
  final stack = <String>[];
  for (final m in RegExp(r'<(/?)(\w+)([^>]*?)(/?)>').allMatches(text)) {
    final closing = m.group(1) == '/';
    final name = m.group(2)!;
    final selfClosing = m.group(4) == '/';
    if (closing) {
      stack.removeLast();
      continue;
    }
    final level = RegExp(r'Level="(\w+)"').firstMatch(m.group(3)!)?.group(1);
    if (level != null) {
      out.putIfAbsent([...stack.skip(1), name].join('/'), () => level);
    }
    if (!selfClosing) stack.add(name);
  }
  return out;
}

void main() {
  test('policy default table matches DSS 6.5.1 constraint.xml', () {
    final levels = _levels(
      File('fixtures/dss/6.5.1/constraint.xml').readAsStringSync(),
    );
    dssDefaultLevels.forEach((field, expected) {
      expect(
        levels[expected.$1]?.toLowerCase(),
        expected.$2,
        reason: '$field = ${expected.$1}',
      );
    });
  });
}
