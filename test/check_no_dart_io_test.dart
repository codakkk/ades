import 'dart:io';

import 'package:test/test.dart';

import '../tool/check_no_dart_io.dart';

void main() {
  late Directory tmp;
  setUp(() => tmp = Directory.systemTemp.createTempSync('nodartio'));
  tearDown(() => tmp.deleteSync(recursive: true));

  void write(String rel, String content) {
    final f = File('${tmp.path}/$rel')..createSync(recursive: true);
    f.writeAsStringSync(content);
  }

  test('clean library passes', () {
    write('lib/a.dart', "import 'dart:typed_data';\n");
    expect(findDartIoViolations(tmp.path), isEmpty);
  });

  test('import, export and double-quoted forms are flagged', () {
    write('lib/a.dart', "import 'dart:io';\n");
    write('lib/src/b.dart', 'export "dart:io" show File;\n');
    write('lib/src/c.dart', "import 'dart:io' as io;\n");
    expect(findDartIoViolations(tmp.path), hasLength(3));
  });

  test('conditional import branch to dart:io is flagged outside helper', () {
    write(
      'lib/a.dart',
      "import 'stub.dart'\n    if (dart.library.io) 'dart:io';\n",
    );
    expect(findDartIoViolations(tmp.path), hasLength(1));
  });

  test('dart:io helper directory is allowed', () {
    write('lib/src/io/reader.dart', "import 'dart:io';\n");
    expect(findDartIoViolations(tmp.path), isEmpty);
  });

  test('mentions in comments are not violations', () {
    write('lib/a.dart', "// import 'dart:io';\n");
    expect(findDartIoViolations(tmp.path), isEmpty);
  });

  test('the real core package is clean', () {
    expect(findDartIoViolations('packages/ades'), isEmpty);
  });
}
