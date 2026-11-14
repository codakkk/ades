import 'package:ades/ades.dart';
import 'package:test/test.dart';

void main() {
  test('core library loads on this platform', () {
    expect(adesVersion, matches(RegExp(r'^\d+\.\d+\.\d+$')));
  });
}
