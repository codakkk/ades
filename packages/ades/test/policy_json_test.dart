// Ticket 06: policy JSON, and the pin of the defaults to DSS's default policy.
import 'dart:convert';

import 'package:ades/ades.dart';
import 'package:test/test.dart';

import 'support/dss_default_levels.dart';

void main() {
  group('defaults pinned to DSS', () {
    test('DSS release is 6.5.1', () {
      expect(ValidationPolicy.dssVersion, '6.5.1');
    });

    test('every constraint has the level of DSS 6.5.1 constraint.xml', () {
      final json = const ValidationPolicy().toJson();
      expect(json.keys.toSet(), dssDefaultLevels.keys.toSet());
      dssDefaultLevels.forEach((name, expected) {
        expect(json[name], expected.$2, reason: '$name = ${expected.$1}');
      });
    });
  });

  group('JSON', () {
    test('round-trips', () {
      const p = ValidationPolicy(
        signatureIntact: ConstraintLevel.warn,
        revocationDataAvailable: ConstraintLevel.ignore,
        signingTime: ConstraintLevel.inform,
      );
      final back = ValidationPolicy.fromJsonString(p.toJsonString());
      expect(jsonEncode(back.toJson()), jsonEncode(p.toJson()));
      expect(back.signatureIntact, ConstraintLevel.warn);
      expect(back.revocationDataAvailable, ConstraintLevel.ignore);
    });

    test('missing keys keep the DSS default', () {
      final p = ValidationPolicy.fromJsonString('{"signatureIntact":"warn"}');
      expect(p.signatureIntact, ConstraintLevel.warn);
      expect(p.certDigestMatch, ConstraintLevel.fail);
      expect(p.issuerSerialMatch, ConstraintLevel.warn);
    });

    PolicyFormatException rejected(String text) {
      try {
        ValidationPolicy.fromJsonString(text);
      } on PolicyFormatException catch (e) {
        return e;
      }
      fail('accepted: $text');
    }

    test('unknown level names the key and the allowed values', () {
      final e = rejected('{"signatureIntact":"maybe"}');
      expect(e.key, 'signatureIntact');
      expect(e.message, contains('maybe'));
      expect(e.message, contains('fail, warn, inform, ignore'));
    });

    test('unknown constraint is rejected', () {
      final e = rejected('{"signatureIntakt":"fail"}');
      expect(e.message, contains('signatureIntakt'));
    });

    test('wrong value type is rejected', () {
      expect(rejected('{"signatureIntact":3}').key, 'signatureIntact');
    });

    test('not JSON and not an object are rejected', () {
      expect(rejected('{nope').message, contains('not valid JSON'));
      expect(rejected('[]').message, contains('JSON object'));
    });
  });
}
