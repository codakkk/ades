// Ticket 06: diagnostic data round-trips through JSON; decide over the
// round-tripped data gives the same reports.
import 'dart:convert';

import 'package:ades/ades.dart';
import 'package:test/test.dart';

import 'support/report_summary.dart';
import 'support/tier1.dart';

void main() {
  late Validator validator;
  setUp(() {
    validator = Validator(
      trustAnchors: [TrustAnchor.fromDer(tier1('pki/rsa2048/leaf-qsign.der'))],
    );
  });

  final fixtures = [
    'signatures/positive/rsa2048-qsign.p7m',
    'signatures/negative/rsa2048-tampered-content.p7m',
    'signatures/negative/rsa2048-wrong-message-digest.p7m',
    'signatures/negative/rsa2048-non-der-signed-attrs.p7m',
    'signatures/negative/rsa2048-untrusted-root.p7m',
  ];

  for (final f in fixtures) {
    test('$f round-trips losslessly and decides identically', () async {
      final data = await validator.collect(tier1(f));
      final text = jsonEncode(data.toJson());
      final back = DiagnosticData.fromJson(
        jsonDecode(text) as Map<String, Object?>,
      );
      expect(jsonEncode(back.toJson()), text);
      final time = DateTime.utc(2026, 11, 9);
      expect(
        summarize(Validator.decide(back, validationTime: time)),
        summarize(Validator.decide(data, validationTime: time)),
      );
    });
  }

  // Ticket 07 facts: ECDSA, detached scope, SIGNED_DATA_NOT_FOUND.
  final ticket07 = <(String, String, bool)>[
    ('p256', 'signatures/positive/p256-qsign.p7m', false),
    ('p256', 'signatures/positive/p256-qsign.p7s', true),
    ('rsa2048', 'signatures/positive/rsa2048-qsign.p7s', true),
    ('rsa2048', 'signatures/positive/rsa2048-qsign.p7s', false),
  ];
  for (final (hierarchy, f, withDocument) in ticket07) {
    test('$f${withDocument ? ' + document' : ''} round-trips and decides '
        'identically', () async {
      final v = Validator(
        trustAnchors: [TrustAnchor.fromDer(tier1('pki/$hierarchy/root.der'))],
      );
      final data = await v.collect(
        tier1(f),
        detachedContent: withDocument ? tier1('content/hello.txt') : null,
      );
      final text = jsonEncode(data.toJson());
      final back = DiagnosticData.fromJson(
        jsonDecode(text) as Map<String, Object?>,
      );
      expect(jsonEncode(back.toJson()), text);
      final s = back.signatures.single;
      if (f.endsWith('.p7s')) {
        expect(s.contentAvailable, withDocument);
        if (withDocument) {
          expect(s.scope!.kind, SignatureScopeKind.detachedDocument);
        }
      }
      final time = DateTime.utc(2026, 11, 9);
      final report = Validator.decide(back, validationTime: time);
      expect(
        summarize(report),
        summarize(Validator.decide(data, validationTime: time)),
      );
      if (f.endsWith('.p7s') && !withDocument) {
        expect(
          report.detailed.signatures.single.subIndication,
          SubIndication.signedDataNotFound,
        );
      }
    });
  }

  test('malformed input round-trips', () async {
    final data = await validator.collect(tier1('content/hello.txt'));
    expect(data.formatFailure, isNotNull);
    final back = DiagnosticData.fromJson(
      jsonDecode(jsonEncode(data.toJson())) as Map<String, Object?>,
    );
    expect(back.formatFailure, data.formatFailure);
  });
}
