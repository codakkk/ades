@TestOn('vm')
library;

import 'dart:convert';

import 'package:ades_cli/src/oracle/oracle_command.dart';
import 'package:test/test.dart';

const _fx = '../../fixtures/tier1';

void main() {
  test('webapp backend posts policy+time and normalizes the reports', () async {
    Uri? url;
    Map<String, Object?>? sent;
    final backend = WebappBackend(
      baseUrl: 'http://dss.test:1/',
      policyXml: (p) async => '<ConstraintsParameters/>',
      post: (u, body) async {
        url = u;
        sent = jsonDecode(body) as Map<String, Object?>;
        return jsonEncode({
          'SimpleReport': {
            'signatureOrTimestampOrEvidenceRecord': [
              {
                'Signature': {
                  'Id': 'S-1',
                  'Indication': 'INDETERMINATE',
                  'SubIndication': 'NO_CERTIFICATE_CHAIN_FOUND',
                  'SigningTime': '2026-06-01T12:00:00Z',
                  'SignatureScope': [
                    {'scope': 'FULL', 'name': null},
                  ],
                },
              },
            ],
          },
          'DetailedReport': {
            'BasicBuildingBlocks': [
              {
                'Id': 'S-1',
                'FC': {
                  'Conclusion': {'Indication': 'PASSED', 'SubIndication': null},
                },
                'XCV': {
                  'Conclusion': {
                    'Indication': 'INDETERMINATE',
                    'SubIndication': 'NO_CERTIFICATE_CHAIN_FOUND',
                  },
                },
                'PSV': null,
              },
            ],
          },
        });
      },
    );
    final r = await backend.validate(
      OracleRequest(
        signaturePath: '$_fx/signatures/positive/rsa2048-qsign.p7m',
        trustAnchorPaths: ['$_fx/pki/rsa2048/root.pem'],
        validationTime: DateTime.utc(2026, 11, 10),
        policy: OraclePolicy.standard,
      ),
    );
    expect(
      url.toString(),
      'http://dss.test:1/services/rest/validation/validateSignature',
    );
    expect(sent!['validationTime'], '2026-11-10T00:00:00.000Z');
    expect((sent!['policy'] as Map)['name'], 'default.xml');
    final sig = (r['signatures'] as List).single as Map;
    expect(sig['subIndication'], 'NO_CERTIFICATE_CHAIN_FOUND');
    expect(sig['blocks'], {
      'FC': {'indication': 'PASSED', 'subIndication': null},
      'XCV': {
        'indication': 'INDETERMINATE',
        'subIndication': 'NO_CERTIFICATE_CHAIN_FOUND',
      },
    });
    expect(sig['scope'], [
      {'kind': 'FULL', 'name': null},
    ]);
  });

  test('unreachable webapp is a backend exception', () async {
    final backend = WebappBackend(
      baseUrl: 'http://127.0.0.1:1',
      policyXml: (_) async => '<x/>',
    );
    expect(
      () => backend.validate(
        OracleRequest(
          signaturePath: '$_fx/signatures/positive/rsa2048-qsign.p7m',
          trustAnchorPaths: const [],
          validationTime: DateTime.utc(2026),
          policy: OraclePolicy.standard,
        ),
      ),
      throwsA(isA<DssBackendException>()),
    );
  });
}
