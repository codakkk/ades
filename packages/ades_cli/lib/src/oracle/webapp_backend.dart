import 'dart:convert';
import 'dart:io';

import 'dss_backend.dart';

/// POSTs [body] (JSON) to [url] and returns the response body.
typedef HttpPost = Future<String> Function(Uri url, String body);

/// Returns the DSS policy XML for [policy].
typedef PolicyLoader = Future<String> Function(OraclePolicy policy);

Future<String> _defaultPost(Uri url, String body) async {
  final client = HttpClient();
  try {
    final req = await client.postUrl(url);
    req.headers.contentType = ContentType.json;
    req.write(body);
    final res = await req.close();
    final text = await utf8.decodeStream(res);
    if (res.statusCode != 200) {
      throw DssBackendException('webapp answered ${res.statusCode}: $text');
    }
    return text;
  } on SocketException catch (e) {
    throw DssBackendException(
      'cannot reach the DSS webapp at $url (${e.message}); start it with '
      '"docker compose -f tool/dss_webapp/docker-compose.yml up -d"',
    );
  } finally {
    client.close(force: true);
  }
}

/// The policy files of the pinned harness image, so the webapp validates
/// under the same constraints as the harness (its own default policy is
/// the TL-based "QES AES/QC AES" one).
Future<String> _policyFromHarnessImage(OraclePolicy policy) async {
  final version = readPinnedDssVersion();
  final r = await Process.run('docker', [
    'run',
    '--rm',
    '--network',
    'none',
    '--entrypoint',
    'cat',
    'ades-dss-oracle:$version',
    '/app/policy/${policy.dssName}.xml',
  ]);
  if (r.exitCode != 0) {
    throw DssBackendException(
      'cannot read the ${policy.dssName} policy from image ades-dss-oracle:$version '
      '(run "dart run tool/dss_oracle/run.dart" once to build it): '
      '${r.stderr}',
    );
  }
  return r.stdout as String;
}

/// The DSS demo webapp REST API (`tool/dss_webapp`). Trust comes from the
/// webapp's own trusted lists (our `-t` anchors and `-c` certificates cannot
/// be handed over), so fixtures signed under test CAs come back with
/// NO_CERTIFICATE_CHAIN_FOUND; it is useful for real signatures.
final class WebappBackend implements DssBackend {
  WebappBackend({
    required this.baseUrl,
    HttpPost post = _defaultPost,
    PolicyLoader policyXml = _policyFromHarnessImage,
  }) : _post = post,
       _policyXml = policyXml;

  final String baseUrl;
  final HttpPost _post;
  final PolicyLoader _policyXml;

  @override
  String get name => 'webapp';

  @override
  Future<Map<String, Object?>> validate(OracleRequest q) async {
    String b64(String path) => base64.encode(File(path).readAsBytesSync());
    final policy = await _policyXml(q.policy);
    final body = jsonEncode({
      'signedDocument': {'bytes': b64(q.signaturePath), 'name': 'signature'},
      if (q.documentPath != null)
        'originalDocuments': [
          {'bytes': b64(q.documentPath!), 'name': 'content'},
        ],
      'policy': {
        'bytes': base64.encode(utf8.encode(policy)),
        'name': '${q.policy.dssName}.xml',
      },
      'validationTime': q.validationTime.toUtc().toIso8601String(),
      'tokenExtractionStrategy': 'NONE',
    });
    final url = Uri.parse(
      '${baseUrl.replaceFirst(RegExp(r'/+$'), '')}'
      '/services/rest/validation/validateSignature',
    );
    final Object? decoded;
    try {
      decoded = jsonDecode(await _post(url, body));
    } on FormatException catch (e) {
      throw DssBackendException('webapp returned invalid JSON: ${e.message}');
    }
    return normalizeWebappReports(
      decoded as Map<String, Object?>,
      policy: q.policy.dssName,
      validationTime: q.validationTime,
    );
  }
}

const _blocks = ['FC', 'ISC', 'VCI', 'XCV', 'CV', 'SAV'];

/// Webapp `WSReportsDTO` JSON (SimpleReport + DetailedReport) to the oracle
/// JSON format of `tool/dss_oracle/README.md` (without the informational
/// constraint lists).
Map<String, Object?> normalizeWebappReports(
  Map<String, Object?> reports, {
  required String policy,
  required DateTime validationTime,
}) {
  final simple = reports['SimpleReport'] as Map<String, Object?>?;
  final detailed = reports['DetailedReport'] as Map<String, Object?>?;
  if (simple == null || detailed == null) {
    throw DssBackendException('webapp response has no SimpleReport');
  }
  final bbbs = {
    for (final b
        in (detailed['BasicBuildingBlocks'] as List? ?? const [])
            .cast<Map<String, Object?>>())
      b['Id']: b,
  };
  final entries =
      (simple['signatureOrTimestampOrEvidenceRecord'] as List? ?? [])
          .cast<Map<String, Object?>>();
  final signatures = <Map<String, Object?>>[];
  for (final e in entries) {
    final s = e['Signature'] as Map<String, Object?>?;
    if (s == null) continue;
    final bbb = bbbs[s['Id']];
    signatures.add({
      'index': signatures.length,
      'indication': s['Indication'],
      'subIndication': s['SubIndication'],
      'signingTime': s['SigningTime'],
      'scope': [
        for (final sc
            in (s['SignatureScope'] as List? ?? const [])
                .cast<Map<String, Object?>>())
          {'kind': sc['scope'], 'name': sc['name']},
      ],
      'blocks': {
        if (bbb != null)
          for (final k in _blocks)
            if (bbb[k] is Map)
              k: {
                'indication':
                    ((bbb[k] as Map)['Conclusion'] as Map)['Indication'],
                'subIndication':
                    ((bbb[k] as Map)['Conclusion'] as Map)['SubIndication'],
              },
      },
    });
  }
  return {
    'dssVersion': 'webapp',
    'validationTime': validationTime.toUtc().toIso8601String(),
    'policy': policy,
    'signatures': signatures,
  };
}
