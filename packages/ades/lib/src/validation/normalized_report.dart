import 'report.dart';

/// Our side of the DSS oracle comparison (ADR-0010). Format documented in
/// `tool/dss_oracle/README.md`. Public so the test helpers and `ades_cli oracle` compare through the same code.
///
/// Normalized shape (one entry per signature):
/// `{index, indication, subIndication, signingTime, scope: [{kind}],
/// blocks: {FC|ISC|VCI|XCV|CV|SAV: {indication, subIndication}}}`.
Map<String, Object?> normalizeReport(
  ValidationReport report, {
  required String validationTime,
}) {
  final simple = report.simple.signatures;
  final detailed = report.detailed.signatures;
  return {
    'validationTime': validationTime,
    'signatures': [
      for (var i = 0; i < simple.length; i++)
        {
          'index': simple[i].index,
          'indication': simple[i].indication.etsi,
          'subIndication': simple[i].subIndication?.etsi,
          // DSS prints whole seconds without a fraction.
          'signingTime': simple[i].signingTime
              ?.toUtc()
              .toIso8601String()
              .replaceFirst('.000Z', 'Z'),
          'scope': [
            for (final s in simple[i].scope) {'kind': _scopeKind(s.kind.name)},
          ],
          'blocks': {
            for (final b in detailed[i].blocks)
              b.block.abbreviation: {
                'indication': b.indication.etsi,
                'subIndication': b.subIndication?.etsi,
              },
          },
        },
    ],
  };
}

/// DSS scope kinds are FULL / PARTIAL / DIGEST / ARCHIVE. Both of our kinds
/// (enveloped content, detached document) cover the whole document: FULL.
String _scopeKind(String ours) => switch (ours) {
  'envelopedContent' || 'detachedDocument' => 'FULL',
  _ => ours.toUpperCase(),
};

/// Projects a DSS golden (or ours) to the compared fields, dropping DSS-only
/// information (`constraints`, scope `name`, `dssVersion`, `error`).
Map<String, Object?> projectForComparison(Map<String, Object?> json) {
  final sigs = (json['signatures']! as List).cast<Map<String, Object?>>();
  return {
    'signatures': [
      for (final s in sigs)
        {
          'index': s['index'],
          'indication': s['indication'],
          'subIndication': s['subIndication'],
          'signingTime': s['signingTime'],
          'scope': [
            for (final k in (s['scope']! as List).cast<Map<String, Object?>>())
              {'kind': k['kind']},
          ],
          'blocks': {
            for (final e in (s['blocks']! as Map<String, Object?>).entries)
              e.key: {
                'indication': (e.value! as Map)['indication'],
                'subIndication': (e.value! as Map)['subIndication'],
              },
          },
        },
    ],
  };
}

/// Flattens a projected report to `path -> scalar` for diffing, e.g.
/// `signatures[0].blocks.XCV.subIndication`. A missing path reads as null.
Map<String, Object?> flattenReport(Object? node, [String prefix = '']) {
  final out = <String, Object?>{};
  void walk(Object? n, String p) {
    if (n is Map) {
      for (final e in n.entries) {
        walk(e.value, p.isEmpty ? '${e.key}' : '$p.${e.key}');
      }
    } else if (n is List) {
      // Record the length so a missing signature or scope shows up as a diff.
      out['$p.length'] = n.length;
      for (var i = 0; i < n.length; i++) {
        walk(n[i], '$p[$i]');
      }
    } else {
      out[p] = n;
    }
  }

  walk(node, prefix);
  return out;
}
