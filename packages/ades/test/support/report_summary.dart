import 'package:ades/ades.dart';

/// Plain-data view of a report, for comparing reports in tests.
Object summarize(ValidationReport r) => [
  for (final s in r.simple.signatures)
    [
      s.index,
      s.indication.etsi,
      s.subIndication?.etsi,
      s.signedBy,
      s.signingTime?.toIso8601String(),
    ],
  for (final s in r.detailed.signatures)
    [
      s.index,
      s.indication.etsi,
      s.subIndication?.etsi,
      for (final b in s.blocks)
        [
          b.block.abbreviation,
          b.indication.etsi,
          b.subIndication?.etsi,
          for (final m in b.messages) '${m.code.name}/${m.severity.name}',
        ],
    ],
];
