import 'diagnostic_data.dart';
import 'indication.dart';
import 'warning.dart';

/// Result of one building block for one signature.
final class BuildingBlockResult {
  const BuildingBlockResult(
    this.block,
    this.indication, {
    this.subIndication,
    this.messages = const [],
  });

  final BuildingBlock block;
  final BlockIndication indication;
  final SubIndication? subIndication;
  final List<ValidationMessage> messages;

  Map<String, Object?> toJson() => {
    'block': block.abbreviation,
    'title': block.title,
    'clause': block.clause,
    'indication': indication.etsi,
    'subIndication': subIndication?.etsi,
    'messages': [
      for (final m in messages) {'code': m.code.name, 'text': m.text},
    ],
  };
}

/// Detailed report for one signature: every building block that ran.
final class SignatureDetailedReport {
  const SignatureDetailedReport({
    required this.index,
    required this.blocks,
    required this.indication,
    required this.subIndication,
  });

  final int index;

  /// Blocks in execution order. A block that did not run (because an
  /// earlier one already decided the outcome) is absent.
  final List<BuildingBlockResult> blocks;
  final Indication indication;
  final SubIndication? subIndication;

  /// The result of [block], or null if it did not run.
  BuildingBlockResult? result(BuildingBlock block) {
    for (final b in blocks) {
      if (b.block == block) return b;
    }
    return null;
  }

  Map<String, Object?> toJson() => {
    'index': index,
    'indication': indication.etsi,
    'subIndication': subIndication?.etsi,
    'blocks': [for (final b in blocks) b.toJson()],
  };
}

final class DetailedReport {
  const DetailedReport(this.signatures);

  final List<SignatureDetailedReport> signatures;

  Map<String, Object?> toJson() => {
    'signatures': [for (final s in signatures) s.toJson()],
  };
}

/// Simple report entry for one signature.
final class SimpleSignatureReport {
  const SimpleSignatureReport({
    required this.index,
    required this.indication,
    required this.subIndication,
    required this.scope,
    required this.signedBy,
    required this.signingTime,
  });

  final int index;
  final Indication indication;

  /// Present unless the indication is [Indication.totalPassed].
  final SubIndication? subIndication;

  /// What the signature covers; empty when the input was unreadable.
  final List<SignatureScope> scope;

  /// Subject of the signing certificate, when identified.
  final String? signedBy;

  /// The signer's claimed signing time (not proven; see GLOSSARY).
  final DateTime? signingTime;

  Map<String, Object?> toJson() => {
    'index': index,
    'indication': indication.etsi,
    'subIndication': subIndication?.etsi,
    'signedBy': signedBy,
    'signingTime': signingTime?.toUtc().toIso8601String(),
    'scope': [
      for (final sc in scope)
        {'kind': sc.kind.name, 'name': sc.name, 'description': sc.description},
    ],
  };
}

final class SimpleReport {
  const SimpleReport(this.signatures);

  final List<SimpleSignatureReport> signatures;

  Map<String, Object?> toJson() => {
    'signatures': [for (final s in signatures) s.toJson()],
  };
}

/// Output of `Validator.decide`.
final class ValidationReport {
  const ValidationReport({
    required this.simple,
    required this.detailed,
    this.warnings = const [],
  });

  final SimpleReport simple;
  final DetailedReport detailed;

  /// Non-fatal observations about the input, for example indefinite-length
  /// BER from a legacy tool (ADR-0004). They never change an indication.
  final List<ValidationWarning> warnings;

  /// The simple and detailed reports as JSON-encodable objects (enums by
  /// their EN 319 102-1 spelling, times ISO 8601 UTC).
  Map<String, Object?> toJson() => {
    'simple': simple.toJson(),
    'detailed': detailed.toJson(),
  };
}
