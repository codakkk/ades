import 'package:json_annotation/json_annotation.dart';

part 'warning.g.dart';

/// Why a validation warning was raised. Warnings never change an indication
/// (ADR-0004): they flag input that is valid but not what a strict DER
/// producer would write.
enum WarningCode {
  /// An indefinite-length encoding outside the signed attributes.
  indefiniteLength,

  /// A non-minimal length, tag number or INTEGER outside the signed
  /// attributes.
  nonMinimalEncoding,

  /// A constructed (segmented) OCTET STRING outside the signed attributes.
  constructedString,

  /// A SET OF not in DER order outside the signed attributes.
  unsortedSet,

  /// Any other BER form that DER forbids.
  nonDerEncoding,
}

/// A non-fatal observation about the input, reported once per kind.
@JsonSerializable()
final class ValidationWarning {
  const ValidationWarning(this.code, this.text);

  factory ValidationWarning.fromJson(Map<String, dynamic> json) =>
      _$ValidationWarningFromJson(json);

  Map<String, dynamic> toJson() => _$ValidationWarningToJson(this);

  final WarningCode code;

  /// Human-readable explanation (English); do not parse it.
  final String text;

  @override
  String toString() => '${code.name}: $text';
}
