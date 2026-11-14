import 'dart:convert';
import 'dart:typed_data';

import 'package:json_annotation/json_annotation.dart';

import '../x509/certificate.dart' show BasicConstraints, KeyUsageFlag;

/// [Uint8List] as a base64 string.
final class BytesConverter implements JsonConverter<Uint8List, String> {
  const BytesConverter();

  @override
  Uint8List fromJson(String json) => base64Decode(json);

  @override
  String toJson(Uint8List object) => base64Encode(object);
}

/// Nullable [Uint8List] as a base64 string or null.
final class NullableBytesConverter
    implements JsonConverter<Uint8List?, String?> {
  const NullableBytesConverter();

  @override
  Uint8List? fromJson(String? json) => json == null ? null : base64Decode(json);

  @override
  String? toJson(Uint8List? object) =>
      object == null ? null : base64Encode(object);
}

/// Optional keyUsage bit set as a list of flag names.
final class KeyUsageConverter
    implements JsonConverter<Set<KeyUsageFlag>?, List<dynamic>?> {
  const KeyUsageConverter();

  @override
  Set<KeyUsageFlag>? fromJson(List<dynamic>? json) => json == null
      ? null
      : {for (final n in json) KeyUsageFlag.values.byName(n as String)};

  @override
  List<dynamic>? toJson(Set<KeyUsageFlag>? object) => object == null
      ? null
      : [
          // Bit order, so the JSON is deterministic.
          for (final f in KeyUsageFlag.values)
            if (object.contains(f)) f.name,
        ];
}

/// Optional basicConstraints as `{isCa, pathLenConstraint}`.
final class BasicConstraintsConverter
    implements JsonConverter<BasicConstraints?, Map<String, dynamic>?> {
  const BasicConstraintsConverter();

  @override
  BasicConstraints? fromJson(Map<String, dynamic>? json) => json == null
      ? null
      : BasicConstraints(
          isCa: json['isCa'] as bool,
          pathLenConstraint: json['pathLenConstraint'] as int?,
        );

  @override
  Map<String, dynamic>? toJson(BasicConstraints? object) => object == null
      ? null
      : {'isCa': object.isCa, 'pathLenConstraint': object.pathLenConstraint};
}
