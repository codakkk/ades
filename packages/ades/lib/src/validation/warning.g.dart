// GENERATED CODE - DO NOT MODIFY BY HAND

part of 'warning.dart';

// **************************************************************************
// JsonSerializableGenerator
// **************************************************************************

ValidationWarning _$ValidationWarningFromJson(Map<String, dynamic> json) =>
    ValidationWarning(
      $enumDecode(_$WarningCodeEnumMap, json['code']),
      json['text'] as String,
    );

Map<String, dynamic> _$ValidationWarningToJson(ValidationWarning instance) =>
    <String, dynamic>{
      'code': _$WarningCodeEnumMap[instance.code]!,
      'text': instance.text,
    };

const _$WarningCodeEnumMap = {
  WarningCode.indefiniteLength: 'indefiniteLength',
  WarningCode.nonMinimalEncoding: 'nonMinimalEncoding',
  WarningCode.constructedString: 'constructedString',
  WarningCode.unsortedSet: 'unsortedSet',
  WarningCode.nonDerEncoding: 'nonDerEncoding',
};
