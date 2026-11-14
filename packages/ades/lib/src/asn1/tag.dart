enum Asn1Class { universal, application, contextSpecific, private }

/// An ASN.1 identifier: class, constructed bit and tag number.
class Asn1Tag {
  const Asn1Tag(this.tagClass, this.constructed, this.number);

  const Asn1Tag.universal(int number, {bool constructed = false})
    : this(Asn1Class.universal, constructed, number);

  final Asn1Class tagClass;
  final bool constructed;
  final int number;

  static const boolean = Asn1Tag.universal(1);
  static const integer = Asn1Tag.universal(2);
  static const bitString = Asn1Tag.universal(3);
  static const octetString = Asn1Tag.universal(4);
  static const nullTag = Asn1Tag.universal(5);
  static const oid = Asn1Tag.universal(6);
  static const enumerated = Asn1Tag.universal(10);
  static const utf8String = Asn1Tag.universal(12);
  static const sequence = Asn1Tag.universal(16, constructed: true);
  static const set = Asn1Tag.universal(17, constructed: true);

  bool get isUniversal => tagClass == Asn1Class.universal;

  /// Class and number only (ignores the constructed bit).
  bool matches(Asn1Class c, int n) => tagClass == c && number == n;

  @override
  bool operator ==(Object other) =>
      other is Asn1Tag &&
      other.tagClass == tagClass &&
      other.constructed == constructed &&
      other.number == number;

  @override
  int get hashCode => Object.hash(tagClass, constructed, number);

  @override
  String toString() =>
      '${tagClass.name}${constructed ? ' constructed' : ''} $number';
}
