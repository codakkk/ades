import '../asn1/asn1.dart';
import '../asn1/structure.dart';

/// Parses an ASN.1 UTCTime or GeneralizedTime (RFC 5280 4.1.2.5, `Z` only,
/// seconds required) into a UTC [DateTime].
DateTime parseAsn1Time(Asn1Element e, String what) {
  final isUtc = e.tag == const Asn1Tag.universal(23);
  final isGen = e.tag == const Asn1Tag.universal(24);
  if (!isUtc && !isGen) {
    throw StructureException('$what must be UTCTime or GeneralizedTime');
  }
  final c = e.contentBytes;
  final expectedLength = isUtc ? 13 : 15;
  if (c.length != expectedLength || c.last != 0x5a) {
    throw StructureException('$what is not in YYMMDDHHMMSSZ form');
  }
  final digits = c.length - 1;
  final v = <int>[];
  for (var i = 0; i < digits; i++) {
    final d = c[i] - 0x30;
    if (d < 0 || d > 9) throw StructureException('$what has a non-digit');
    v.add(d);
  }
  int two(int i) => v[i] * 10 + v[i + 1];
  var year = isUtc ? two(0) : two(0) * 100 + two(2);
  var p = isUtc ? 2 : 4;
  if (isUtc) year += year >= 50 ? 1900 : 2000;
  final month = two(p);
  final day = two(p + 2);
  final hour = two(p + 4);
  final minute = two(p + 6);
  final second = two(p + 8);
  final t = DateTime.utc(year, month, day, hour, minute, second);
  if (t.year != year ||
      t.month != month ||
      t.day != day ||
      hour > 23 ||
      minute > 59 ||
      second > 59) {
    throw StructureException('$what is not a valid date');
  }
  return t;
}
