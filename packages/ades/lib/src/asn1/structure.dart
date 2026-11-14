import 'element.dart';
import 'tag.dart';

/// Thrown by ASN.1-based structure parsers (X.509, CMS) when well-formed
/// ASN.1 does not have the expected shape. Internal; the validator turns it
/// into a FORMAT_FAILURE report.
final class StructureException implements Exception {
  const StructureException(this.message);

  final String message;

  @override
  String toString() => 'StructureException: $message';
}

/// Helpers shared by structure parsers.
extension StructureAccess on Asn1Element {
  /// Children of a constructed element, or a [StructureException].
  List<Asn1Element> childrenOf(String what) =>
      children ?? (throw StructureException('$what must be constructed'));

  /// This element's children, requiring a SEQUENCE.
  List<Asn1Element> sequenceOf(String what) {
    if (tag != Asn1Tag.sequence) {
      throw StructureException('$what must be a SEQUENCE, found $tag');
    }
    return children!;
  }

  /// This element's children, requiring a SET.
  List<Asn1Element> setOf(String what) {
    if (tag != Asn1Tag.set) {
      throw StructureException('$what must be a SET, found $tag');
    }
    return children!;
  }

  /// Requires universal [expected] and returns this element.
  Asn1Element expect(Asn1Tag expected, String what) {
    if (tag != expected) {
      throw StructureException('$what must be $expected, found $tag');
    }
    return this;
  }

  bool isContext(int number) => tag.matches(Asn1Class.contextSpecific, number);
}
