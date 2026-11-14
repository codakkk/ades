import 'package:collection/collection.dart';

const _equality = ListEquality<int>();

/// Whether [a] and [b] hold the same bytes. The one byte-equality helper of
/// the core; not constant time, so never use it to compare secrets.
bool bytesEqual(List<int> a, List<int> b) => _equality.equals(a, b);
