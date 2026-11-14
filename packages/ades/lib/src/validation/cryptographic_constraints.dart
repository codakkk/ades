import '../crypto/algorithms.dart';
import 'diagnostic_data.dart';

/// DSS 6.5.1's default cryptographic constraints (`constraint.xml`,
/// `Cryptographic`): the algorithms and key sizes it accepts and the dates
/// they expire (ETSI TS 119 312), restricted to the algorithms we can read.
/// Only the levels are policy (see `ValidationPolicy.cryptographic`); the
/// tables are DSS's.

/// DSS `AlgoExpirationDate/@UpdateDate`: expiries after it only warn.
final policyUpdateDate = DateTime.utc(2026, 2, 1);

/// What is wrong with an algorithm or key.
enum CryptographicProblem {
  /// Not an acceptable algorithm, or a key below the minimum size.
  notAcceptable,

  /// Acceptable, but past its expiry date at the validation time.
  expired,
}

/// One finding of [checkCryptography].
final class CryptographicFinding {
  const CryptographicFinding(
    this.problem,
    this.text, {
    this.expiresAfterPolicyUpdate = false,
  });

  final CryptographicProblem problem;
  final String text;

  /// For [CryptographicProblem.expired]: the expiry date is after the policy
  /// update date, so DSS lowers the level to a warning.
  final bool expiresAfterPolicyUpdate;
}

const _minKeySize = {
  PublicKeyAlgorithm.rsa: 786,
  PublicKeyAlgorithm.ecdsa: 160,
};

/// Key size buckets: a key of size S expires on the date of the largest
/// listed size not above S (null: never).
final _keyExpiry = <PublicKeyAlgorithm, List<(int, DateTime?)>>{
  PublicKeyAlgorithm.rsa: [
    (786, DateTime.utc(2010, 8, 1)),
    (1024, DateTime.utc(2019, 10, 1)),
    (1536, DateTime.utc(2019, 10, 1)),
    (1900, DateTime.utc(2027, 1, 1)),
    (3000, DateTime.utc(2035, 1, 1)),
  ],
  PublicKeyAlgorithm.ecdsa: [
    (160, DateTime.utc(2012, 8, 1)),
    (163, DateTime.utc(2012, 8, 1)),
    (224, DateTime.utc(2021, 10, 1)),
    (256, null),
  ],
};

final _digestExpiry = <DigestAlgorithm, DateTime?>{
  DigestAlgorithm.sha1: DateTime.utc(2012, 8, 1),
  DigestAlgorithm.sha256: null,
  DigestAlgorithm.sha384: null,
  DigestAlgorithm.sha512: null,
};

/// Judges a signature made with [digest] and a key of [keyAlgorithm] and
/// [keySize] bits, at [time]. [what] names the token for messages.
List<CryptographicFinding> checkCryptography({
  required String what,
  required DigestAlgorithm digest,
  required PublicKeyAlgorithm keyAlgorithm,
  required int? keySize,
  required DateTime time,
}) {
  final findings = <CryptographicFinding>[];
  void expiry(DateTime? date, String subject) {
    if (date == null || time.isBefore(date)) return;
    findings.add(
      CryptographicFinding(
        CryptographicProblem.expired,
        '$what: $subject expired on ${date.toIso8601String()}',
        expiresAfterPolicyUpdate: date.isAfter(policyUpdateDate),
      ),
    );
  }

  expiry(_digestExpiry[digest], digest.displayName);
  final min = _minKeySize[keyAlgorithm];
  if (min == null || keySize == null) {
    findings.add(
      CryptographicFinding(
        CryptographicProblem.notAcceptable,
        '$what: the key algorithm is not acceptable',
      ),
    );
  } else if (keySize < min) {
    findings.add(
      CryptographicFinding(
        CryptographicProblem.notAcceptable,
        '$what: a $keySize-bit ${keyAlgorithm.name} key is below the '
        'minimum of $min bits',
      ),
    );
  } else {
    DateTime? date;
    for (final (size, d) in _keyExpiry[keyAlgorithm]!) {
      if (size <= keySize) date = d;
    }
    expiry(date, '$keySize-bit ${keyAlgorithm.name} keys');
  }
  return findings;
}
