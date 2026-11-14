/// Process exit codes of `ades`.
///
/// For `validate` they follow the worst indication over all signatures:
/// failed (1) beats indeterminate (2) beats passed (0). The values above 63
/// follow sysexits.h.
abstract final class ExitCode {
  /// Validation TOTAL-PASSED, or signing succeeded.
  static const int ok = 0;

  /// Validation TOTAL-FAILED (including unreadable signature).
  static const int failed = 1;

  /// Validation INDETERMINATE.
  static const int indeterminate = 2;

  /// Bad command line (EX_USAGE).
  static const int usage = 64;

  /// Input data unusable, for example a wrong password, a bad key file or a
  /// credential the core refuses (EX_DATAERR).
  static const int dataError = 65;

  /// An input file does not exist or cannot be read (EX_NOINPUT).
  static const int noInput = 66;

  /// The requested feature is not available in this build (EX_UNAVAILABLE).
  static const int unavailable = 69;
}
