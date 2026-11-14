import 'dart:io';

/// Everything the commands need from the outside world, injectable for
/// tests: output sinks and the password prompt.
final class CliEnvironment {
  CliEnvironment({
    required this.out,
    required this.err,
    required this.promptPassword,
    this.now,
    this.promptLine,
  });

  /// Real stdout/stderr and a hidden-input terminal prompt.
  factory CliEnvironment.system() => CliEnvironment(
    out: stdout,
    err: stderr,
    promptPassword: (message) async {
      stderr.write(message);
      final hadEcho = stdin.hasTerminal && stdin.echoMode;
      if (stdin.hasTerminal) stdin.echoMode = false;
      try {
        return stdin.readLineSync() ?? '';
      } finally {
        if (stdin.hasTerminal) stdin.echoMode = hadEcho;
        stderr.writeln();
      }
    },
    promptLine: (message) async {
      stderr.write(message);
      return stdin.readLineSync() ?? '';
    },
  );

  final StringSink out;
  final StringSink err;

  /// Asks the user for a secret; the argument is the prompt text.
  final Future<String> Function(String message) promptPassword;

  /// Asks the user a visible question (for example which credential to use).
  /// Null when the environment is not interactive.
  final Future<String> Function(String message)? promptLine;

  /// Callbacks run (in reverse order) when the command ends, for credential
  /// sources that hold a device open.
  final List<Future<void> Function()> cleanups = [];

  Future<void> runCleanups() async {
    while (cleanups.isNotEmpty) {
      try {
        await cleanups.removeLast()();
      } catch (_) {}
    }
  }

  /// Clock override (signing time).
  final DateTime Function()? now;
}
