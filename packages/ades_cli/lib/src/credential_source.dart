import 'dart:io';

import 'package:ades/ades.dart';
import 'package:ades_soft/ades_soft.dart';
import 'package:args/args.dart';

import 'environment.dart';
import 'pkcs11_credential_source.dart';

/// A way to obtain a [SigningCredential] for `ades sign`.
///
/// To add one (for example `--pkcs11`, ticket 15): implement this class and
/// append an instance to [CredentialSource.registry]. The sign command
/// registers [addOptions] on its parser, asks every source whether it is
/// [selected], and requires exactly one. Sources report user-fixable
/// problems with [CredentialSourceException] (exit code 65).
abstract class CredentialSource {
  const CredentialSource();

  /// Sources known to `ades sign`. Add new ones here.
  static const List<CredentialSource> registry = [
    Pkcs12CredentialSource(),
    Pkcs11CredentialSource(),
  ];

  /// Human-readable name used in messages.
  String get name;

  /// Adds this source's options (prefix them to avoid clashes).
  void addOptions(ArgParser parser);

  /// Whether the user chose this source on the command line.
  bool selected(ArgResults args);

  /// Opens the credential. [env] gives access to the password prompt.
  Future<SigningCredential> open(ArgResults args, CliEnvironment env);
}

/// A credential problem the user can fix; maps to exit code 65.
final class CredentialSourceException implements Exception {
  CredentialSourceException(this.message);
  final String message;
  @override
  String toString() => message;
}

/// `--p12 <file>`: PKCS#12 through `ades_soft`. The password is read from
/// `--p12-password-file` or prompted, never taken from the command line.
final class Pkcs12CredentialSource extends CredentialSource {
  const Pkcs12CredentialSource();

  @override
  String get name => 'PKCS#12';

  @override
  void addOptions(ArgParser parser) {
    parser
      ..addOption('p12', valueHelp: 'file', help: 'Sign with a PKCS#12 file.')
      ..addOption(
        'p12-password-file',
        valueHelp: 'file',
        help:
            'Read the PKCS#12 password from this file (first line).\n'
            'Without it the password is prompted.',
      );
  }

  @override
  bool selected(ArgResults args) => args.wasParsed('p12');

  @override
  Future<SigningCredential> open(ArgResults args, CliEnvironment env) async {
    final file = File(args['p12'] as String);
    if (!file.existsSync()) {
      throw CredentialSourceException('PKCS#12 file not found: ${file.path}');
    }
    final bytes = file.readAsBytesSync();
    final pwFile = args['p12-password-file'] as String?;
    String password;
    if (pwFile != null) {
      final f = File(pwFile);
      if (!f.existsSync()) {
        throw CredentialSourceException('Password file not found: $pwFile');
      }
      final lines = f.readAsLinesSync();
      password = lines.isEmpty ? '' : lines.first;
    } else {
      password = await env.promptPassword('PKCS#12 password: ');
    }
    try {
      return SoftSigningCredential.fromPkcs12(bytes, password: password);
    } on SoftKeyLoadException catch (e) {
      throw CredentialSourceException(
        e.failure == SoftKeyLoadFailure.wrongPassword
            ? 'Wrong PKCS#12 password.'
            : 'Cannot use PKCS#12 file: ${e.failure.name}.',
      );
    }
  }
}
