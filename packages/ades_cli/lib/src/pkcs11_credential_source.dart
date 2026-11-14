import 'package:ades/ades.dart';
import 'package:ades_pkcs11/ades_pkcs11.dart';
import 'package:args/args.dart';

import 'credential_source.dart';
import 'environment.dart';

/// `--pkcs11 <module|auto>`: a smart card (CNS) or HSM through a PKCS#11
/// module. `auto` probes the known CNS middleware locations
/// (`discoverPkcs11Modules`). Every credential (certificate) found on the
/// tokens is listed; `--pkcs11-credential` picks one (1-based number or
/// label), otherwise the user is asked when there is more than one. The PIN
/// is requested through [CliEnvironment.promptPassword], once per token.
final class Pkcs11CredentialSource extends CredentialSource {
  const Pkcs11CredentialSource();

  @override
  String get name => 'PKCS#11';

  @override
  void addOptions(ArgParser parser) {
    parser
      ..addOption(
        'pkcs11',
        valueHelp: 'module|auto',
        help:
            'Sign with a smart card or HSM through this PKCS#11 module\n'
            '(path to the middleware library), or "auto" to find a known\n'
            'CNS middleware.',
      )
      ..addOption(
        'pkcs11-credential',
        valueHelp: 'number|label',
        help:
            'Which credential on the token to use (see the list printed\n'
            'by --pkcs11). Asked interactively when omitted.',
      );
  }

  @override
  bool selected(ArgResults args) => args.wasParsed('pkcs11');

  @override
  Future<SigningCredential> open(ArgResults args, CliEnvironment env) async {
    var path = args['pkcs11'] as String;
    if (path == 'auto') path = await _discover();

    final Pkcs11Module module;
    try {
      module = await Pkcs11Module.load(
        path,
        onPin: (req) async {
          final pin = await env.promptPassword('PIN for "${req.tokenLabel}": ');
          return pin.isEmpty ? null : pin;
        },
      );
    } on Pkcs11Exception catch (e) {
      throw CredentialSourceException(
        'Cannot load PKCS#11 module "$path": ${e.message}',
      );
    }
    env.cleanups.add(module.close);

    final List<Pkcs11Credential> creds;
    try {
      creds = await module.listCredentials();
    } on Pkcs11Exception catch (e) {
      throw CredentialSourceException('Cannot list credentials: ${e.message}');
    }
    if (creds.isEmpty) {
      throw CredentialSourceException(
        'No certificate found on any token of "$path". '
        'Is the card inserted?',
      );
    }
    // Stable numbering: modules list in no particular order.
    creds.sort((a, b) {
      final t = a.tokenLabel.compareTo(b.tokenLabel);
      return t != 0 ? t : a.label.compareTo(b.label);
    });
    return _choose(creds, args['pkcs11-credential'] as String?, env);
  }

  Future<String> _discover() async {
    final report = await discoverPkcs11Modules();
    if (report.found.length == 1) return report.found.single.path;
    final b = StringBuffer();
    if (report.found.isEmpty) {
      b.write('No known PKCS#11 middleware found on this machine.');
      for (final f in report.failed) {
        b.write('\n  failed: ${f.candidate.path}: ${f.reason}');
      }
      b.write('\nPass the library path: --pkcs11 <module>.');
    } else {
      b.write('Several PKCS#11 modules found; choose one with --pkcs11:');
      for (final f in report.found) {
        b.write('\n  ${f.path}');
      }
    }
    throw CredentialSourceException('$b');
  }

  Future<Pkcs11Credential> _choose(
    List<Pkcs11Credential> creds,
    String? wanted,
    CliEnvironment env,
  ) async {
    String describe(int i) {
      final c = creds[i];
      final ku = c.keyUsage;
      final usage = ku == null || ku.isEmpty
          ? ''
          : '  [${ku.map((u) => u.name).join(', ')}]';
      return '  ${i + 1}) ${c.label}  (token: ${c.tokenLabel})$usage';
    }

    final listing =
        'Credentials:\n'
        '${[for (var i = 0; i < creds.length; i++) describe(i)].join('\n')}\n';

    Pkcs11Credential? pick(String answer) {
      final n = int.tryParse(answer);
      if (n != null) return n >= 1 && n <= creds.length ? creds[n - 1] : null;
      final byLabel = creds.where((c) => c.label == answer).toList();
      return byLabel.length == 1 ? byLabel.single : null;
    }

    if (wanted != null) {
      final c = pick(wanted.trim());
      if (c != null) return c;
      throw CredentialSourceException(
        'No unique credential "$wanted". $listing',
      );
    }
    if (creds.length == 1) return creds.single;

    final ask = env.promptLine;
    if (ask == null) {
      throw CredentialSourceException(
        'Several credentials found and no terminal to ask on; '
        'use --pkcs11-credential.\n$listing',
      );
    }
    env.err.write(listing);
    for (var attempt = 0; attempt < 3; attempt++) {
      final answer = await ask('Choose a credential [1-${creds.length}]: ');
      final c = pick(answer.trim());
      if (c != null) return c;
      env.err.writeln('Not a valid choice.');
    }
    throw CredentialSourceException('No credential chosen.');
  }
}
