import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:ades/ades.dart';
import 'package:args/args.dart';

import 'core_bridge.dart';
import 'credential_source.dart';
import 'environment.dart';
import 'exit_codes.dart';
import 'oracle/oracle_command.dart';

const String _usageHeader =
    '''
ades $adesVersion: sign and validate AdES signatures.

Usage: ades <command> [options]

Commands:
  validate   Validate a .p7m / .p7s and print the simple report.
  oracle     Compare our verdict with the pinned DSS (dev tool).
  sign       Create a CAdES signature.
''';

/// Runs the `ades` command line and returns the process exit code
/// (see [ExitCode]). Never throws for user errors.
Future<int> runCli(List<String> args, {required CliEnvironment env}) async {
  final validate = _validateParser();
  final sign = _signParser();
  if (args.isEmpty || args.first == '-h' || args.first == '--help') {
    env.out.writeln(_usageHeader);
    return args.isEmpty ? ExitCode.usage : ExitCode.ok;
  }
  final command = args.first;
  final rest = args.sublist(1);
  if (command == 'oracle') return _runOracle(rest, env);
  final parser = switch (command) {
    'validate' => validate,
    'sign' => sign,
    _ => null,
  };
  if (parser == null) {
    env.err.writeln('Unknown command "$command".\n$_usageHeader');
    return ExitCode.usage;
  }
  final ArgResults results;
  try {
    results = parser.parse(rest);
  } on FormatException catch (e) {
    env.err.writeln('${e.message}\n\n${_commandUsage(command, parser)}');
    return ExitCode.usage;
  }
  if (results['help'] as bool) {
    env.out.writeln(_commandUsage(command, parser));
    return ExitCode.ok;
  }
  try {
    return command == 'validate'
        ? await _runValidate(results, env, _commandUsage(command, parser))
        : await _runSign(results, env, _commandUsage(command, parser));
  } on _UsageError catch (e) {
    env.err.writeln('${e.message}\n\n${_commandUsage(command, parser)}');
    return ExitCode.usage;
  } on _InputError catch (e) {
    env.err.writeln(e.message);
    return e.code;
  }
}

final class _UsageError implements Exception {
  _UsageError(this.message);
  final String message;
}

final class _InputError implements Exception {
  _InputError(this.message, this.code);
  final String message;
  final int code;
}

String _commandUsage(String command, ArgParser p) =>
    'Usage: ades $command <file> [options]\n\n${p.usage}';

ArgParser _validateParser() => ArgParser()
  ..addFlag('help', abbr: 'h', negatable: false, help: 'Show this help.')
  ..addMultiOption(
    'trust-anchor',
    abbr: 't',
    valueHelp: 'file',
    help: 'Trust anchor certificate (PEM or DER). Repeatable.',
  )
  ..addMultiOption(
    'certificate',
    abbr: 'c',
    valueHelp: 'file',
    help:
        'Extra certificate for path building, such as a missing\n'
        'intermediate (PEM or DER). Repeatable.',
  )
  ..addOption(
    'document',
    abbr: 'd',
    valueHelp: 'file',
    help: 'Signed document, for a detached signature (.p7s).',
  )
  ..addOption(
    'validation-time',
    valueHelp: 'ISO-8601',
    help: 'Validate as of this time (default: now).',
  )
  ..addOption(
    'policy',
    valueHelp: 'file',
    help: 'Validation policy as JSON (default: the DSS default policy).',
  )
  ..addFlag(
    'ignore-revocation',
    negatable: false,
    help: 'Do not require revocation data (applied on top of --policy).',
  )
  ..addOption(
    'report-json',
    valueHelp: 'file|-',
    help: 'Write the simple and detailed reports as JSON.',
  )
  ..addOption(
    'diagnostic-json',
    valueHelp: 'file|-',
    help: 'Write the diagnostic data as JSON.',
  );

ArgParser _signParser() {
  final p = ArgParser()
    ..addFlag('help', abbr: 'h', negatable: false, help: 'Show this help.')
    ..addOption(
      'out',
      abbr: 'o',
      valueHelp: 'file',
      help: 'Output file (default: <file>.p7m, or <file>.p7s if detached).',
    )
    ..addFlag(
      'detached',
      negatable: false,
      help: 'Create a detached signature instead of an enveloping one.',
    )
    ..addFlag('force', abbr: 'f', negatable: false, help: 'Overwrite output.');
  for (final s in CredentialSource.registry) {
    s.addOptions(p);
  }
  return p;
}

Uint8List _readFile(String path, String what) {
  final f = File(path);
  try {
    return f.readAsBytesSync();
  } on FileSystemException catch (e) {
    throw _InputError(
      'Cannot read $what "$path": ${e.osError?.message ?? e.message}',
      ExitCode.noInput,
    );
  }
}

String _singleFile(ArgResults r) {
  if (r.rest.isEmpty) throw _UsageError('Missing <file> argument.');
  if (r.rest.length > 1) {
    throw _UsageError('Too many arguments: ${r.rest.skip(1).join(' ')}');
  }
  return r.rest.first;
}

/// PEM or DER certificate file -> DER bytes of every certificate in it.
List<Uint8List> _certificates(String path, String what) {
  final bytes = _readFile(path, what);
  final text = latin1.decode(bytes, allowInvalid: true);
  if (!text.contains('-----BEGIN')) return [bytes];
  final out = <Uint8List>[];
  final re = RegExp(
    r'-----BEGIN CERTIFICATE-----([^-]*)-----END CERTIFICATE-----',
  );
  for (final m in re.allMatches(text)) {
    try {
      out.add(base64.decode(m.group(1)!.replaceAll(RegExp(r'\s'), '')));
    } on FormatException {
      throw _InputError('$what "$path" is not valid PEM.', ExitCode.dataError);
    }
  }
  if (out.isEmpty) {
    throw _InputError('$what "$path" has no certificate.', ExitCode.dataError);
  }
  return out;
}

Future<int> _runValidate(ArgResults r, CliEnvironment env, String usage) async {
  final file = _singleFile(r);
  DateTime? time;
  final t = r['validation-time'] as String?;
  if (t != null) {
    time = DateTime.tryParse(t)?.toUtc();
    if (time == null) throw _UsageError('Invalid --validation-time "$t".');
  }
  final anchors = <TrustAnchor>[];
  for (final path in r['trust-anchor'] as List<String>) {
    for (final der in _certificates(path, 'trust anchor')) {
      try {
        anchors.add(TrustAnchor.fromDer(der));
      } on FormatException catch (e) {
        throw _InputError(
          'Trust anchor "$path" is not a certificate: ${e.message}',
          ExitCode.dataError,
        );
      }
    }
  }
  final pool = <Uint8List>[
    for (final path in r['certificate'] as List<String>)
      ..._certificates(path, 'certificate'),
  ];
  var policy = const ValidationPolicy();
  final policyPath = r['policy'] as String?;
  try {
    if (policyPath != null) {
      policy = ValidationPolicy.fromJsonString(
        utf8.decode(_readFile(policyPath, 'policy'), allowMalformed: true),
      );
    }
    if (r['ignore-revocation'] as bool) {
      policy = ValidationPolicy.fromJson({
        ...policy.toJson(),
        'revocationDataAvailable': ConstraintLevel.ignore.name,
      });
    }
  } on PolicyFormatException catch (e) {
    throw _InputError('Invalid policy: ${e.message}', ExitCode.dataError);
  }
  final signature = _readFile(file, 'signature');
  final docPath = r['document'] as String?;
  final document = docPath == null ? null : _readFile(docPath, 'document');

  final CoreOutcome outcome;
  try {
    outcome = await runCoreValidation(
      signature: signature,
      document: document,
      trustAnchors: anchors,
      pool: pool,
      validationTime: time,
      policy: policy,
    );
  } on FormatException catch (e) {
    throw _InputError('Invalid certificate: ${e.message}', ExitCode.dataError);
  }
  final report = outcome.report;

  final diag = r['diagnostic-json'] as String?;
  if (diag != null) {
    _writeJson(diag, outcome.diagnosticJson, env);
  }
  final rep = r['report-json'] as String?;
  if (rep != null) _writeJson(rep, report.toJson(), env);

  _printSimpleReport(report, file, env.out);
  return _exitFor(report);
}

void _writeJson(String target, Object json, CliEnvironment env) {
  final text = '${const JsonEncoder.withIndent('  ').convert(json)}\n';
  if (target == '-') {
    env.out.write(text);
  } else {
    File(target).writeAsStringSync(text);
  }
}

int _exitFor(ValidationReport report) {
  var code = ExitCode.ok;
  for (final s in report.simple.signatures) {
    switch (s.indication) {
      case Indication.totalFailed:
        return ExitCode.failed;
      case Indication.indeterminate:
        code = ExitCode.indeterminate;
      case Indication.totalPassed:
        break;
    }
  }
  return code;
}

void _printSimpleReport(ValidationReport report, String file, StringSink out) {
  out.writeln('File: $file');
  final sigs = report.simple.signatures;
  out.writeln('Signatures: ${sigs.length}');
  for (final s in sigs) {
    out.writeln('Signature #${s.index}');
    out.writeln(
      '  Indication: ${s.indication.etsi}'
      '${s.subIndication == null ? '' : ' / ${s.subIndication!.etsi}'}',
    );
    if (s.signedBy != null) out.writeln('  Signed by: ${s.signedBy}');
    if (s.signingTime != null) {
      out.writeln(
        '  Claimed signing time: ${s.signingTime!.toUtc().toIso8601String()}',
      );
    }
    for (final sc in s.scope) {
      out.writeln('  Scope: ${sc.name} (${sc.description})');
    }
  }
}

Future<int> _runSign(ArgResults r, CliEnvironment env, String usage) async {
  try {
    return await _runSignInner(r, env, usage);
  } finally {
    await env.runCleanups();
  }
}

Future<int> _runSignInner(
  ArgResults r,
  CliEnvironment env,
  String usage,
) async {
  final file = _singleFile(r);
  final selected = [
    for (final s in CredentialSource.registry)
      if (s.selected(r)) s,
  ];
  if (selected.isEmpty) {
    throw _UsageError(
      'No signing credential given. Use one of: '
      '${CredentialSource.registry.map((s) => s.name).join(', ')}.',
    );
  }
  if (selected.length > 1) {
    throw _UsageError('Choose only one signing credential.');
  }
  final detached = r['detached'] as bool;
  final out = (r['out'] as String?) ?? '$file${detached ? '.p7s' : '.p7m'}';
  if (!(r['force'] as bool) && File(out).existsSync()) {
    throw _InputError(
      'Output "$out" exists; use --force to overwrite.',
      ExitCode.dataError,
    );
  }
  final document = _readFile(file, 'document');

  final SigningCredential credential;
  try {
    credential = await selected.single.open(r, env);
  } on CredentialSourceException catch (e) {
    throw _InputError(e.message, ExitCode.dataError);
  }

  final Uint8List signature;
  try {
    signature = await signWithCore(
      document: document,
      credential: credential,
      detached: detached,
      signingTime: env.now?.call(),
    );
  } on AdesException catch (e) {
    final cause = e is SigningFailedException && e.cause != null
        ? ': ${e.cause}'
        : '';
    env.err.writeln('Signing failed: ${e.message}$cause');
    return ExitCode.dataError;
  }
  File(out).writeAsBytesSync(signature);
  env.out.writeln('Wrote $out');
  return ExitCode.ok;
}

Future<int> _runOracle(List<String> args, CliEnvironment env) async {
  try {
    return await runOracle(args, env: env);
  } on DssBackendException catch (e) {
    env.err.writeln('DSS unavailable: ${e.message}');
    return ExitCode.unavailable;
  }
}
