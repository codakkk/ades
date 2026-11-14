import 'package:ades/ades.dart';
import 'package:ades_pkcs11/ades_pkcs11.dart';

/// What a credential is for, judged from its certificate's key usage.
enum CredentialKind { qualifiedSignature, authentication, other }

/// A credential as the UI shows it.
final class CredentialChoice {
  const CredentialChoice({
    required this.id,
    required this.label,
    required this.tokenLabel,
    required this.kind,
    required this.credential,
  });

  final String id;
  final String label;
  final String tokenLabel;
  final CredentialKind kind;
  final SigningCredential credential;
}

/// An open connection to the middleware. Close it when done.
abstract interface class CardSession {
  List<CredentialChoice> get credentials;

  /// What discovery tried, for display (found / failed with reason).
  String get discoverySummary;

  Future<void> close();
}

/// Finds the middleware and opens it. [onPin] is called (on the UI isolate)
/// when a signature needs the PIN; return null to cancel.
abstract interface class CardSource {
  Future<CardSession> open({required PinCallback onPin});
}

/// Thrown when no usable middleware is installed.
final class NoMiddlewareException implements Exception {
  const NoMiddlewareException(this.summary);
  final String summary;
  @override
  String toString() => 'No PKCS#11 middleware found.\n$summary';
}

String describeDiscovery(DiscoveryReport r) {
  final b = StringBuffer();
  for (final f in r.found) {
    b.writeln('found: ${f.candidate.name} at ${f.path}');
  }
  for (final f in r.failed) {
    b.writeln(
      'failed to load: ${f.candidate.name} at ${f.candidate.path}: '
      '${f.reason}',
    );
  }
  b.write('${r.absent.length} known locations not present');
  return b.toString();
}

/// Real source: [discoverPkcs11Modules] then every module that loads.
final class Pkcs11CardSource implements CardSource {
  const Pkcs11CardSource({this.extraCandidates = const []});

  /// User-supplied library locations, tried before the built-in list.
  final List<MiddlewareCandidate> extraCandidates;

  @override
  Future<CardSession> open({required PinCallback onPin}) async {
    final report = await discoverPkcs11Modules(candidates: extraCandidates);
    final summary = describeDiscovery(report);
    final modules = <Pkcs11Module>[];
    final choices = <CredentialChoice>[];
    try {
      for (final found in report.found) {
        final module = await Pkcs11Module.load(found.path, onPin: onPin);
        modules.add(module);
        for (final c in await module.listCredentials()) {
          choices.add(
            CredentialChoice(
              id: '${found.path}#${c.slotId}#${c.label}',
              label: c.label,
              tokenLabel: c.tokenLabel,
              kind: _kind(c.keyUsage),
              credential: c,
            ),
          );
        }
      }
    } on Object {
      for (final m in modules) {
        await m.close();
      }
      rethrow;
    }
    if (report.found.isEmpty) {
      throw NoMiddlewareException(summary);
    }
    return _Session(modules, choices, summary);
  }

  static CredentialKind _kind(Set<Pkcs11KeyUsage>? usage) {
    if (usage == null) return CredentialKind.other;
    if (usage.contains(Pkcs11KeyUsage.nonRepudiation)) {
      return CredentialKind.qualifiedSignature;
    }
    if (usage.contains(Pkcs11KeyUsage.digitalSignature)) {
      return CredentialKind.authentication;
    }
    return CredentialKind.other;
  }
}

final class _Session implements CardSession {
  _Session(this._modules, this.credentials, this.discoverySummary);
  final List<Pkcs11Module> _modules;

  @override
  final List<CredentialChoice> credentials;
  @override
  final String discoverySummary;

  @override
  Future<void> close() async {
    for (final m in _modules) {
      await m.close();
    }
  }
}
