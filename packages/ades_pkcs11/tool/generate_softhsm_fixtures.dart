// Writes the SoftHSM-signed tier-1 fixtures: CAdES-B-B made by ades through
// ades_pkcs11 on a SoftHSM2 token holding the tier-1 rsa2048 qualified-signing
// key (what a card would do), enveloping (.p7m) and detached (.p7s). RSA
// PKCS#1 v1.5 is deterministic and the signing time is fixed, so the output is
// byte-stable. Runs inside the Linux test container (SoftHSM2 and pkcs11-tool
// installed): `packages/ades_pkcs11/tool/generate_fixtures_in_docker.sh`.
//
// Needs SOFTHSM2_CONF, ADES_PKCS11_MODULE; the repo root is the working
// directory; the output directory is the first argument.
import 'dart:io';
import 'dart:typed_data';

import 'package:ades/ades.dart';
import 'package:ades_pkcs11/ades_pkcs11.dart';

const _pin = '1234';
const _soPin = '5678';
const _label = 'ades-fixtures';

void _run(String exe, List<String> args) {
  final r = Process.runSync(exe, args);
  if (r.exitCode != 0) {
    throw StateError('$exe ${args.join(' ')} failed:\n${r.stdout}${r.stderr}');
  }
}

/// A card holds the leaf only; the fixtures embed the intermediate like the
/// other `ours` fixtures do, so the credential is wrapped to add it.
final class _WithChain extends SigningCredential {
  _WithChain(this._inner, this._chain);

  final SigningCredential _inner;
  final Uint8List _chain;

  @override
  Future<Uint8List> get certificate => _inner.certificate;

  @override
  Future<List<Uint8List>> get chain async => [_chain];

  @override
  List<SignatureAlgorithm> get supportedAlgorithms =>
      _inner.supportedAlgorithms;

  @override
  Future<SignatureValue> sign(SignRequest request) => _inner.sign(request);
}

Future<void> main(List<String> args) async {
  final out = Directory(args.single)..createSync(recursive: true);
  final module = Platform.environment['ADES_PKCS11_MODULE']!;
  final pki = 'fixtures/tier1/pki/rsa2048';
  final doc = File('fixtures/tier1/content/hello.txt').readAsBytesSync();

  _run('softhsm2-util', [
    '--init-token', '--free', '--label', _label,
    '--so-pin', _soPin, '--pin', _pin, //
  ]);
  _run('softhsm2-util', [
    '--import', '$pki/leaf-qsign.key', '--token', _label,
    '--label', 'qsign', '--id', '0a', '--pin', _pin, //
  ]);
  _run('pkcs11-tool', [
    '--module', module, '--token-label', _label, '--login', '--pin', _pin,
    '--write-object', '$pki/leaf-qsign.der', '--type', 'cert',
    '--label', 'qsign', '--id', '0a', //
  ]);

  await Pkcs11Module.use(module, (_) async => _pin, (m) async {
    final card = (await m.listCredentials()).singleWhere(
      (c) => c.tokenLabel == _label,
    );
    final credential = _WithChain(
      card,
      File('$pki/intermediate.der').readAsBytesSync(),
    );
    for (final detached in [false, true]) {
      final signature = await Cades.sign(
        document: doc,
        credential: credential,
        algorithm: SignatureAlgorithm.rsaPkcs1v15Sha256,
        detached: detached,
        signingTime: DateTime.utc(2026, 6, 1, 12),
      );
      final path =
          '${out.path}/softhsm-rsa2048-qsign.${detached ? 'p7s' : 'p7m'}';
      File(path).writeAsBytesSync(signature);
      stdout.writeln('wrote $path');
    }
  });
}
