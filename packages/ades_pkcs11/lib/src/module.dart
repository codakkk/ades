import 'dart:async';
import 'dart:isolate';
import 'dart:typed_data';

import 'package:ades/ades.dart';

import 'exceptions.dart';
import 'worker.dart';

/// What the PIN callback is asked for.
final class PinRequest {
  const PinRequest({
    required this.slotId,
    required this.tokenLabel,
    required this.credentialLabel,
    this.forSignature = false,
  });

  final int slotId;
  final String tokenLabel;

  /// Label of the credential being used.
  final String credentialLabel;

  /// True when this is the per-signature PIN that a key with
  /// CKA_ALWAYS_AUTHENTICATE demands right before every signature (PKCS#11
  /// context-specific login, as on qualified signature keys of Italian CNS
  /// cards), false for the login PIN. Both are the same user PIN.
  final bool forSignature;
}

/// Supplies the user PIN. Runs on the caller's isolate (so it can show a
/// Flutter dialog); the PIN is then used on the worker isolate. Return null
/// when the user cancels.
typedef PinCallback = Future<String?> Function(PinRequest request);

/// X.509 keyUsage bits of a credential's certificate.
enum Pkcs11KeyUsage {
  digitalSignature,
  nonRepudiation,
  keyEncipherment,
  dataEncipherment,
  keyAgreement,
  keyCertSign,
  cRlSign,
  encipherOnly,
  decipherOnly,
}

/// A PKCS#11 module loaded by path. All blocking calls run on one worker
/// isolate owned by this object; call [close] (or use [use]) to release the
/// worker, sessions and library handle.
final class Pkcs11Module {
  Pkcs11Module._(this._isolate, this._toWorker, this._fromWorker, this._pin);

  final Isolate _isolate;
  final SendPort _toWorker;
  final ReceivePort _fromWorker;
  final PinCallback _pin;
  final _pending = <int, Completer<Object?>>{};
  var _seq = 0;
  var _closed = false;
  Future<void>? _closing;
  late final ReceivePort _exitPort;

  /// Loads the module at [path] (absolute, or a name the OS loader finds).
  ///
  /// [onPin] is called, on the calling isolate, whenever a login is needed.
  /// [debugBlockingDelay] makes the worker block that long inside each login
  /// and sign (a stand-in for a slow card), for tests of the isolate model.
  static Future<Pkcs11Module> load(
    String path, {
    required PinCallback onPin,
    Duration debugBlockingDelay = Duration.zero,
  }) async {
    final fromWorker = ReceivePort();
    final ready = Completer<SendPort>();
    final exitPort = ReceivePort();
    Isolate isolate;
    try {
      isolate = await Isolate.spawn(
        workerMain,
        WorkerInit(
          fromWorker.sendPort,
          path,
          debugBlockingDelay.inMicroseconds,
        ),
        onExit: exitPort.sendPort,
        onError: exitPort.sendPort,
      );
    } catch (e) {
      fromWorker.close();
      exitPort.close();
      throw Pkcs11ModuleLoadException('cannot start worker isolate: $e');
    }
    late Pkcs11Module module;
    var initialised = false;
    fromWorker.listen((Object? m) {
      final msg = m! as List<Object?>;
      if (!initialised) {
        if (msg[0] == 'ready') {
          ready.complete(msg[1]! as SendPort);
        } else {
          ready.completeError(
            Pkcs11Exception.fromWire(msg[1]! as List<Object?>),
          );
        }
        return;
      }
      module._onMessage(msg);
    });
    exitPort.listen((Object? _) {
      // Worker exited (cleanly after close, or crashed).
      if (!ready.isCompleted) {
        ready.completeError(
          const Pkcs11ModuleLoadException('worker isolate exited early'),
        );
      } else {
        module._workerGone();
      }
    });
    final SendPort toWorker;
    try {
      toWorker = await ready.future;
    } catch (_) {
      fromWorker.close();
      exitPort.close();
      isolate.kill(priority: Isolate.immediate);
      rethrow;
    }
    module = Pkcs11Module._(isolate, toWorker, fromWorker, onPin)
      .._exitPort = exitPort;
    initialised = true;
    return module;
  }

  /// Loads, runs [body], and always closes.
  static Future<T> use<T>(
    String path,
    PinCallback onPin,
    Future<T> Function(Pkcs11Module module) body,
  ) async {
    final m = await load(path, onPin: onPin);
    try {
      return await body(m);
    } finally {
      await m.close();
    }
  }

  void _onMessage(List<Object?> msg) {
    switch (msg[0]) {
      case 'ok':
        _pending.remove(msg[1])?.complete(msg[2]);
      case 'err':
        _pending
            .remove(msg[1])
            ?.completeError(Pkcs11Exception.fromWire(msg[2]! as List<Object?>));
      case 'needPin':
        unawaited(_askPin(msg));
    }
  }

  Future<void> _askPin(List<Object?> msg) async {
    final pinId = msg[1]! as int;
    String? pin;
    String? error;
    try {
      pin = await _pin(
        PinRequest(
          slotId: msg[2]! as int,
          tokenLabel: msg[3]! as String,
          credentialLabel: msg[4]! as String,
          forSignature: msg[5]! as bool,
        ),
      );
    } catch (e) {
      error = '$e';
    }
    if (!_closed) _toWorker.send(['pin', pinId, pin, error]);
  }

  void _workerGone() {
    _closed = true;
    for (final c in _pending.values) {
      if (!c.isCompleted) {
        c.completeError(const Pkcs11ClosedException('worker isolate exited'));
      }
    }
    _pending.clear();
  }

  Future<T> _call<T>(String op, [Object? args]) {
    if (_closed) {
      return Future.error(const Pkcs11ClosedException('module is closed'));
    }
    final id = _seq++;
    final c = Completer<Object?>();
    _pending[id] = c;
    _toWorker.send(['call', id, op, args]);
    return c.future.then((v) => v as T);
  }

  /// Lists the credentials (certificates with a label) on every initialised
  /// token present. The private key is looked up at sign time (many tokens
  /// show it only after login).
  Future<List<Pkcs11Credential>> listCredentials() async {
    final raw = await _call<List<Object?>>('list');
    return [
      for (final r in raw.cast<Map<Object?, Object?>>())
        Pkcs11Credential._(
          this,
          slotId: r['slotId']! as int,
          tokenLabel: r['tokenLabel']! as String,
          label: r['label']! as String,
          keyId: r['id']! as Uint8List,
          certificateDer: r['certificate']! as Uint8List,
        ),
    ];
  }

  /// Releases the worker isolate, sessions (logging out) and the library.
  /// Idempotent. Pending calls fail with [Pkcs11ClosedException].
  Future<void> close() => _closing ??= _doClose();

  Future<void> _doClose() async {
    if (_closed) {
      // Worker already gone; just release ports.
      _fromWorker.close();
      _exitPort.close();
      return;
    }
    try {
      await _call<Object?>('close');
    } on Pkcs11Exception {
      // fall through to forced release
    } finally {
      _closed = true;
      for (final c in _pending.values) {
        if (!c.isCompleted) {
          c.completeError(const Pkcs11ClosedException('module closed'));
        }
      }
      _pending.clear();
      _isolate.kill(priority: Isolate.immediate);
      _fromWorker.close();
      _exitPort.close();
    }
  }
}

/// A certificate on a token plus the (inaccessible) private key behind it.
final class Pkcs11Credential extends SigningCredential {
  Pkcs11Credential._(
    this._module, {
    required this.slotId,
    required this.tokenLabel,
    required this.label,
    required this.keyId,
    required Uint8List certificateDer,
  }) : _certificate = certificateDer;

  final Pkcs11Module _module;
  final Uint8List _certificate;

  final int slotId;
  final String tokenLabel;

  /// CKA_LABEL of the certificate.
  final String label;

  /// CKA_ID shared by the certificate and its private key.
  final Uint8List keyId;

  /// keyUsage bits of the certificate, null when the extension is absent or
  /// the certificate does not parse.
  late final Set<Pkcs11KeyUsage>? keyUsage = _usage(_certificate);

  static Set<Pkcs11KeyUsage>? _usage(Uint8List der) {
    try {
      final ku = X509Certificate.parse(der).keyUsage;
      if (ku == null) return null;
      return {for (final f in ku) Pkcs11KeyUsage.values.byName(f.name)};
    } catch (_) {
      return null;
    }
  }

  @override
  Future<Uint8List> get certificate async => Uint8List.fromList(_certificate);

  /// SHA-256 only: new signatures use no other digest.
  @override
  List<SignatureAlgorithm> get supportedAlgorithms => const [
    SignatureAlgorithm.rsaPkcs1v15Sha256,
  ];

  @override
  Future<SignatureValue> sign(SignRequest request) async {
    if (!supportedAlgorithms.contains(request.signatureAlgorithm)) {
      throw UnsupportedCredentialAlgorithmException(
        'ades_pkcs11 cannot sign ${request.signatureAlgorithm}',
      );
    }
    final sig = await _module._call<Uint8List>('sign', {
      'slotId': slotId,
      'id': keyId,
      'label': label,
      'data': request.dtbsrDigestInfo,
    });
    return SignatureValue.raw(sig);
  }

  @override
  String toString() => 'Pkcs11Credential($tokenLabel / $label)';
}
