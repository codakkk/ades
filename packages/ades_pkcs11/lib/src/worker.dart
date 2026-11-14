// Worker isolate: owns the library handle and every session, and is the only
// place a blocking PKCS#11 call happens.
//
// Protocol (plain lists, so it crosses the isolate boundary):
//   main -> worker  ['call', id, op, args]   |  ['pin', pinId, pin?, error?]
//   worker -> main  ['ready', SendPort] | ['initError', wireException]
//                   ['ok', id, result] | ['err', id, wireException]
//                   ['needPin', pinId, slotId, tokenLabel, credentialLabel,
//                    forSignature]
import 'dart:async';
import 'dart:convert';
import 'dart:io' show sleep;
import 'dart:isolate';
import 'dart:typed_data';

import 'exceptions.dart';
import 'native.dart';

/// Arguments of [workerMain].
final class WorkerInit {
  WorkerInit(this.toMain, this.path, this.blockingDelayMicros);
  final SendPort toMain;
  final String path;
  final int blockingDelayMicros;
}

void workerMain(WorkerInit init) {
  final inbox = ReceivePort();
  final NativeModule native;
  try {
    native = NativeModule.load(init.path);
  } on Pkcs11Exception catch (e) {
    init.toMain.send(['initError', e.toWire()]);
    return;
  }
  final worker = _Worker(native, init.toMain, init.blockingDelayMicros);
  init.toMain.send(['ready', inbox.sendPort]);
  inbox.listen((Object? m) {
    final msg = m! as List<Object?>;
    switch (msg[0]) {
      case 'call':
        worker.enqueue(msg[1]! as int, msg[2]! as String, msg[3]);
      case 'pin':
        worker.pinReply(msg[1]! as int, msg[2] as String?, msg[3] as String?);
    }
  });
}

final class _Worker {
  _Worker(this._native, this._toMain, this._delayMicros);

  final NativeModule _native;
  final SendPort _toMain;
  final int _delayMicros;

  /// Slot -> open session handle; slots we logged into.
  final _sessions = <int, int>{};
  final _loggedIn = <int>{};
  final _pinWaits = <int, Completer<String?>>{};
  var _pinSeq = 0;
  var _closed = false;

  // Calls run one at a time; PIN replies bypass the queue.
  Future<void> _tail = Future.value();

  void enqueue(int id, String op, Object? args) {
    _tail = _tail.then((_) async {
      try {
        final result = await _run(op, args);
        _toMain.send(['ok', id, result]);
      } on Pkcs11Exception catch (e) {
        _toMain.send(['err', id, e.toWire()]);
      } catch (e) {
        _toMain.send([
          'err',
          id,
          Pkcs11CallException('worker failure: $e', op, -1).toWire(),
        ]);
      }
    });
  }

  void pinReply(int pinId, String? pin, String? error) {
    final c = _pinWaits.remove(pinId);
    if (c == null) return;
    if (error != null) {
      c.completeError(Pkcs11PinCallbackException(error));
    } else {
      c.complete(pin);
    }
  }

  Future<Object?> _run(String op, Object? args) async {
    if (_closed) throw const Pkcs11ClosedException('module is closed');
    switch (op) {
      case 'list':
        return _list();
      case 'sign':
        return _sign(args! as Map<Object?, Object?>);
      case 'close':
        _shutdown();
        return null;
    }
    throw ArgumentError('unknown op $op');
  }

  void _blockFor() {
    // Test hook: stands in for a slow card/HSM. A real blocking call.
    if (_delayMicros > 0) sleep(Duration(microseconds: _delayMicros));
  }

  int _session(int slot) => _sessions[slot] ??= _native.openSession(slot);

  List<Object?> _list() {
    final out = <Object?>[];
    for (final slot in _native.slotIds()) {
      final TokenInfo info;
      try {
        info = _native.tokenInfo(slot);
      } on Pkcs11Exception {
        continue; // token vanished or unreadable
      }
      if (!info.initialized) continue;
      final s = _session(slot);
      final certs = _native.find(s, {
        ckaClass: ulongBytes(ckoCertificate),
        ckaCertificateType: ulongBytes(ckcX509),
      });
      for (final c in certs) {
        final a = _native.attributes(s, c, [ckaLabel, ckaId, ckaValue]);
        final der = a[ckaValue];
        if (der == null || der.isEmpty) continue;
        out.add({
          'slotId': slot,
          'tokenLabel': info.label,
          'label': utf8.decode(
            a[ckaLabel] ?? Uint8List(0),
            allowMalformed: true,
          ),
          'id': a[ckaId] ?? Uint8List(0),
          'certificate': der,
        });
      }
    }
    return out;
  }

  Future<void> _ensureLoggedIn(
    int slot,
    int session,
    String credentialLabel,
  ) async {
    if (_loggedIn.contains(slot)) return;
    final info = _native.tokenInfo(slot);
    if (info.loginRequired) {
      if (info.protectedAuthPath) {
        _blockFor();
        _native.login(session, null);
      } else {
        final pin = await _askPin(slot, info.label, credentialLabel, false);
        _blockFor();
        _native.login(session, utf8.encode(pin));
      }
    }
    _loggedIn.add(slot);
  }

  /// Asks the caller for a PIN. [forSignature]: it is the per-signature PIN
  /// of a CKA_ALWAYS_AUTHENTICATE key, not the login PIN.
  Future<String> _askPin(
    int slot,
    String tokenLabel,
    String credentialLabel,
    bool forSignature,
  ) async {
    final pinId = _pinSeq++;
    final wait = Completer<String?>();
    _pinWaits[pinId] = wait;
    _toMain.send([
      'needPin',
      pinId,
      slot,
      tokenLabel,
      credentialLabel,
      forSignature,
    ]);
    final pin = await wait.future;
    if (pin == null) {
      throw const Pkcs11PinCancelledException('PIN entry cancelled');
    }
    return pin;
  }

  Future<Uint8List> _sign(Map<Object?, Object?> a) async {
    final slot = a['slotId']! as int;
    final id = a['id']! as Uint8List;
    final label = a['label']! as String;
    final session = _session(slot);
    await _ensureLoggedIn(slot, session, label);
    final keys = _native.find(session, {
      ckaClass: ulongBytes(ckoPrivateKey),
      if (id.isNotEmpty) ckaId: id else ckaLabel: utf8.encode(label),
    });
    if (keys.isEmpty) {
      throw Pkcs11KeyNotFoundException(
        'no private key for credential "$label" on slot $slot',
      );
    }
    final key = keys.first;
    final always = _native.attributes(session, key, [
      ckaAlwaysAuthenticate,
    ])[ckaAlwaysAuthenticate];
    final needsContextLogin = always != null && always.any((b) => b != 0);
    // Ask before C_SignInit: a cancelled prompt must not leave a signing
    // operation active on the session.
    String? signPin;
    final info = _native.tokenInfo(slot);
    if (needsContextLogin && !info.protectedAuthPath) {
      signPin = await _askPin(slot, info.label, label, true);
    }
    _native.signInitRsaPkcs(session, key);
    if (needsContextLogin) {
      try {
        _blockFor();
        _native.login(
          session,
          signPin == null ? null : utf8.encode(signPin),
          userType: ckuContextSpecific,
        );
      } on Object {
        // The initialised signing operation cannot be cancelled in PKCS#11;
        // dropping the session ends it (and the login, which is redone).
        _native.closeSession(session);
        _sessions.remove(slot);
        _loggedIn.remove(slot);
        rethrow;
      }
    }
    _blockFor();
    return _native.signRsaPkcs(session, a['data']! as Uint8List);
  }

  /// Deterministic release: logout, close sessions, finalise.
  void _shutdown() {
    _closed = true;
    for (final c in _pinWaits.values) {
      if (!c.isCompleted) {
        c.completeError(const Pkcs11ClosedException('module closed'));
      }
    }
    _pinWaits.clear();
    try {
      for (final e in _sessions.entries) {
        if (_loggedIn.contains(e.key)) _native.logout(e.value);
        _native.closeSession(e.value);
      }
    } finally {
      _sessions.clear();
      _loggedIn.clear();
      _native.finalizeModule();
    }
  }
}
