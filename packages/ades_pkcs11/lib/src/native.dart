// Minimal PKCS#11 (v2.40) binding over dart:ffi. Used ONLY inside the worker
// isolate: every call here may block.
//
// CK_ULONG is `unsigned long` (4 bytes on Windows, 8 on LP64) and the
// Windows headers pack structures to 1 byte; structures are therefore laid
// out by hand instead of with `Struct`.
import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'exceptions.dart';

// Return values.
const ckrOk = 0x00;
const ckrAttributeSensitive = 0x11;
const ckrAttributeTypeInvalid = 0x12;
const ckrPinIncorrect = 0xA0;
const ckrPinLocked = 0xA4;
const ckrUserAlreadyLoggedIn = 0x100;
const ckrCryptokiAlreadyInitialized = 0x191;

// Attributes / classes.
const ckaClass = 0x00;
const ckaLabel = 0x03;
const ckaValue = 0x11;
const ckaCertificateType = 0x80;
const ckaId = 0x102;
const ckaAlwaysAuthenticate = 0x202;
const ckoCertificate = 1;
const ckoPrivateKey = 3;
const ckcX509 = 0;
const ckmRsaPkcs = 1;

// Flags.
const ckfSerialSession = 0x4;
const ckfLoginRequired = 0x4;
const ckfProtectedAuthenticationPath = 0x100;
const ckfTokenInitialized = 0x400;
const ckuUser = 1;
const ckuContextSpecific = 2;

final _ulSize = sizeOf<UnsignedLong>();
final _packed = Platform.isWindows;
const _ptrSize = 8;

int _roundUp(int v, int a) => (v + a - 1) ~/ a * a;

// Layout shared by CK_ATTRIBUTE and CK_MECHANISM: {ulong, pointer, ulong}.
final _ptrOff = _packed ? _ulSize : _roundUp(_ulSize, _ptrSize);
final _lenOff = _ptrOff + _ptrSize;
final _structSize = _packed
    ? _lenOff + _ulSize
    : _roundUp(_lenOff + _ulSize, 8);

int _getUl(ByteData d, int off) => _ulSize == 8
    ? d.getUint64(off, Endian.host)
    : d.getUint32(off, Endian.host);

void _setUl(ByteData d, int off, int v) {
  if (_ulSize == 8) {
    d.setUint64(off, v, Endian.host);
  } else {
    d.setUint32(off, v, Endian.host);
  }
}

ByteData _view(Pointer<Uint8> p, int len) =>
    ByteData.sublistView(p.asTypedList(len));

// Function table indices (CK_FUNCTION_LIST order).
const _iInitialize = 0;
const _iFinalize = 1;
const _iGetSlotList = 4;
const _iGetTokenInfo = 6;
const _iOpenSession = 12;
const _iCloseSession = 13;
const _iLogin = 18;
const _iLogout = 19;
const _iGetAttributeValue = 24;
const _iFindObjectsInit = 26;
const _iFindObjects = 27;
const _iFindObjectsFinal = 28;
const _iSignInit = 42;
const _iSign = 43;

typedef _GetFunctionListN = UnsignedLong Function(Pointer<Pointer<Uint8>>);
typedef _GetFunctionListD = int Function(Pointer<Pointer<Uint8>>);
typedef _InitN = UnsignedLong Function(Pointer<Void>);
typedef _InitD = int Function(Pointer<Void>);
typedef _FinN = UnsignedLong Function(Pointer<Void>);
typedef _FinD = int Function(Pointer<Void>);
typedef _SlotListN =
    UnsignedLong Function(Uint8, Pointer<Uint8>, Pointer<Uint8>);
typedef _SlotListD = int Function(int, Pointer<Uint8>, Pointer<Uint8>);
typedef _TokenInfoN = UnsignedLong Function(UnsignedLong, Pointer<Uint8>);
typedef _TokenInfoD = int Function(int, Pointer<Uint8>);
typedef _OpenN =
    UnsignedLong Function(
      UnsignedLong,
      UnsignedLong,
      Pointer<Void>,
      Pointer<Void>,
      Pointer<Uint8>,
    );
typedef _OpenD =
    int Function(int, int, Pointer<Void>, Pointer<Void>, Pointer<Uint8>);
typedef _SessN = UnsignedLong Function(UnsignedLong);
typedef _SessD = int Function(int);
typedef _LoginN =
    UnsignedLong Function(
      UnsignedLong,
      UnsignedLong,
      Pointer<Uint8>,
      UnsignedLong,
    );
typedef _LoginD = int Function(int, int, Pointer<Uint8>, int);
typedef _GetAttrN =
    UnsignedLong Function(
      UnsignedLong,
      UnsignedLong,
      Pointer<Uint8>,
      UnsignedLong,
    );
typedef _GetAttrD = int Function(int, int, Pointer<Uint8>, int);
typedef _FindInitN =
    UnsignedLong Function(UnsignedLong, Pointer<Uint8>, UnsignedLong);
typedef _FindInitD = int Function(int, Pointer<Uint8>, int);
typedef _FindN =
    UnsignedLong Function(
      UnsignedLong,
      Pointer<Uint8>,
      UnsignedLong,
      Pointer<Uint8>,
    );
typedef _FindD = int Function(int, Pointer<Uint8>, int, Pointer<Uint8>);
typedef _SignInitN =
    UnsignedLong Function(UnsignedLong, Pointer<Uint8>, UnsignedLong);
typedef _SignInitD = int Function(int, Pointer<Uint8>, int);
typedef _SignN =
    UnsignedLong Function(
      UnsignedLong,
      Pointer<Uint8>,
      UnsignedLong,
      Pointer<Uint8>,
      Pointer<Uint8>,
    );
typedef _SignD =
    int Function(int, Pointer<Uint8>, int, Pointer<Uint8>, Pointer<Uint8>);

/// Information about one token.
final class TokenInfo {
  TokenInfo(this.label, this.flags);
  final String label;
  final int flags;
  bool get initialized => flags & ckfTokenInitialized != 0;
  bool get loginRequired => flags & ckfLoginRequired != 0;
  bool get protectedAuthPath => flags & ckfProtectedAuthenticationPath != 0;
}

/// A loaded, initialised PKCS#11 module.
final class NativeModule {
  NativeModule._(this._lib, this._table, this._fnOff, this._weInitialised);

  // Keeps the library mapped for as long as function pointers are in use.
  // ignore: unused_field
  final DynamicLibrary _lib;
  final ByteData _table;
  final int _fnOff;
  final bool _weInitialised;

  late final _InitD _finalize = _fn<_FinN>(_iFinalize).asFunction<_FinD>();
  late final _SlotListD _slotList = _fn<_SlotListN>(
    _iGetSlotList,
  ).asFunction<_SlotListD>();
  late final _TokenInfoD _tokenInfo = _fn<_TokenInfoN>(
    _iGetTokenInfo,
  ).asFunction<_TokenInfoD>();
  late final _OpenD _open = _fn<_OpenN>(_iOpenSession).asFunction<_OpenD>();
  late final _SessD _close = _fn<_SessN>(_iCloseSession).asFunction<_SessD>();
  late final _LoginD _login = _fn<_LoginN>(_iLogin).asFunction<_LoginD>();
  late final _SessD _logout = _fn<_SessN>(_iLogout).asFunction<_SessD>();
  late final _GetAttrD _getAttr = _fn<_GetAttrN>(
    _iGetAttributeValue,
  ).asFunction<_GetAttrD>();
  late final _FindInitD _findInit = _fn<_FindInitN>(
    _iFindObjectsInit,
  ).asFunction<_FindInitD>();
  late final _FindD _find = _fn<_FindN>(_iFindObjects).asFunction<_FindD>();
  late final _SessD _findFinal = _fn<_SessN>(
    _iFindObjectsFinal,
  ).asFunction<_SessD>();
  late final _SignInitD _signInit = _fn<_SignInitN>(
    _iSignInit,
  ).asFunction<_SignInitD>();
  late final _SignD _sign = _fn<_SignN>(_iSign).asFunction<_SignD>();

  Pointer<NativeFunction<T>> _fn<T extends Function>(int i) =>
      Pointer<NativeFunction<T>>.fromAddress(
        _table.getUint64(_fnOff + i * _ptrSize, Endian.host),
      );

  /// Loads [path] and calls `C_Initialize`.
  static NativeModule load(String path) {
    final DynamicLibrary lib;
    try {
      lib = DynamicLibrary.open(path);
    } on ArgumentError catch (e) {
      throw Pkcs11ModuleLoadException('cannot load $path: ${e.message}');
    } catch (e) {
      throw Pkcs11ModuleLoadException('cannot load $path: $e');
    }
    final Pointer<NativeFunction<_GetFunctionListN>> getList;
    try {
      getList = lib.lookup<NativeFunction<_GetFunctionListN>>(
        'C_GetFunctionList',
      );
    } catch (e) {
      throw Pkcs11ModuleLoadException(
        '$path is not a PKCS#11 module (no C_GetFunctionList)',
      );
    }
    return using((arena) {
      final out = arena<Pointer<Uint8>>();
      final rv = getList.asFunction<_GetFunctionListD>()(out);
      if (rv != ckrOk || out.value.address == 0) {
        throw Pkcs11ModuleLoadException(
          'C_GetFunctionList failed (0x${rv.toRadixString(16)})',
        );
      }
      // version (2 bytes), then the pointers.
      final fnOff = _packed ? 2 : _ptrSize;
      final table = _view(out.value, fnOff + 70 * _ptrSize);
      final init = Pointer<NativeFunction<_InitN>>.fromAddress(
        table.getUint64(fnOff + _iInitialize * _ptrSize, Endian.host),
      ).asFunction<_InitD>();
      final irv = init(nullptr);
      if (irv != ckrOk && irv != ckrCryptokiAlreadyInitialized) {
        throw Pkcs11ModuleLoadException(
          'C_Initialize failed (0x${irv.toRadixString(16)})',
        );
      }
      return NativeModule._(lib, table, fnOff, irv == ckrOk);
    });
  }

  /// `C_Finalize`, only if this binding initialised the module.
  void finalizeModule() {
    if (_weInitialised) _finalize(nullptr);
  }

  Never _fail(String function, int rv) {
    switch (rv) {
      case ckrPinIncorrect:
        throw const Pkcs11WrongPinException('incorrect PIN');
      case ckrPinLocked:
        throw const Pkcs11PinLockedException('PIN is locked');
    }
    throw Pkcs11CallException(
      '$function failed (CKR 0x${rv.toRadixString(16)})',
      function,
      rv,
    );
  }

  void _check(String function, int rv) {
    if (rv != ckrOk) _fail(function, rv);
  }

  List<int> slotIds() => using((arena) {
    final count = arena<Uint8>(_ulSize);
    _check('C_GetSlotList', _slotList(1, nullptr, count));
    final n = _getUl(_view(count, _ulSize), 0);
    if (n == 0) return <int>[];
    final buf = arena<Uint8>(n * _ulSize);
    _setUl(_view(count, _ulSize), 0, n);
    _check('C_GetSlotList', _slotList(1, buf, count));
    final m = _getUl(_view(count, _ulSize), 0);
    final d = _view(buf, n * _ulSize);
    return [for (var i = 0; i < m; i++) _getUl(d, i * _ulSize)];
  });

  TokenInfo tokenInfo(int slot) => using((arena) {
    final p = arena<Uint8>(512);
    p.asTypedList(512).fillRange(0, 512, 0);
    _check('C_GetTokenInfo', _tokenInfo(slot, p));
    final label = String.fromCharCodes(p.asTypedList(32)).trim();
    // label 32, manufacturer 32, model 16, serial 16, then flags.
    final flags = _getUl(_view(p, 512), 96);
    return TokenInfo(label, flags);
  });

  int openSession(int slot) => using((arena) {
    final h = arena<Uint8>(_ulSize);
    _check('C_OpenSession', _open(slot, ckfSerialSession, nullptr, nullptr, h));
    return _getUl(_view(h, _ulSize), 0);
  });

  void closeSession(int session) => _close(session);

  /// Logs in as the normal user. A null [pin] uses the protected
  /// authentication path (pin pad). Blocks.
  /// `C_Login`. [userType] is [ckuUser], or [ckuContextSpecific] to
  /// re-authenticate right before a signature with a CKA_ALWAYS_AUTHENTICATE
  /// key.
  void login(int session, List<int>? pin, {int userType = ckuUser}) =>
      using((arena) {
        final Pointer<Uint8> buf;
        if (pin == null) {
          buf = nullptr;
        } else {
          buf = arena<Uint8>(pin.isEmpty ? 1 : pin.length);
          buf.asTypedList(pin.length).setAll(0, pin);
        }
        final rv = _login(session, userType, buf, pin?.length ?? 0);
        if (rv == ckrUserAlreadyLoggedIn) return;
        _check('C_Login', rv);
      });

  void logout(int session) => _logout(session);

  /// Handles of objects matching [template] (attribute type -> value).
  List<int> find(int session, Map<int, Uint8List> template) => using((arena) {
    final t = _template(arena, template);
    _check('C_FindObjectsInit', _findInit(session, t, template.length));
    try {
      final result = <int>[];
      const batch = 16;
      final objs = arena<Uint8>(batch * _ulSize);
      final cnt = arena<Uint8>(_ulSize);
      while (true) {
        _check('C_FindObjects', _find(session, objs, batch, cnt));
        final n = _getUl(_view(cnt, _ulSize), 0);
        final d = _view(objs, batch * _ulSize);
        for (var i = 0; i < n; i++) {
          result.add(_getUl(d, i * _ulSize));
        }
        if (n < batch) break;
      }
      return result;
    } finally {
      _findFinal(session);
    }
  });

  /// Reads attributes; unavailable ones are absent from the result.
  Map<int, Uint8List> attributes(int session, int object, List<int> types) =>
      using((arena) {
        final t = arena<Uint8>(types.length * _structSize);
        t
            .asTypedList(types.length * _structSize)
            .fillRange(0, types.length * _structSize, 0);
        final d = _view(t, types.length * _structSize);
        for (var i = 0; i < types.length; i++) {
          _setUl(d, i * _structSize, types[i]);
        }
        final rv = _getAttr(session, object, t, types.length);
        if (rv != ckrOk &&
            rv != ckrAttributeSensitive &&
            rv != ckrAttributeTypeInvalid) {
          _fail('C_GetAttributeValue', rv);
        }
        final lens = [
          for (var i = 0; i < types.length; i++)
            _getUl(d, i * _structSize + _lenOff),
        ];
        final unavailable = _ulSize == 8 ? -1 : 0xFFFFFFFF;
        for (var i = 0; i < types.length; i++) {
          final len = lens[i] == unavailable || lens[i] > 1 << 24 ? 0 : lens[i];
          final buf = arena<Uint8>(len == 0 ? 1 : len);
          d.setUint64(i * _structSize + _ptrOff, buf.address, Endian.host);
          _setUl(d, i * _structSize + _lenOff, len);
        }
        final rv2 = _getAttr(session, object, t, types.length);
        if (rv2 != ckrOk &&
            rv2 != ckrAttributeSensitive &&
            rv2 != ckrAttributeTypeInvalid) {
          _fail('C_GetAttributeValue', rv2);
        }
        final out = <int, Uint8List>{};
        for (var i = 0; i < types.length; i++) {
          final len = _getUl(d, i * _structSize + _lenOff);
          if (len == unavailable || len > 1 << 24) continue;
          final addr = d.getUint64(i * _structSize + _ptrOff, Endian.host);
          out[types[i]] = Uint8List.fromList(
            Pointer<Uint8>.fromAddress(addr).asTypedList(len),
          );
        }
        return out;
      });

  /// `C_SignInit(CKM_RSA_PKCS)`. A CKA_ALWAYS_AUTHENTICATE key needs a
  /// context-specific [login] after this and before [signRsaPkcs].
  void signInitRsaPkcs(int session, int key) => using((arena) {
    final mech = arena<Uint8>(_structSize);
    mech.asTypedList(_structSize).fillRange(0, _structSize, 0);
    _setUl(_view(mech, _structSize), 0, ckmRsaPkcs);
    _check('C_SignInit', _signInit(session, mech, key));
  });

  /// `C_Sign` over [data], after [signInitRsaPkcs]. Blocks.
  Uint8List signRsaPkcs(int session, Uint8List data) => using((arena) {
    final inp = arena<Uint8>(data.length);
    inp.asTypedList(data.length).setAll(0, data);
    final lenP = arena<Uint8>(_ulSize);
    _setUl(_view(lenP, _ulSize), 0, 0);
    _check('C_Sign', _sign(session, inp, data.length, nullptr, lenP));
    final n = _getUl(_view(lenP, _ulSize), 0);
    final sig = arena<Uint8>(n);
    _check('C_Sign', _sign(session, inp, data.length, sig, lenP));
    final m = _getUl(_view(lenP, _ulSize), 0);
    return Uint8List.fromList(sig.asTypedList(m));
  });

  Pointer<Uint8> _template(Arena arena, Map<int, Uint8List> attrs) {
    final t = arena<Uint8>(attrs.length * _structSize);
    final d = _view(t, attrs.length * _structSize);
    var i = 0;
    for (final e in attrs.entries) {
      final v = arena<Uint8>(e.value.isEmpty ? 1 : e.value.length);
      v.asTypedList(e.value.length).setAll(0, e.value);
      final base = i * _structSize;
      _setUl(d, base, e.key);
      d.setUint64(base + _ptrOff, v.address, Endian.host);
      _setUl(d, base + _lenOff, e.value.length);
      i++;
    }
    return t;
  }
}

/// A CK_ULONG as the bytes a template value needs.
Uint8List ulongBytes(int v) {
  final b = ByteData(_ulSize);
  _setUl(b, 0, v);
  return b.buffer.asUint8List();
}
