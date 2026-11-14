/// Typed failures of the PKCS#11 credential. Not `AdesException`s (that
/// hierarchy is sealed inside the core): they describe the device, and the
/// core's one-call `sign` wraps them in `SigningFailedException`.
sealed class Pkcs11Exception implements Exception {
  const Pkcs11Exception(this.message);
  final String message;

  @override
  String toString() => '$runtimeType: $message';

  String get wireKind;

  /// Wire form used between the worker isolate and the caller.
  List<Object?> toWire() => [wireKind, message, null];

  static Pkcs11Exception fromWire(List<Object?> w) {
    final msg = w[1]! as String;
    switch (w[0]) {
      case 'wrongPin':
        return Pkcs11WrongPinException(msg);
      case 'pinLocked':
        return Pkcs11PinLockedException(msg);
      case 'pinCancelled':
        return Pkcs11PinCancelledException(msg);
      case 'pinCallback':
        return Pkcs11PinCallbackException(msg);
      case 'keyNotFound':
        return Pkcs11KeyNotFoundException(msg);
      case 'closed':
        return Pkcs11ClosedException(msg);
      case 'load':
        return Pkcs11ModuleLoadException(msg);
      case 'call':
        final d = w[2]! as List<Object?>;
        return Pkcs11CallException(msg, d[0]! as String, d[1]! as int);
      default:
        return Pkcs11CallException(msg, 'unknown', -1);
    }
  }
}

/// The module could not be loaded or initialised (bad path, wrong
/// architecture, `C_Initialize` failed).
final class Pkcs11ModuleLoadException extends Pkcs11Exception {
  const Pkcs11ModuleLoadException(super.message);
  @override
  String get wireKind => 'load';
}

/// A PKCS#11 function returned an error not covered by a more specific type.
final class Pkcs11CallException extends Pkcs11Exception {
  const Pkcs11CallException(super.message, this.function, this.returnValue);

  /// PKCS#11 function name, e.g. `C_Sign`.
  final String function;

  /// The raw CK_RV.
  final int returnValue;

  @override
  String get wireKind => 'call';
  @override
  List<Object?> toWire() => [
    wireKind,
    message,
    [function, returnValue],
  ];
}

/// `CKR_PIN_INCORRECT`. The token counts the attempt; the caller may sign
/// again to retry (a new PIN prompt follows).
final class Pkcs11WrongPinException extends Pkcs11Exception {
  const Pkcs11WrongPinException(super.message);
  @override
  String get wireKind => 'wrongPin';
}

/// `CKR_PIN_LOCKED`: too many wrong attempts; needs the PUK/SO PIN.
final class Pkcs11PinLockedException extends Pkcs11Exception {
  const Pkcs11PinLockedException(super.message);
  @override
  String get wireKind => 'pinLocked';
}

/// The PIN callback returned null (the user cancelled the prompt).
final class Pkcs11PinCancelledException extends Pkcs11Exception {
  const Pkcs11PinCancelledException(super.message);
  @override
  String get wireKind => 'pinCancelled';
}

/// The PIN callback itself threw.
final class Pkcs11PinCallbackException extends Pkcs11Exception {
  const Pkcs11PinCallbackException(super.message);
  @override
  String get wireKind => 'pinCallback';
}

/// No private key on the token matches the credential's certificate.
final class Pkcs11KeyNotFoundException extends Pkcs11Exception {
  const Pkcs11KeyNotFoundException(super.message);
  @override
  String get wireKind => 'keyNotFound';
}

/// The module was closed (or its worker isolate died).
final class Pkcs11ClosedException extends Pkcs11Exception {
  const Pkcs11ClosedException(super.message);
  @override
  String get wireKind => 'closed';
}
