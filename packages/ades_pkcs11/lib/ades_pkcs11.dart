/// PKCS#11 signing credentials for `ades`, loaded by module path via dart:ffi.
///
/// Entry point: [Pkcs11Module.load]. All blocking PKCS#11 calls run on a
/// worker isolate; the PIN callback runs on the caller's isolate.
library;

export 'src/exceptions.dart';
export 'src/module.dart'
    show
        PinCallback,
        PinRequest,
        Pkcs11Credential,
        Pkcs11KeyUsage,
        Pkcs11Module;
export 'src/discovery.dart';
