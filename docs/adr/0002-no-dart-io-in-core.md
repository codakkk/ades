# Web is a first-class target: no dart:io in core libraries

The core must compile and pass tests on the Dart VM, AOT, dart2js and dart2wasm. Browser-side remote signing (CSC) is a real use case. So no core library imports `dart:io`. Input arrives as `Uint8List` or `Stream<List<int>>`, and file-system helpers live in a separate `dart:io`-only library behind a conditional import. Accepted cost: on JS, BigInt-based RSA/ECDSA is much slower.
