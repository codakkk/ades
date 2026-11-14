/// File-system helpers for VM targets. Import only where `dart:io` exists.
library;

export 'src/io/read_file_stub.dart'
    if (dart.library.io) 'src/io/read_file_io.dart';
