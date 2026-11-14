# Rust admission gate

Rust code is admitted only when all four hold: (1) a benchmark on a real workload shows pure-Dart AOT below target (SHA-256 >= 300 MB/s; RSA-2048 verify >= 2,000/s); (2) Rust is at least 3x faster on that workload; (3) it ships as an opt-in `CryptoProvider` in a separate package via Dart build hooks with prebuilt binaries; (4) pure Dart stays the default and the tested fallback. Web performance is addressed with a WebCrypto provider, never Rust. This gate is fixed up front so the question isn't reopened case by case.
