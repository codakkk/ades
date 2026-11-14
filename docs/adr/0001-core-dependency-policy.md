# Core dependency policy: pure Dart, minimal vetted deps, own DER and C14N

"Pure Dart" means the core runs on the Dart SDK with no native code. It does not mean zero pub dependencies. The core may depend on dart.dev-published packages (`crypto`, `convert`, `collection`, `meta`, `typed_data`), plus `xml` (parsing only), `archive` (raw inflate/deflate only, always with an output cap) and `pointycastle` (asymmetric primitives only, behind an internal `CryptoProvider` seam so it can be swapped for Rust or WebCrypto later). We write our own strict DER codec and our own XML canonicalization (C14N 1.0/1.1/exclusive). Security-critical parsing is not outsourced, and no existing Dart C14N is trustworthy enough.

Rules for `archive` (pinned `>=4.6.0 <5.0.0`): use only the pure-Dart `Inflate.lazy` + `inflateBlock()` into our own counting sink, on every platform. Never use `ZLibDecoder`: it picks native zlib on the VM and pure Dart on the web, so it behaves differently per platform, and its `maxOutputSize` is checked only after full inflation on the web. Always enable strict error flags (4.6.0 no longer throws on corrupt data by default). Before inflating, cap compressed size and ratio per stream (PDF `/Length`, zip central-directory size; both are policy values), because one deflate block is buffered before the sink sees it. We offer an upstream patch that drains output inside a block. If fuzzing shows the in-block buffering is exploitable and upstream won't fix it, our own inflate replaces `archive` behind the same internal seam.

## Considered Options

- SDK-only, everything hand-written: rejected. Writing our own RSA/ECDSA/bignum code adds risk without benefit.
- Use `asn1lib` for ASN.1: rejected. Not strict enough about DER for signature verification.
- Use `archive`'s `ZipDecoder` for ASiC: rejected. It normalizes away duplicate entry names and local/central header mismatches, which are exactly the ASiC attack vectors. ASiC zip structure is parsed by our own code, and only the decompression of entry bytes is delegated to `archive`.
- Write our own inflate: rejected. Generic decompression is well covered by `archive`, and owning it adds bug surface for no gain.

## Addendum: `json_annotation`

The core also depends on `json_annotation` (runtime) for the classes annotated for `json_serializable` (a dev dependency; the generated `*.g.dart` files are committed). The MVP spec chose `json_serializable` for the diagnostic data and policy models, and the generated code needs `json_annotation` at runtime. It is maintained by the Dart team and has no dependencies of its own, so it joins the allow-list next to `collection`, which the core uses for byte comparison.
