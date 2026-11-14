# Validation is split into collect (async, I/O) and decide (sync, pure)

Collect is the only stage that does I/O, and only through sources the caller passes in (no network by default). It produces serializable diagnostic data. Decide runs the EN 319 102-1 processes (one unit per building block) over diagnostic data, the validation policy and the validation time, and produces detailed and simple reports deterministically. This makes every validation reproducible from a single JSON file (bug reports, golden tests), keeps offline behaviour predictable, and lets work be split across server and client. Collect gathers all revocation candidates (embedded, DSS dictionary, live). Decide picks among them with DSS's rules and reports why each was used or rejected.

## Considered Options

- Interleaved engine that fetches on demand: rejected. Hard to test or reproduce, and offline behaviour depends on hidden network calls.
