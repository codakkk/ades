# DSS oracle harness (ADR-0010)

A thin Java CLI (`src/main/java/oracle/Oracle.java`) over the **pinned DSS release in `dss_version.txt`** (currently 6.5.1, also in `pom.xml`). It validates every tier-1 fixture offline and writes normalized JSON goldens next to the fixtures. Our own Dart tests diff against them (no Java in the PR loop).

## Run

Needs only Docker (no host Maven or JDK):

```
dart run tool/dss_oracle/run.dart            # regenerate every golden in place
dart run tool/dss_oracle/run.dart --check    # regenerate to a temp dir, exit 1 on any diff (nightly)
dart run tool/dss_oracle/run.dart --only <case-id>
```

The container runs with `--network none`: no AIA, no CRL/OCSP, no trusted lists. Cases come from `fixtures/tier1/oracle-cases.json` (fixed `validationTime`, one trust anchor per case, optional detached `content`, `policy`).

Policies (files baked into the image from the pinned DSS jar): `default` is DSS's own `constraint.xml`; `no-revocation` is the same with `RevocationDataAvailable` and `AcceptableRevocationDataFound` set to IGNORE. It maps to our `ValidationPolicy(revocationDataAvailable: ConstraintLevel.ignore)` and is the only way to see TOTAL-PASSED offline. Each case is run under both: `<fixture>.dss.json` and `<fixture>.dss-norev.json`.

## Regenerating our own signed fixtures

`dart run packages/ades_soft/tool/generate_signed_fixtures.dart` writes `fixtures/tier1/signatures/ours/` (enveloping and detached, RSA and ECDSA P-256, tier-1 keys, fixed signing time, byte-stable). Then rerun the harness. Changing tier-1 fixtures requires regenerating the goldens too.

## JSON format (one file per case)

```
{
  "dssVersion": "6.5.1",
  "validationTime": "2026-11-10T00:00:00Z",
  "policy": "default" | "no-revocation",
  "error": "...",              // only when the harness itself failed; the runner refuses to write it
  "signatures": [{
    "index": 0,
    "indication": "TOTAL-PASSED" | "TOTAL-FAILED" | "INDETERMINATE",   // ETSI spelling (hyphens)
    "subIndication": "HASH_FAILURE" | ... | null,
    "signingTime": "2026-06-01T12:00:00Z" | null,                      // whole seconds, UTC
    "scope": [{"kind": "FULL", "name": "Full document"}],              // name is DSS-only
    "blocks": {                                                        // a block that did not run is absent
      "FC|ISC|VCI|XCV|CV|SAV": {"indication": "PASSED|FAILED|INDETERMINATE", "subIndication": ... | null,
        "constraints": [{"name": "BBB_XCV_IRDPFC", "status": "OK|NOT_OK|WARNING|INFORMATION"}],
        "subXCV": [...]                                                // XCV only: per certificate, same shape
      }
    }
  }]
}
```

`constraints`, `subXCV`, scope `name`, `dssVersion`, `policy` and `error` are informational (triage); they are not compared.

Our side: `packages/ades/lib/src/validation/normalized_report.dart` (`normalizeReport`, `projectForComparison`, `flattenReport`). Scope kinds `envelopedContent` and `detachedDocument` both normalize to `FULL`.

## Comparison and known divergences

`packages/ades/test/dss_goldens_test.dart` flattens both sides to `path -> value` and fails on any path that differs unless `fixtures/tier1/known-divergences.json` lists it with the exact `ours` and `dss` values and a non-empty `reason`. It also fails on listed entries that no longer differ, so the file cannot rot. Triage aid: `cd packages/ades && dart run test/support/dss_diff.dart` prints current differences as ready-to-edit entries.

## Updating DSS

Bump `dss.version` in `pom.xml` and `dss_version.txt` together, run the harness, review the golden diff, update divergences. `test/dss_oracle_pin_test.dart` fails if goldens and pin disagree.
