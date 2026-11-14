# DSS demo webapp and `ades oracle` (ticket 18)

Dev tools for ad-hoc investigation against the same DSS release as the oracle harness (`tool/dss_oracle/dss_version.txt`, currently 6.5.1). Not part of CI. Goldens come only from the harness (ADR-0010).

## Start the webapp

DSS publishes no prebuilt image, so compose builds the official `Dockerfile` of the `esig/dss-demonstrations` release tag (Tomcat + demo WAR). First build takes a few minutes (Maven downloads).

```
docker compose -f tool/dss_webapp/docker-compose.yml up --build -d
open http://localhost:9795          # DSS_WEBAPP_PORT=... to change the port
docker compose -f tool/dss_webapp/docker-compose.yml down
```

It binds to 127.0.0.1 only. Unlike the harness it is online: it loads the EU trusted lists, so it trusts real qualified chains but not our test CAs.

## `ades oracle <file>`

```
dart run packages/ades_cli/bin/ades.dart oracle sig.p7m -t root.pem [-c intermediate.pem] [-d content] \
    [--validation-time 2026-11-10T00:00:00Z] [--ignore-revocation] [--webapp [--webapp-url URL]] [--json]
```

It validates with ades and with DSS, normalizes both to the oracle JSON format (`tool/dss_oracle/README.md`) and prints one row per compared path, `DIFF` marking differences. Exit 0 identical, 3 differences, 69 DSS side unavailable (no Docker, webapp down).

- Default DSS side: the offline Docker harness (same image, same `default` / `no-revocation` policy, `--network none`). Needs exactly one `-t` anchor. The image is built on first use.
- `--webapp`: the demo webapp's REST API, with the harness image's policy XML and `--validation-time` passed along. Our `-t`/`-c` certificates cannot be handed to the webapp, so it uses its trusted lists: fixtures signed under test CAs report `NO_CERTIFICATE_CHAIN_FOUND` there. Use it for real-world signatures (for example ticket 15's CNS).

## Monthly manual spot-check (webapp vs harness)

The harness is the source of truth for goldens; the webapp is the independent, official front end of the same DSS release. Once a month, and whenever the pin changes:

1. Check for a new DSS release; if one exists, bump the pin first (`tool/dss_oracle/README.md`, "Updating DSS", and the tag in `docker-compose.yml`).
2. Start the webapp (above) and open `http://localhost:9795` > Validation.
3. Upload 2-3 signatures from `fixtures/tier1/signatures/` (one positive, one tampered, one with a trust problem) with the default validation policy, and compare the webapp's simple report to the matching `*.dss.json` golden: indication, sub-indication and signing time. Different trust is expected (the webapp has no test anchors), so compare tampered/format failures, signing time and scope rather than chain results.
4. Optionally run `ades oracle <file> --webapp` on a real signature and read any `DIFF` rows.
5. If the webapp and harness disagree on something that is not trust, the harness wiring is suspect: investigate before trusting new goldens.
