# Issue tracker: GitHub Issues

Issues and specs for this repo live in GitHub Issues. Use the `gh` CLI. The repo is inferred from the `origin` remote.

## Conventions

- **Feature**: a GitHub milestone named after the feature (e.g. `M2 time`).
- **Spec**: one issue labelled `spec` in the feature's milestone. The spec text is the issue body.
- **Implementation tickets**: one issue per ticket, in the same milestone, added as **sub-issues** of the spec issue. The body starts with `Part of #<spec>`. Never put several tickets in one issue.
- **Triage state**: one triage label per issue (see `triage-labels.md`). Done means the issue is closed: `completed` when resolved, `not planned` for `wontfix`.
- **Comments and history**: issue comments.
- **No personal data** in issues: never paste real signatures, certificates, names or codice fiscale (ADR-0010). Reproduce with tier-1 synthetic fixtures.

## When a skill says "publish to the issue tracker"

`gh issue create --title ... --body-file ... --label ... --milestone ...`. Create the milestone first if it doesn't exist (`gh api repos/{owner}/{repo}/milestones -f title=...`).

## When a skill says "fetch the relevant ticket"

`gh issue view <number> --comments`. The user will normally pass the issue number or URL.

## Wayfinding operations

Used by `/wayfinder`. The **map** is an issue with one **child** sub-issue per ticket.

- **Map**: an issue labelled `map` (the Notes / Decisions-so-far / Fog body).
- **Child ticket**: a sub-issue of the map, with the question in the body and a type label: `research`, `prototype`, `grilling` or `task`.
- **Blocking**: a `Blocked by: #N, #N` line at the top of the body. A ticket is unblocked when every issue it lists is closed.
- **Frontier**: the open, unblocked sub-issues of the map that have no assignee. The lowest number wins.
- **Claim**: assign yourself (`gh issue edit <n> --add-assignee @me`) before any work.
- **Resolve**: post the answer as a comment headed `## Answer`, close the issue, then add a context pointer (gist + link) to the map's Decisions-so-far by editing the map issue body.
