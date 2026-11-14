## Agent skills

### Issue tracker

Issues tracked in GitHub Issues (via `gh`). See `docs/agents/issue-tracker.md`.

### Triage labels

Default five canonical labels (needs-triage, needs-info, ready-for-agent, ready-for-human, wontfix). See `docs/agents/triage-labels.md`.

### Domain docs

Single-context: root `GLOSSARY.md` + `docs/adr/`. See `docs/agents/domain.md`.

### Subagent model selection

When spawning subagents (Agent tool, Workflow `agent()` calls, or agents spawned by skills such as `implement-spec`, `tdd`, `code-review`, `grilling`), always set `model` explicitly:

- **Opus 5.5 (`model: "opus"`)** — judgment work: grilling, code review, spec review, verification, planning, exploration/research, merge-conflict resolution.
- **Sonnet 5.5 (`model: "sonnet"`)** — implementation work: implementer subagents (e.g. `implement-spec` step 4, `tdd` builds), the fix-up implementer after code review, mechanical merges.

If a task mixes both, pick by its primary output: code written → Sonnet; verdict/findings/plan → Opus.
