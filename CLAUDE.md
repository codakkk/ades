@AGENTS.md

## Claude Code: subagent model selection

When spawning subagents (Agent tool, Workflow `agent()` calls, or agents spawned by skills such as `implement-spec`, `tdd`, `code-review`, `grilling`), always set `model` explicitly:

- **Opus 5.5 (`model: "opus"`)**: judgment work: grilling, code review, spec review, verification, planning, exploration/research, merge-conflict resolution.
- **Sonnet 5.5 (`model: "sonnet"`)**: implementation work: implementer subagents (e.g. `implement-spec` step 4, `tdd` builds), the fix-up implementer after code review, mechanical merges.

If a task mixes both, pick by its primary output: code written → Sonnet; verdict/findings/plan → Opus.
