---
name: bounded-session
description: Bounded AI engineering workflow using a Daily Orchestration Session plus disposable Ephemeral Working Sessions (Explore, Execute, Clean-Eyes Review) tailored for verifiable-software-factory.
---

# Skill: Bounded Session Workflow (`/bounded-session`)

Use this skill to keep factory gate development, policy changes, and ConMon triage contained, predictable, and free of scope creep or conversational drift.

## 1. Two-Tier Cadence

1. **Daily Orchestration Session (`.session/daily-plan.md`, `.gitignore`'d):**
   - Sets 1–3 bounded objectives, explicit deferred items, and stopping points for the day (`Plan → Act → Review → Repeat`).
   - **Commit-Boundary Gate:** Promote only human-approved **Verified Facts** (backed by command output or commit SHAs) into the daily plan; keep all tangential findings in **Parked Ideas**.
2. **Ephemeral Working Sessions:**
   - **Explore (read-only):** Inspect code/logs and lock decisions before editing.
   - **Execute (bounded build):** Edit only `Allowed Paths`, then run:
     ```bash
     make build && go test ./...
     ./bin/factory fast-check --target ../new-vision-gaming
     ```
   - **Clean-Eyes Review (fresh diff-only):** Review `git diff` against the brief and `OUT OF SCOPE` list in a clean context (or via `supply-chain-auditor`) with zero implementation transcript.

## 2. Ephemeral Working Session Brief Template

```markdown
## Ephemeral Working Session Brief
- **Mode:** Explore (read-only) | Execute (code + verify) | Clean-Eyes Review (diff-only)
- **Single Objective:** <one concrete, verifiable outcome>
- **Allowed Paths / Files:** <explicit list or glob>
- **Explicitly OUT OF SCOPE:** <what NOT to touch, refactor, or expand>
- **Done Condition (Verifiable):** `make build && go test ./... && ./bin/factory fast-check --target ../new-vision-gaming`
- **Circuit Breaker:** Stop and report back after 2 failed attempts or if scope needs to expand.
- **Return Artifact:** 1) Verified Facts (command/SHA proof), 2) Decisions Made, 3) Parked Ideas.
```

## 3. Handover File (`.handoff/latest.md`, `.gitignore`'d)

Before resetting a worn session or switching phases, write `.handoff/latest.md` with:
- Current objective & mode
- Locked decisions & verified command outputs
- Pointers to modified files / commits (do not paste whole files)
- Exact next step & remaining `OUT OF SCOPE` guardrails
