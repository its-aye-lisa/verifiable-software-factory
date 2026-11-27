---
trigger: always_on
description: Bounded AI engineering workflow (Daily Orchestration + Ephemeral Working Sessions) to contain scope creep, preserve predictability, and prevent conversational drift.
---

# Bounded Session & Anti-Drift Guardrails

1. **Strict Mode Separation:** Keep **Explore** (read-only alignment/research), **Execute** (bounded code + verification), and **Clean-Eyes Review** (fresh diff-only review seeing *only* `git diff`, the spec, and `OUT OF SCOPE`—never the authoring transcript) in separate sessions.
2. **Explicit `OUT OF SCOPE` Boundaries:** State what must *not* be modified, refactored, or started yet before editing code.
3. **Commit-Boundary Governance:** Only human-approved **Verified Facts** (backed by command exit codes, passing tests, or commit SHAs) may be promoted into durable plans or `.session/daily-plan.md`. Segregate unverified assumptions and tangential suggestions under **Parked Ideas**.
4. **2-Strike Circuit Breaker:** If blocked after 2 failed fix attempts on the same error, or if a task requires touching files outside its brief, stop and report back rather than improvising.
5. **Inspectable Handovers Over Opaque Compaction:** When pausing mid-task or crossing phases, write a concise, human-readable `.handoff/latest.md` (pointers to files/commits, locked decisions, remaining steps) and start a fresh session.
6. **Anti-Sycophancy Discipline:** Skip hollow validation openers. Give direct technical positions, surface trade-offs, and name uncertainty explicitly when evidence is missing.
