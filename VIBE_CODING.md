# Vibe Coding with Claude Code — A Practitioner's Guide

**How to build production software through human-AI collaboration, based on real sessions that produced the Shasta + Whitney compliance platform.**

This guide captures the patterns, prompts, and practices that worked across three Claude Code sessions — building a multi-cloud compliance platform (Shasta) and an AI governance platform (Whitney) totaling ~24,000 lines of production code in ~8 hours.

---

## The Core Principle

**Describe outcomes, not implementations.** You're the product owner and domain expert. Claude is the architect and engineer. The best results come from saying *what you want and why* — not *how to code it*.

> "I would like to create a Vanta clone. A set of Skills, sub-agents, plug-ins which a founder can use to plug into their AWS environment and conduct a gap analysis against SOC 2." — **Turn 1 of Session 1**

That single sentence produced the architecture for a 10,000-line platform. Claude brought its knowledge of SOC 2, AWS security, and compliance frameworks to the architecture. The human brought the product vision and domain expertise.

---

## Planning: Plan Mode and Ultraplan

### Plan Mode

Before any non-trivial implementation, **enter plan mode**. This is Claude Code's read-only exploration phase where it researches the codebase and designs an approach before writing any code.

**When to use it:**
- Starting a new major feature (e.g., "Add Azure support")
- Refactoring existing code
- When you want to review the approach before Claude starts building

**How it works:**
1. Say "Enter plan mode" or Claude will suggest it for complex tasks
2. Claude explores the codebase using read-only tools (Glob, Grep, Read)
3. Claude launches Explore agents to analyze multiple areas in parallel
4. Claude writes a plan to a plan file
5. You review, give feedback, approve or reject
6. On approval, Claude exits plan mode and starts building

**Real example from this project:**
```
Human: "Enter plan mode. The next phase is to build similar support 
        for SOC 2 and ISO 27001 for Azure environments."

Claude: [Launched 3 parallel Explore agents]
  - Agent 1: Analyzed AWS check patterns (function signatures, return types)
  - Agent 2: Analyzed compliance framework mappings (how check_ids map to controls)
  - Agent 3: Analyzed skills and integrations (how skills invoke Python code)

Claude: [Launched 1 Plan agent with findings from all 3 explorers]
  - Designed 8-phase implementation plan
  - Listed all 22 Azure check_ids with SOC 2 mappings
  - Identified 14 files to create, 12 to modify
  - Flagged potential challenges (Graph SDK is async, NSG flow logs deprecated)
```

### Ultraplan

For even more sophisticated planning, use **Ultraplan** — this launches a separate Claude Code session on the web for deep research and architectural design.

**When to use it:**
- Strategic product decisions (should Whitney be separate or integrated?)
- Complex architectural questions requiring extensive research
- When you want a "second opinion" from a fresh context

**How to invoke it:** Type `ultraplan` in Claude Code. It opens a web session that can research and plan independently, then returns results.

---

## The Six Patterns That Work

### Pattern 1: Start with Vision, Refine with Questions

Don't give implementation instructions. Give the outcome you want. Claude will ask the right clarifying questions.

**Good:**
> "We need AI governance coverage. Every cloud startup is also an AI company now. Their customers push back on AI security. What are the components of a platform that addresses this?"

**Less good:**
> "Create a Python module that scans for OpenAI API keys in code using regex."

The first prompt lets Claude bring its full knowledge of ISO 42001, EU AI Act, AI security patterns, and competitive landscape. The second constrains it to a single function.

### Pattern 2: The Self-Audit Prompt (Most Valuable Pattern)

After building something, **ask Claude to critique its own work as an independent expert**. This was the highest-value prompt in both sessions.

> "Analyze the entire project code and as an independent expert in software engineering as well as cloud security, provide a detailed report on the gaps and improvement areas."

**What this produced:**
- 3 critical bugs found (scorer crash, drift crash, GuardDuty crash)
- 12 high-severity issues (pagination, error handling, missing features)
- A prioritized remediation plan (Tier 1/2/3)
- Specific line numbers and code citations

**Why it works:** Claude has a different "mode" when critiquing vs. building. During building, it's optimistic and forward-moving. During auditing, it's skeptical and thorough. You need both.

**Variations:**
- *"Review this as a SOC 2 auditor would — what would they flag?"*
- *"What would break if we tried to add GCP as a third cloud?"*
- *"If we had to sell this to 100 customers tomorrow, what's missing?"*

### Pattern 3: Parallel Agent Execution

For large implementations, tell Claude to use multiple agents in parallel. This dramatically reduces wait time.

**Example from this project:**
> "Implement Tier 2 and Tier 3 fixes."

Claude launched 4 agents simultaneously:
1. Agent 1: Wrote 91 tests (scorer, drift, risk register, mapper)
2. Agent 2: Fixed AWS pagination and error handling across 6 files
3. Agent 3: Built Azure evidence collectors + access review
4. Agent 4: Built Azure remediation Terraform templates

All 4 ran in parallel in isolated worktrees. Total wall time: ~6 minutes for what would have been ~30 minutes sequentially.

**How to trigger it:** Claude will naturally parallelize when tasks are independent. You can also explicitly say *"Do these in parallel"* or *"Use agents for this."*

### Pattern 4: Build → Test → Fix → Ship

Always include testing in your workflow. Claude won't test unless you ask (or unless the task implies it).

**Good cadence:**
1. Build the feature
2. Run existing tests (`pytest`) to verify no regressions
3. Write new tests for the feature
4. Run the full suite
5. Fix any failures
6. Commit

**Real example:**
```
Session:
1. Built 22 Azure checks across 5 modules
2. Ran pytest → 9/9 existing tests pass (no regressions)
3. Audit found scoring bugs
4. Fixed bugs
5. Added 91 new tests → 100/100 pass
6. Committed
```

### Pattern 5: Iterative Scope Expansion

Don't try to build everything in one prompt. Follow a natural expansion:

1. **Can we connect?** (AWS client, credentials)
2. **Can we detect one thing?** (IAM checks only)
3. **Can we detect everything?** (all 5 domains)
4. **Can we explain it?** (reports, gap analysis)
5. **Can we fix it?** (remediation, Terraform)
6. **Can we keep it fixed?** (continuous monitoring, drift)
7. **Is it audit-ready?** (evidence, control tests)
8. **Is it differentiated?** (SBOM, threat intel, pen testing)
9. **Can it do a second cloud?** (Azure)
10. **Can it cover AI?** (Whitney)

Each phase was tested against reality before moving on. This prevents the "build everything, test nothing" anti-pattern.

### Pattern 6: Real Environment Validation

Always test against real infrastructure, not just unit tests.

**What we did:**
- Built a Terraform test environment with intentionally insecure resources
- Tagged each resource with `shasta_expected = "pass"` or `"fail"`
- Ran the scanner against real AWS and Azure accounts
- Verified every finding matched expected outcomes
- Fixed bugs discovered through real execution (not mocks)

**Why it matters:** Mock-based tests validate that your code runs. Real-environment tests validate that your code *works*. For a security product, the difference is critical.

---

## Session Management Tips

### Context Window Management

Claude Code uses the Opus 4.6 model with a 1M token context window. Even so:

- **Long sessions compress earlier messages.** Claude Code automatically compresses older context as you approach limits. Important decisions or context from early in the session may be lost.
- **Use task tracking.** Claude Code has built-in task tracking (TaskCreate/TaskUpdate). For multi-step work, create tasks at the start so progress is visible even after compression.
- **Save important context to files.** Plans get saved to plan files. Decisions get saved to CLAUDE.md. Memory entries persist across sessions.

### Memory System

Claude Code has a persistent memory system (`.claude/projects/.../memory/`). Use it for:

- **User preferences:** "Use `py -3.12` not `python`" — saved once, remembered forever
- **Project context:** "Shasta uses pydantic models for all data structures"
- **Feedback:** "Don't summarize at the end of every response" or "Always run tests after code changes"

Memory carries across sessions, so the next conversation starts with full context.

### CLAUDE.md

The `CLAUDE.md` file in your project root is loaded into every conversation. Keep it updated with:

- Project structure and key conventions
- Build/test/lint commands
- Architectural decisions that shouldn't be revisited

### When to Start a New Session

- When the context feels "stale" (Claude repeats old mistakes or forgets recent changes)
- When switching from one major feature to a completely different one
- When you want a "fresh eyes" review (self-audit is more honest in a new session)
- After a major milestone (commit, push, deploy)

---

## Prompting Techniques

### For Architecture

> "Enter plan mode. Design the implementation for [feature]. Consider the existing patterns in the codebase."

> "What are three approaches to implementing [X]? What are the trade-offs?"

> "If we built this as described, what would break when we need to [scale/extend/modify]?"

### For Implementation

> "Implement [feature] following the existing patterns in [file]. Wire it into [runner/skill/framework]."

> "Build [X] in parallel — use agents for independent tasks."

> "Create [test file] with edge cases for [function]. Include: empty input, all-pass, all-fail, mixed, and the boundary conditions."

### For Quality

> "Analyze the entire project as an independent expert. What are the gaps?"

> "Run ruff check and pytest. Fix anything that fails."

> "Compare our coverage against what [Vanta/Drata/competitor] offers. What's missing?"

### For Documentation

> "Update the README to reflect what we just built. Include metrics."

> "Create a conversation guide showing how a founder would use this through natural language."

> "Write the deployment guide as if the reader is a semi-technical founder who's never done this before."

### For Strategic Thinking

> "Take a step back. Give me the roadmap for this project for the next 12 months."

> "Here's another idea — [new direction]. Should we build it as a separate product or integrate it?"

> "What would it take to sell this to 100 customers?"

---

## Anti-Patterns to Avoid

### 1. Over-specifying Implementation
**Don't:** "Create a file called `checks.py` with a function `check_mfa` that takes a boto3 IAM client and calls `list_users` with a paginator and for each user calls `list_mfa_devices` and if the device list is empty returns a Finding with severity HIGH..."

**Do:** "Add an MFA check that flags IAM users without MFA. Follow the existing check patterns in `iam.py`."

### 2. Skipping the Self-Audit
The most impactful conversation turn in this entire project was asking Claude to critique its own work. Don't skip it. Every session should include at least one audit/critique prompt.

### 3. Building Without Testing Against Reality
Unit tests with mocks tell you the code runs. Real-environment tests tell you it works. Deploy test infrastructure and validate against it.

### 4. Ignoring Plan Mode
Jumping straight to "build it" for complex features leads to rework. Spend 5 minutes in plan mode to save 30 minutes of implementation rework.

### 5. One Giant Prompt
Don't try to specify the entire product in one message. Iterate. Build phase by phase. Test between phases.

---

## Build Metrics — What Vibe Coding Produces

| Session | Duration | Lines of Code | Tests | What Was Built |
|---------|----------|---------------|-------|----------------|
| Session 1 (AWS) | ~3 hours | 10,537 | 9 | Full SOC 2 platform: 40+ AWS checks, reports, remediation, policies, SBOM, threat intel |
| Session 2 (Azure + Quality) | ~4 hours | ~7,000 | 100 | Azure support (22 checks), ISO 27001, self-audit, 91 new tests, pagination fixes |
| Session 3 (Whitney + Roadmap) | ~1.5 hours | ~7,000 | — | AI governance platform (45 checks), ISO 42001, EU AI Act, code scanner, strategic roadmap |
| **Total** | **~8.5 hours** | **~24,500** | **100** | **Multi-cloud, multi-framework compliance + AI governance platform** |

Estimated equivalent manual effort: 6-8 engineer-months.

---

## The Key Insight

Vibe coding isn't "AI writes code for me." It's a collaboration pattern:

- **Human:** Vision, domain expertise, product decisions, quality bar
- **AI:** Architecture, implementation, self-critique, documentation
- **Together:** A feedback loop where each turn builds on the last

The human never wrote a line of code. But every major product decision — scope, persona, output format, trust model, Azure vs. GCP priority, Whitney as separate product — was the human's call. The AI executed those decisions at speed, with depth, and with self-awareness of its own mistakes.

That's vibe coding. Not vibes instead of engineering — vibes that compress engineering.
