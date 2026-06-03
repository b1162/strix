---
name: pentagi_coordination
description: PentAGI-inspired multi-agent role division and hierarchical planning protocols
---

# PentAGI Coordination and Hierarchical Planning

Inspired by the PentAGI framework architecture, this coordination protocol optimizes dynamic security assessments by dividing work among highly specialized agent roles and enforcing a strict 3-7 step preliminary planning phase.

## 1. Specialist Role Division

When spawning subagents using `create_agent`, do not create generic testers. Always divide the work into PentAGI-style specialists matching the exact attack vector:

*   **Primary Coordinator (Root)**: That's you. Manage the high-level plan, orchestrate specialists, avoid task drift, aggregate findings, and control child agent execution limits.
    *   *Timeout Control*: When spawning specialists via `create_agent`, always assign realistic timeouts using `timeout_seconds`. For quick verification/validation tasks (e.g., verifying a single SQLi, XSS, or local vulnerability), set `timeout_seconds` to `300` or `600` (5-10 minutes) instead of the default. Keep execution tight and fast.
*   **Coder / Pentester Specialist**: Spawned specifically to write, adapt, and run exploit scripts or custom tools (e.g., custom Python payloads, buffer overflow adjustments, race condition triggers).
    *   *Recommended Skills*: `vulnerabilities/race_conditions`, `tooling/nuclei`, custom exploit scripts.
*   **Searcher / Threat-Intel Specialist**: Spawned to search Tavily, Perplexity, or local databases for CVEs, public exploit POCs, and technical documentation.
    *   *Recommended Skills*: `tooling/web_search`, security databases.
*   **Adviser / Remediation Specialist**: Spawned at the end of finding validation to write professional mitigation guides and developer-friendly fixes (CWE-mapping, code remediation).
*   **Installer Specialist**: Spawned to configure, compile, or install required dependencies or security tools within the Kali sandbox.

## 2. Phase-Based Planning Guardrail

Before executing *any* spawned task or performing complex manual testing, you must construct a **3-7 step preliminary execution plan** (Planning Step). Write this plan as a note or keep it in your immediate reasoning context.

### Execution Plan Structure:
1.  **Step 1: Reconnaissance & Target Mapping** — Active port scanning, endpoint fuzzing, or code triage.
2.  **Step 2: Injection & Vector Probing** — Injecting targeted test payloads.
3.  **Step 3: Verification** — Retrieving response tokens, error logs, or OOB interactions.
4.  **Step 5: Exploitation & Proof of Concept** — Creating an actionable, reproducible exploit script.
5.  **Step 6: Remediation Writing** — Formulating the corrective patch.

Enforce that specialists follow their step-by-step plans strictly. If a specialist drifts or encounters a roadblock, pause and re-generate the plan.
