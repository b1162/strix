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
4.  **Step 4: Exploitation & Proof of Concept** — Creating an actionable, reproducible exploit script.
5.  **Step 5: Chain Analysis** — After all individual findings are confirmed, check for chainable vulnerabilities. If multiple findings can be linked (output of one enables the next), spawn a specialist with `skills=["vuln_chain"]` to document and file the `[CHAIN]` report.
6.  **Step 6: Remediation Writing** — Formulating the corrective patch per finding (Adviser Specialist).
7.  **Step 7: Report Generation** — If the operator requested a written report, call `generate_final_report` before invoking the lifecycle tool.

Enforce that specialists follow their step-by-step plans strictly. If a specialist drifts or encounters a roadblock, pause and re-generate the plan.

## 3. MFA-Protected Targets

If a target requires TOTP/OTP authentication during testing:
- Use `get_totp(secret_or_path)` to generate the current code (pass either the raw Base32 secret or a path to a SOPS-encrypted secrets file)
- Check `valid_seconds_remaining` in the response — submit requests before the code expires
- For automated sprays, refresh the code at the start of each auth attempt
