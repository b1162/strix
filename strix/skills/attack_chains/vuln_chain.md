---
name: vuln_chain
description: Identifying and documenting multi-step vulnerability chains to produce high-impact attack scenarios
---

# Vulnerability Chaining

Individual vulnerabilities rarely tell the full story. A low-severity information disclosure combined with a medium-severity IDOR can produce a critical data breach. Chaining forces you to think like an attacker who exploits systems end-to-end, not in isolation, and produces reports that accurately reflect true business risk.

## What Makes a Chain

A vulnerability chain is a sequence of two or more distinct weaknesses where the output of one step enables or amplifies the next. The chain as a whole reaches impact that none of the individual vulnerabilities could achieve alone.

**Minimal chain structure:**
1. **Entry point** — the first weakness the attacker exploits from their starting position
2. **Pivot** — what the entry point yields (credentials, tokens, an internal address, a writable path)
3. **Escalation** — how that pivot is used to reach the next weakness
4. **Impact** — the final capability gained (data exfiltration, RCE, privilege escalation, etc.)

Chains can be linear (A → B → C) or branching (A → B₁ or B₂ → C).

## High-Value Chain Patterns

### Web Application Chains

| Pattern | Individual Severity | Chained Severity |
|---------|-------------------|-----------------|
| Open Redirect → OAuth token hijack | Low + Medium | Critical |
| IDOR → PII bulk export + account takeover | Medium | Critical |
| XSS (stored) → CSRF → admin action | Medium + Low | High |
| SQLi (read-only) → credential leak → auth bypass | High + Low | Critical |
| SSRF → internal metadata → cloud creds | Medium | Critical |
| Path Traversal → config read → hardcoded secret | Medium | High |
| Mass Assignment → privilege escalation → admin RCE | Medium | Critical |
| Race Condition → double-spend → financial fraud | Medium | High |
| SSTI → RCE → internal network pivot | Critical (standalone) | Critical (justified) |

### API / Microservice Chains

- **JWT algorithm confusion** → token forging → BFLA → admin endpoints
- **Broken auth on internal service** → SSRF pivot → secrets manager access
- **GraphQL introspection** → hidden mutation → IDOR → data dump
- **Unauthenticated health endpoint** → internal IP disclosure → SSRF → RCE

### Authentication Chains

- Weak password reset → account takeover → lateral movement via shared credentials
- MFA bypass (race/logic) → session fixation → persistent access
- OAuth misconfiguration → token theft → silent re-auth

## How to Identify Chains

1. **Map all individual findings first.** File each vulnerability via `create_vulnerability_report` before attempting to chain.
2. **Classify outputs.** For every finding ask: *what does this give me?*
   - Credential / token / session
   - Internal address / service port
   - File read / write access
   - Code execution primitive
   - Elevated privilege or role
3. **Match outputs to inputs.** Look for other vulnerabilities that *require* what a prior finding *produces*.
4. **Test the chain end-to-end.** Each link must be reproducible in sequence. Confirm that:
   - The precondition is reliably satisfied by step N-1
   - The chain works on a fresh session/state
   - Side effects (created objects, sent emails) are minimal and reversible
5. **Evaluate combined impact.** The chain CVSS score is not the sum of individual scores; it reflects the impact from the attacker's starting position through to the final capability.

## Documentation Standard

When filing a vulnerability chain, produce:

1. **Individual reports** — one `create_vulnerability_report` call per distinct weakness, at its own realistic CVSS. These stand alone.
2. **Chain report** — one additional `create_vulnerability_report` with:
   - `title`: `"[CHAIN] <descriptive name>"` (e.g., `"[CHAIN] SSRF → Cloud Metadata → S3 Exfiltration"`)
   - `severity`: the chain's combined severity (usually higher than any individual link)
   - `description`: narrative overview for a non-technical reader
   - `technical_analysis`: step-by-step walkthrough with request/response evidence for each link
   - `poc_description`: ordered list of reproduction steps spanning the full chain
   - `poc_script_code`: a single script or curl sequence that exercises all links in order
   - `impact`: business-level consequence of the full chain (what an attacker achieves, not just the last step)
   - `remediation_steps`: fix each link independently and note which single fix breaks the chain earliest

### Chain Report Template (technical_analysis field)

```
## Attack Chain: <name>

**Starting position:** <attacker's initial capability, e.g. "unauthenticated internet access">
**Final capability:** <what the attacker achieves, e.g. "read all customer PII records">
**Constituent vulnerabilities:** <vuln-0001>, <vuln-0003>

### Step 1 — <vuln title> (<vuln id>)
**What:** <one sentence>
**How:** <request/command that exploits it>
**Yields:** <what the attacker now has>

### Step 2 — <vuln title> (<vuln id>)
**Precondition:** uses <output from Step 1>
**What:** <one sentence>
**How:** <request/command>
**Yields:** <final impact>

### Chain CVSS Rationale
Individual scores: <vuln-0001>=X.X (<severity>), <vuln-0003>=Y.Y (<severity>)
Chain score: Z.Z (Critical) — attack vector is Network, no privileges required from
starting position, impact is full confidentiality/integrity loss.
```

## CVSS Adjustment Rules for Chains

- **Attack Vector:** use the starting attacker's position (usually Network), not the inner link's
- **Privileges Required:** use the privileges at chain entry, not mid-chain
- **User Interaction:** required only if the full chain requires it
- **Impact metrics:** reflect the final capability (C/I/A at the end state)

## Common Mistakes

- **Don't inflate severity** without a reproducible chain. If step 2 requires unlikely preconditions, note them.
- **Don't merge unrelated vulns.** A chain requires that one vulnerability's output is consumed by the next.
- **Don't skip individual reports.** The chain report supplements, not replaces, per-vuln reports.
- **Don't assume server-side state.** Confirm that the pivot (e.g., a stolen token) is actually usable across sessions.

## Checklist Before Filing a Chain

- [ ] Every individual link has its own `create_vulnerability_report`
- [ ] The chain is reproducible end-to-end in a fresh session
- [ ] The combined impact is clearly higher than any single vulnerability
- [ ] The chain title starts with `[CHAIN]`
- [ ] The CVSS reflects the attacker's starting position, not mid-chain
- [ ] Remediation addresses each link with guidance on which fix alone stops the chain
