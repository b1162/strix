---
name: final_report
description: How to write a professional penetration test final report — executive summary, methodology, ranked findings, and actionable recommendations
---

# Final Report Writing

The final report is the primary deliverable of a penetration test. It must simultaneously serve a CISO reading on a phone and a senior developer fixing code at 2 AM. Every word should be earned. Call `finish_scan` only when you are certain that every finding is filed, every chain is documented, and every section below is complete.

## Pre-Report Checklist

Before calling `finish_scan`:

- [ ] All vulnerabilities filed via `create_vulnerability_report` (including chain reports)
- [ ] Every child agent has finished (`view_agent_graph` shows no running/waiting agents)
- [ ] At least one vulnerability OR a clear "no findings" conclusion with evidence
- [ ] CVSS scores reviewed — do they reflect actual exploitability from the attacker's starting position?
- [ ] PoC evidence gathered for every Critical and High finding

## Report Sections

`finish_scan` expects four string fields. Write them as follows:

---

### `executive_summary`

**Audience:** CISO, CTO, board — people who make budget and risk decisions, not people who fix code.

**Structure (400–700 words):**

1. **Opening sentence** — overall posture in plain language: *"The assessment identified N vulnerabilities across the target surface, including X critical issues that allow [concrete bad thing]."*
2. **Most critical findings** — name the top 2-3 issues by business impact, not by CVSS number. Translate technical impact: "an unauthenticated attacker can read every customer record" rather than "SQLi in the /api/users endpoint."
3. **Root cause theme** — if multiple findings share a cause (e.g., missing input validation, over-permissioned service accounts), name it. One systemic fix beats twelve tactical patches.
4. **Risk quantification** — data exposure scope, compliance implications (GDPR, PCI-DSS, HIPAA), regulatory notification obligations if applicable.
5. **Immediate actions** — 1-3 things that must happen before the next business day (patch, disable, rotate).
6. **Positive observations** — what is working (defence-in-depth layers that forced chaining, MFA enforced, rate limiting on login). Credibility comes from balance.

**Avoid:**
- Jargon (XSS, SSRF, IDOR) without a plain-language translation in the same sentence
- Percentages without denominators
- Vague risk statements ("this could be exploited by a malicious actor")
- Repeating the methodology section

---

### `methodology`

**Audience:** technical leads, auditors, compliance reviewers.

**Structure:**

1. **Engagement type** — black-box / grey-box / white-box; authenticated or unauthenticated starting position; any agreed-upon restrictions (no DoS, read-only DB access)
2. **Scope** — list of in-scope hosts, URLs, APIs, and any explicit out-of-scope items
3. **Frameworks applied** — cite the ones actually followed:
   - OWASP Web Security Testing Guide (WSTG) v4.2
   - OWASP API Security Top 10 (2023)
   - PTES (Penetration Testing Execution Standard)
   - NIST SP 800-115
   - OSSTMM v3
4. **Phases executed** — reconnaissance → mapping → vulnerability identification → exploitation → post-exploitation → reporting
5. **Tools used** — name the primary tools (nmap, nuclei, sqlmap, ffuf, semgrep, Caido proxy, custom scripts)
6. **Limitations** — time constraints, rate limiting encountered, endpoints that could not be tested and why

---

### `technical_analysis`

**Audience:** senior developers and security engineers who will fix the issues.

**Structure:**

1. **Overview** — total findings by severity (Critical: N, High: N, Medium: N, Low: N, Info: N). State the CVSS scoring model used (CVSSv3.1).
2. **Severity model** — define what Critical/High/Medium/Low means in this context (e.g., Critical = exploitable without authentication, direct data breach or RCE)
3. **Finding categories** — group findings by CWE family or OWASP category. Show the pattern: *"5 of 12 findings stem from insufficient input validation (CWE-20), suggesting a systemic gap in the validation layer."*
4. **Systemic root causes** — identify architectural or process issues behind multiple findings. E.g., shared service accounts, missing WAF rules, absent security headers across all responses.
5. **Attack surface summary** — which areas of the application are highest risk and why (authenticated vs unauthenticated surface, third-party integrations, legacy endpoints)
6. **Exploitation difficulty** — note which findings are trivially exploitable (automated tools, public PoCs) vs requiring significant effort

---

### `recommendations`

**Audience:** developers, DevOps, and product managers who prioritize work.

**Structure — prioritised by urgency:**

**Immediate (within 24-48 hours):**
- Actions that prevent active exploitation of Critical/High findings
- E.g., disable the endpoint, rotate compromised credentials, apply emergency WAF rule
- Each item: what to do, why, estimated effort

**Short-term (within 2 weeks):**
- Targeted patches for Critical and High findings
- Specific code changes, configuration updates, or library upgrades
- Reference the vulnerability IDs: *"Fix vuln-0003 (SQL injection): use parameterised queries in `UserRepository.findById()`"*

**Medium-term (within 1-3 months):**
- Architectural fixes that address root causes across multiple findings
- Security tooling gaps (SAST in CI, dependency scanning, WAF tuning)
- Process improvements (secure code review, threat modelling for new features)

**Each recommendation must include:**
- The vulnerability ID(s) it addresses
- A concrete action (not "improve input validation" but "replace string concatenation in SQL queries with PreparedStatement")
- Estimated severity reduction (e.g., "eliminates 3 Critical and 2 High findings")
- A verification step the developer can run to confirm the fix

---

## Quality Bar

- Every Critical and High finding must appear in both the executive summary (by name) and the technical analysis
- No finding mentioned in recommendations that isn't in vulnerability reports
- No vulnerability report without a corresponding recommendation
- Chains documented in both individual and chain reports
- Total vuln count in executive summary matches the filed reports exactly

## Anti-Patterns to Avoid

| What not to write | Why |
|---|---|
| "We found several vulnerabilities" | How many? What kind? |
| "The system is vulnerable to XSS" | What page, what parameter, what impact? |
| "Implement proper security controls" | Which control, where, how? |
| CVSS 9.8 for a finding that requires auth | Over-inflation destroys credibility |
| Copy-pasted generic remediation | Shows the report wasn't read |
| Listing 40 info-level findings before critical | Buries the lead |
