---
name: email_spoofing
description: Email authentication DNS misconfiguration testing — SPF, DKIM, DMARC, MTA-STS, DANE/TLSA, BIMI; covers spoofing vectors and phishing enablement
---

# Email Spoofing via DNS Misconfiguration

Missing or weak email authentication DNS records allow attackers to send email that appears to originate from the victim's domain — enabling phishing, BEC (Business Email Compromise), and impersonation attacks.

## 1. Records to Check

| Record | Purpose | Location |
|--------|---------|----------|
| SPF (TXT) | Which IPs may send mail for this domain | `@` / root domain |
| DKIM (TXT) | Public key to verify signed email | `<selector>._domainkey.<domain>` |
| DMARC (TXT) | Policy for SPF/DKIM failures + reporting | `_dmarc.<domain>` |
| MTA-STS (TXT + HTTPS) | Enforce TLS on inbound SMTP | `_mta-sts.<domain>` + policy file |
| DANE/TLSA (TLSA) | Certificate pinning for SMTP over DNSSEC | `_25._tcp.<domain>` |
| BIMI (TXT) | Brand logo in email (requires DMARC p=quarantine/reject) | `default._bimi.<domain>` |

---

## 2. SPF (Sender Policy Framework)

```sh
# Check SPF record
dig TXT target.com +short | grep -i "v=spf1"

# Multiple TXT records starting with v=spf1 = configuration error (only one allowed)
dig TXT target.com +short | grep -c "v=spf1"
```

### SPF findings table

| Finding | Severity | Details |
|---------|----------|---------|
| No SPF record | High | Anyone can spoof the domain |
| `~all` (softfail) | Medium | Spoofed mail marked as suspicious but still delivered |
| `?all` (neutral) | High | Equivalent to no policy for DMARC alignment |
| `+all` | Critical | Explicitly allows any IP to send — worst case |
| `include:` chain > 10 DNS lookups | Medium | Causes permerror → treated as neutral by some MTA |
| Multiple SPF records | Medium | RFC 7208 §3.2: only one allowed; some MTAs use first, some fail |
| `ip4:0.0.0.0/0` or `ip6:::0/0` | Critical | Effectively `+all` |
| Unused legacy mail server IPs | Low | Expands attack surface |

```sh
# Count DNS lookups (includes, a, mx, exists, redirect = 1 each; ptr ignored)
# Quick manual count: trace all include: chains
SPF=$(dig TXT target.com +short | grep "v=spf1")
echo "$SPF"
# Recursively resolve each include: to count total lookups
```

**SPF alone is NOT sufficient** — an attacker can pass SPF by sending from their own domain and spoofing the `From:` header (only `Return-Path`/`Mail From` is checked by SPF).

---

## 3. DKIM (DomainKeys Identified Mail)

DKIM signs email headers/body with a private key; public key published in DNS.

```sh
# Common selectors to probe (guess the selector name)
for sel in default google mail dkim email s1 s2 k1 k2 selector1 selector2 \
           20210112 20230101 protonmail zoho sendgrid mailchimp; do
  result=$(dig TXT ${sel}._domainkey.target.com +short 2>/dev/null)
  [ -n "$result" ] && echo "FOUND $sel: $result"
done

# If you have a sample email, extract the 's=' value from DKIM-Signature header
# d=target.com; s=selector1 → dig TXT selector1._domainkey.target.com
```

### DKIM findings table

| Finding | Severity | Details |
|---------|----------|---------|
| No DKIM records found for known selectors | Medium | Hard to confirm without a real email sample |
| RSA key < 1024 bits | High | Practically factorable |
| RSA key = 1024 bits | Medium | Should rotate to 2048+ |
| `p=` empty | Medium | Key revoked, signing will fail |
| `t=y` flag present | Low | Testing mode — DKIM failures ignored |
| No rotation evidence (single old selector) | Low | Stale key risk if private key compromised |

```sh
# Extract key length from TXT record
dig TXT selector1._domainkey.target.com +short \
  | grep -oP '(?<=p=)[A-Za-z0-9+/=]+' \
  | base64 -d 2>/dev/null \
  | openssl pkey -pubin -inform DER -text -noout 2>/dev/null \
  | grep "bit"
# Or: openssl rsa -pubin -inform DER -text -noout
```

---

## 4. DMARC (Domain-based Message Authentication, Reporting and Conformance)

DMARC ties SPF + DKIM together and specifies what to do when both fail.

```sh
# Check DMARC record
dig TXT _dmarc.target.com +short

# Organizational domain (if subdomain)
dig TXT _dmarc.example.com +short   # parent org domain applies to all subdomains by default

# Check subdomain policy override
dig TXT _dmarc.mail.target.com +short
```

### DMARC findings table

| Finding | Severity | Details |
|---------|----------|---------|
| No DMARC record | High | Domain fully spoofable regardless of SPF/DKIM |
| `p=none` + no `rua`/`ruf` | High | No enforcement and no visibility into abuse |
| `p=none` + `rua` present | Medium | Monitoring only — emails still delivered |
| `p=quarantine` | Low | Spoofed mail goes to spam — acceptable interim |
| `p=reject` | Pass | Full enforcement |
| `pct=` < 100 with `p=reject` | Low | Partial enforcement; increase pct gradually |
| `sp=none` on org domain | Medium | Subdomain policy overrides parent reject |
| `adkim=r` (relaxed) without SPF alignment concern | Info | Relaxed DKIM allows subdomain signing |
| `aspf=r` + no SPF for subdomains | Medium | Subdomains can spoof parent in relaxed mode |

**DMARC identifier alignment:**
- SPF alignment: `Return-Path` domain must match `From:` domain
- DKIM alignment: `d=` in DKIM-Signature must match `From:` domain
- Relaxed alignment: organizational domain match is sufficient

```sh
# Full email auth check (requires swaks or mxtoolbox approach)
# Quick: use online tool output for evidence
# Manual: send a test email and check Received/Authentication-Results headers
```

---

## 5. Subdomain Spoofing

Even with strong DMARC on the root domain, subdomains may be unprotected:

```sh
# Check if subdomain has its own DMARC
dig TXT _dmarc.sub.target.com +short

# No result → falls back to org-domain DMARC
# But if org-domain DMARC has sp=none → subdomain is unprotected
dig TXT _dmarc.target.com +short | grep -oP '(?<=sp=)\w+'

# Enumerate sending subdomains that might not have SPF/DMARC
# e.g. marketing.target.com, news.target.com, noreply.target.com
for sub in mail newsletter news marketing noreply notify alerts billing; do
  spf=$(dig TXT ${sub}.target.com +short | grep "v=spf1")
  dmarc=$(dig TXT _dmarc.${sub}.target.com +short | grep "v=DMARC1")
  echo "$sub: SPF='$spf' DMARC='$dmarc'"
done
```

---

## 6. MTA-STS (Mail Transfer Agent Strict Transport Security)

MTA-STS enforces TLS for inbound SMTP — prevents downgrade and MITM attacks on mail delivery.

```sh
# Check MTA-STS DNS record
dig TXT _mta-sts.target.com +short
# Expected: "v=STSv1; id=YYYYMMDDHHMMSS"

# Fetch policy file
curl -s https://mta-sts.target.com/.well-known/mta-sts.txt
# Expected fields: version, mode (enforce/testing/none), mx, max_age
```

### MTA-STS findings

| Finding | Severity |
|---------|----------|
| No MTA-STS record | Low–Medium |
| `mode=none` | Low |
| `mode=testing` | Info |
| `mode=enforce` + valid MX entries | Pass |
| Policy file unreachable (404/503) | Medium |
| Short `max_age` < 604800 (1 week) | Low |

---

## 7. DANE / TLSA

DANE pins TLS certificates for SMTP via DNSSEC-authenticated TLSA records. Requires DNSSEC.

```sh
# Check for TLSA record on port 25
dig TLSA _25._tcp.mail.target.com +short

# Check for STARTTLS on port 25
openssl s_client -connect mail.target.com:25 -starttls smtp 2>&1 | \
  grep -E 'subject|issuer|Verify'
```

Missing DANE is Low severity unless DNSSEC is deployed (then Medium — inconsistency).

---

## 8. Spoofing Proof of Concept

With authorization, demonstrate spoofing ability using `swaks`:

```sh
# Install
apt-get install -y swaks

# Test spoofing (no auth — relies on permissive relay or direct MX connection)
swaks --to victim@example.com \
      --from ceo@target.com \
      --server mail.target.com \
      --header-X-Mailer "Test" \
      --body "This is a spoofing test."

# Direct-to-MX spoof attempt (bypasses SPF for From: spoofing check)
MX=$(dig MX target.com +short | sort -n | head -1 | awk '{print $2}')
swaks --to victim@example.com \
      --from admin@target.com \
      --server $MX \
      --port 25
```

**Do not send to real victim addresses.** Use controlled test mailboxes. Check `Authentication-Results` header in received test emails to confirm SPF/DKIM/DMARC pass/fail status.

---

## 9. Testing Checklist

```sh
# Full automated check
domain="target.com"

echo "=== SPF ===" && dig TXT $domain +short | grep "v=spf1"
echo "=== DMARC ===" && dig TXT _dmarc.$domain +short
echo "=== MTA-STS ===" && dig TXT _mta-sts.$domain +short
echo "=== CAA ===" && dig CAA $domain +short
echo "=== MX ===" && dig MX $domain +short
echo "=== TLSA ===" && dig TLSA _25._tcp.mail.$domain +short

# DKIM: probe common selectors
for sel in default google mail dkim s1 s2 selector1 selector2; do
  r=$(dig TXT ${sel}._domainkey.$domain +short 2>/dev/null)
  [ -n "$r" ] && echo "DKIM $sel: $r"
done

# Subdomain DMARC
echo "=== org-domain sp= tag ===" && dig TXT _dmarc.$domain +short | grep -o 'sp=[^;]*'
```

### Nuclei email security templates
```sh
nuclei -u $domain -tags email,spf,dkim,dmarc -silent -j
```

---

## 10. Severity Scoring

| Scenario | Severity | CVSS approx |
|----------|----------|-------------|
| No SPF + No DMARC | Critical | 9.1 |
| SPF `+all` or missing DMARC | Critical | 9.1 |
| DMARC `p=none`, no monitoring | High | 7.5 |
| DMARC `p=quarantine` | Medium | 5.3 |
| SPF `~all` without DMARC | High | 7.5 |
| Subdomain spoofable (`sp=none`) | High | 7.5 |
| DKIM weak key (1024-bit) | Medium | 5.9 |
| No MTA-STS | Low | 3.7 |

---

## 11. Remediation Guidance

**SPF:**
- Use `~all` minimum, `−all` preferred
- Keep DNS lookups ≤ 10 (use `ip4:`/`ip6:` instead of chained `include:` where possible)
- One record per domain; use SPF flattening tools for complex environments

**DKIM:**
- Minimum 2048-bit RSA keys (or Ed25519)
- Rotate keys at least annually; keep old selector active for 48h post-rotation
- Remove `t=y` testing flag in production

**DMARC:**
- Start with `p=none; rua=mailto:dmarc@yourdomain.com` for 30 days of visibility
- Escalate to `p=quarantine; pct=10`, gradually to `p=reject; pct=100`
- Set `sp=reject` to protect subdomains
- Use strict alignment (`adkim=s; aspf=s`) when possible

**MTA-STS:**
- Deploy `mode=enforce` with all active MX hosts listed
- Set `max_age=604800` minimum; `31557600` (1 year) recommended

## 12. Report Chain

After confirming spoofing ability, file:
1. `create_vulnerability_report` for each misconfigured record (SPF, DKIM, DMARC separately)
2. If the combination allows full spoofing (no DMARC + weak SPF), use the `vuln_chain` skill to file a `[CHAIN]` report: "Email Spoofing Chain: Missing SPF/DMARC → Domain Impersonation → Phishing / BEC"
