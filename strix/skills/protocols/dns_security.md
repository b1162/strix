---
name: dns_security
description: DNS security testing — zone transfers, DNSSEC validation, cache poisoning, DNS rebinding, tunneling detection, wildcard abuse, and DNS reconnaissance
---

# DNS Security Testing

## 1. Attack Surface

| Category | What to Test |
|----------|-------------|
| Zone transfer (AXFR/IXFR) | Full zone dump without auth |
| Record enumeration | A, AAAA, CNAME, MX, NS, TXT, SRV, PTR brute-force |
| DNSSEC | Missing, broken, or downgrade-able validation |
| DNS rebinding | TTL / IP change trick to bypass SOP |
| Cache poisoning | Predictable TxID / source port (Kaminsky-style) |
| DNS tunneling | Data exfiltration over DNS queries |
| Wildcard records | Excessive *.domain catch-alls |
| Recursive resolvers | Open resolver abuse, amplification |
| Internal DNS | Split-horizon leakage, internal hostnames via AXFR |

---

## 2. DNS Reconnaissance

### Record enumeration

```sh
# All standard record types for a domain
dig ANY target.com +noall +answer 2>/dev/null || true
for type in A AAAA CNAME MX NS TXT SOA SRV CAA DMARC TLSA; do
  dig $type target.com +short | sed "s/^/$type: /"
done

# SOA — serial, primary NS, email, TTL parameters
dig SOA target.com +short

# Name server list
dig NS target.com +short

# Mail servers
dig MX target.com +short
```

### Reverse DNS / PTR
```sh
# Single IP
dig -x 192.168.1.1 +short

# PTR sweep over a /24 using dnsx
seq 1 254 | xargs -I{} dig +short -x 192.168.1.{} | grep -v '^$'
# Or: echo "192.168.1.0/24" | dnsx -ptr -resp-only
```

### SRV record discovery (internal services)
```sh
for svc in _ldap._tcp _kerberos._tcp _kerberos._udp _kpasswd._tcp \
           _gc._tcp _msdcs._tcp _autodiscover._tcp _sip._tls \
           _sipfederationtls._tcp _xmpp-server._tcp _http._tcp _https._tcp; do
  result=$(dig SRV ${svc}.target.com +short)
  [ -n "$result" ] && echo "$svc: $result"
done
```

### CAA records (Certificate Authority Authorization)
```sh
dig CAA target.com +short
# Missing CAA = any CA can issue certs for the domain
# Overly broad: "0 issue \";\""  (no CA allowed but not enforced)
```

---

## 3. Zone Transfer (AXFR / IXFR)

A successful zone transfer dumps the entire DNS zone — all hostnames, IPs, internal services.

```sh
# Attempt AXFR against each nameserver
for ns in $(dig NS target.com +short); do
  echo "=== Trying AXFR from $ns ==="
  dig AXFR target.com @$ns
done

# With host command
host -l target.com ns1.target.com

# dnsrecon automated
dnsrecon -d target.com -t axfr

# fierce (zone transfer + brute)
fierce --domain target.com
```

**Impact if successful:** Full host inventory, internal IPs, sensitive subdomains (vpn, mail, internal-app, dev, staging), service discovery.

**Expected secure response:** `Transfer failed` or `REFUSED`. Any `ANSWER` section with multiple A/CNAME records is a confirmed vulnerability.

**How to file:** `create_vulnerability_report` with severity HIGH, attach raw AXFR output as PoC.

---

## 4. DNSSEC Validation

DNSSEC signs zone data; missing or broken signing enables spoofing attacks.

```sh
# Check if DNSSEC is enabled (DS record at parent)
dig DS target.com +short
dig DS target.com @8.8.8.8 +short

# Fetch DNSKEY (zone signing keys)
dig DNSKEY target.com +short

# Full DNSSEC chain validation
dig +dnssec +sigchase target.com A @8.8.8.8 2>/dev/null
# Or use delv (ships with bind9-utils)
delv @8.8.8.8 target.com A +rtrace 2>&1 | grep -E 'fully|failed|bogus|insecure'

# Check NSEC/NSEC3 (zone enumeration resistance)
dig NSEC target.com +dnssec
dig NSEC3PARAM target.com +short   # present = NSEC3 used (harder to enumerate)
```

**Findings to report:**

| Finding | Severity |
|---------|----------|
| No DS record → DNSSEC not deployed | Medium |
| DS present but DNSKEY missing → broken chain | High |
| `delv` returns "validation failed" or "bogus" | Critical |
| NSEC without NSEC3 → zone walking possible | Low–Medium |
| Weak algorithm (RSA-1024, MD5) | High |

**NSEC zone walking** (enumerate all names without brute force):
```sh
# If NSEC (not NSEC3), next name is disclosed in each denial response
ldns-walk target.com
# Or dnsx with NSEC walk support
```

---

## 5. DNS Cache Poisoning Assessment

Modern caches randomize source ports + TxIDs (Kaminsky patch). Assess the resolver:

```sh
# Check if resolver is open (accepts queries from anywhere)
dig +short @RESOLVER_IP target.com

# Port randomization check via CAIDA spoofer (need external test)
# Alternatively check via dns-oarc.net porttest
dig +short porttest.dns-oarc.net TXT @RESOLVER_IP

# Example good output: "GOOD ... source port randomness looks good"
# Bad output: "POOR" or fixed port
```

**Predictability indicators:**
- Fixed source port (53 → 53 or low ephemeral range)
- Sequential TxIDs (increment by 1)
- No 0x20 encoding (case randomization)

```sh
# 0x20 encoding check: does resolver preserve mixed-case queries?
dig TeSt.TaRgEt.CoM @RESOLVER_IP
# If answer QNAME is lowercased → no 0x20, marginally more poisonable
```

---

## 6. DNS Rebinding

DNS rebinding tricks a browser into making cross-origin requests to an internal service by returning a short-TTL external IP first, then switching to an internal IP.

**Attack scenario:**
1. Attacker controls `evil.com` NS and sets TTL=0
2. Victim visits `http://evil.com` → browser caches external IP
3. After TTL expires, attacker returns `192.168.1.1` (internal)
4. Browser same-origin check passes (still `evil.com`)
5. JS makes requests to internal services at `192.168.1.1`

**Testing indicators on target:**
```sh
# Check if any internal/private IPs leak via any record type
dig A target.com +short | grep -E '^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)'

# Check minimum TTL (very low TTL enables rebinding)
dig SOA target.com +short | awk '{print "Minimum TTL:", $7}'
dig A target.com +short +ttl | awk '{print "A TTL:", $1}'
# TTL < 60 for externally-facing records is a rebinding enabler
```

**Mitigations to check on web servers:**
- `Host` header validation (reject non-allowlisted hosts)
- DNS rebinding protection in local services (Home Assistant, Plex, Jenkins)

**Testing internal service rebinding exposure:** If the target runs a local HTTP service with no Host validation, it's vulnerable. Confirm by sending requests with unexpected `Host` values.

---

## 7. DNS Tunneling Detection

DNS tunneling exfiltrates data by encoding it in subdomain labels of DNS queries.

**Indicators of tunneling traffic:**
- Long subdomain labels (>40 chars per label)
- High entropy base32/base64 subdomains
- Unusually high TXT query volume
- Many unique subdomains under the same parent
- High bytes-per-query ratio
- Regular-interval queries (heartbeat pattern)

**Detection on a captured PCAP:**
```sh
# Extract unique DNS query names
tshark -r capture.pcap -Y dns.qry.type==1 -T fields -e dns.qry.name \
  | sort | uniq -c | sort -rn | head -50

# Flag long labels
tshark -r capture.pcap -Y dns.qry.type==1 -T fields -e dns.qry.name \
  | awk -F. '{for(i=1;i<=NF;i++) if(length($i)>40) print}' | sort -u

# High-entropy labels (Shannon entropy proxy via length + charset)
# Labels with >30 chars of hex/base32 chars are suspicious
```

**Testing a specific domain for tunneling capability:**
```sh
# Check if long TXT queries resolve (used for tunnel C2)
dig TXT "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.target.com" +short
# NXDOMAIN = probably no tunnel; response = investigate

# iodine, dnscat2 detection fingerprints:
# iodine: NULL/CNAME query types, specific version exchange in first query
# dnscat2: TXT queries, sequential subdomains with incrementing IDs
```

---

## 8. Open Recursive Resolver

An open resolver answers queries from any IP — usable for DDoS amplification.

```sh
# Test if resolver is open (resolve an external name)
dig +short @TARGET_IP google.com
# If you get an answer: open resolver confirmed

# Amplification factor estimate
dig ANY isc.org @TARGET_IP | wc -c      # response size
echo "35" | wc -c                         # query size ~35 bytes
# Amplification factor = response / query
```

**Report open resolver as Medium–High** depending on amplification factor (ANY queries can yield 40-70x).

---

## 9. Wildcard DNS Abuse

```sh
# Check for wildcard A record
dig RANDOM123NOTEXIST.target.com +short
# If returns an IP: wildcard exists

# Check for wildcard CNAME
dig RANDOM456.target.com CNAME +short

# Wildcard implications:
# - Enables arbitrary subdomain takeover of HTTP services that accept all Host headers
# - May bypass HSTS subdomain scope
# - Can hide phishing infrastructure under trusted domain
```

---

## 10. Testing Methodology

1. **SOA + NS mapping** — Identify all authoritative nameservers and zone parameters
2. **Zone transfer attempt** — AXFR/IXFR against every NS; file immediately if successful
3. **DNSSEC chain validation** — `delv` + DS/DNSKEY presence check
4. **Record sweep** — ALL types including CAA, SRV, DMARC; build full host inventory
5. **Open resolver check** — External query test + amplification factor
6. **TTL analysis** — Flag suspiciously low TTLs on public-facing records
7. **NSEC zone walking** — If no NSEC3, attempt ldns-walk enumeration
8. **Wildcard check** — Random subdomain probe
9. **Tunneling scan** — If PCAP available or DNS logs accessible
10. **Internal hostname leakage** — Crosscheck AXFR/PTR results for private IP ranges

## 11. Key Tools

| Tool | Purpose | Install |
|------|---------|---------|
| `dig` | Manual DNS queries | apt install dnsutils |
| `host` | Simple lookups + AXFR | apt install dnsutils |
| `dnsrecon` | Automated enumeration | apt install dnsrecon |
| `fierce` | Zone transfer + brute | pip install fierce |
| `dnsx` | Fast multi-type resolver | go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest |
| `ldns-walk` | NSEC zone walking | apt install ldnsutils |
| `delv` | DNSSEC validation | apt install bind9-utils |
| `subfinder` | Passive subdomain enum | already in sandbox |
| `nuclei` | DNS template checks | already in sandbox |

```sh
# One-liner recon sweep (uses tools available in sandbox)
subfinder -d target.com -silent | dnsx -a -aaaa -cname -mx -ns -txt -resp -silent
```
