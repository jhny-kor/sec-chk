"""Live website security posture checks using only the Python standard library.

This is the lightweight, dependency-free counterpart to the Docker/OWASP-ZAP
path in ``dast.py``. Given an authorized URL it sends a small number of
**non-destructive** requests (a single GET plus one TLS handshake) and inspects
the response: security headers, TLS/certificate posture, cookie flags, HTTP to
HTTPS enforcement, information disclosure, and CORS misconfiguration.

It never sends attack payloads, never fuzzes, and only reads what the server
already returns. Run it only against systems you own or are authorized to test.
The analysis helpers (``analyze_response``/``check_tls``) are separated from the
network fetch so they can be unit tested without a live server.
"""

from __future__ import annotations

import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime, timezone
from pathlib import Path

from .models import Finding

_USER_AGENT = "KODA-web-scanner (+https://github.com/jhny-kor/koda)"
# Certificates expiring within this window are surfaced before they break TLS.
_CERT_EXPIRY_WARN_DAYS = 21
_WEAK_TLS_VERSIONS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}


def check_web(url: str, *, timeout: float = 15.0) -> tuple[list[Finding], list[str]]:
    """Run all live web checks against ``url``.

    Returns ``(findings, warnings)``. Network failures degrade to a warning (and,
    for a TLS handshake failure, a finding) instead of raising, so one broken
    probe never aborts the scan.
    """

    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return [], [f"Web scan skipped: not an http(s) URL: {url}"]

    target = parsed.netloc
    warnings: list[str] = []

    request = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT}, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            final_url = response.geturl()
            header_items = list(response.headers.items())
            set_cookies = response.headers.get_all("Set-Cookie") or []
    except urllib.error.HTTPError as exc:
        # An error status still carries the response headers we want to inspect.
        final_url = url
        header_items = list(exc.headers.items()) if exc.headers else []
        set_cookies = exc.headers.get_all("Set-Cookie") if exc.headers else []
    except (urllib.error.URLError, ssl.SSLError, socket.timeout, OSError) as exc:
        reason = getattr(exc, "reason", exc)
        return (
            [
                _finding(
                    "web.connection-failed",
                    "info",
                    "Website could not be reached",
                    url,
                    target=target,
                    evidence=str(reason),
                    recommendation="Confirm the URL, that the service is running, and that TLS is valid.",
                )
            ],
            [f"Web scan could not reach {url}: {reason}"],
        )

    findings = analyze_response(final_url, header_items, set_cookies, target=target)

    if parsed.scheme == "http" and urllib.parse.urlparse(final_url).scheme != "https":
        findings.append(
            _finding(
                "web.no-https-redirect",
                "medium",
                "HTTP is not redirected to HTTPS",
                final_url,
                target=target,
                evidence=f"GET {url} did not upgrade to https (final URL {final_url}).",
                recommendation="Redirect all HTTP traffic to HTTPS and serve HSTS on the HTTPS response.",
            )
        )

    final = urllib.parse.urlparse(final_url)
    if final.scheme == "https" and final.hostname:
        tls_findings, tls_warnings = check_tls(
            final.hostname, final.port or 443, timeout=timeout, target=target, url=final_url
        )
        findings.extend(tls_findings)
        warnings.extend(tls_warnings)

    findings.sort(key=lambda finding: finding.sort_key())
    return findings, warnings


def analyze_response(
    url: str,
    headers: Mapping[str, str] | Iterable[tuple[str, str]],
    set_cookies: Sequence[str] = (),
    *,
    target: str = "",
) -> list[Finding]:
    """Analyze already-fetched response headers/cookies (no network).

    ``headers`` may be a mapping or an iterable of ``(name, value)`` pairs, as
    returned by ``http.client.HTTPMessage.items()``.
    """

    lowered = _lower_headers(headers)
    is_https = urllib.parse.urlparse(url).scheme == "https"
    findings: list[Finding] = []
    findings.extend(_security_headers(url, lowered, is_https, target))
    findings.extend(_cookie_flags(url, set_cookies, is_https, target))
    findings.extend(_information_disclosure(url, lowered, target))
    findings.extend(_cors(url, lowered, target))
    return findings


def check_tls(
    host: str,
    port: int = 443,
    *,
    timeout: float = 15.0,
    target: str = "",
    url: str = "",
) -> tuple[list[Finding], list[str]]:
    """Inspect certificate expiry and negotiated protocol via one TLS handshake."""

    location = url or f"https://{host}"
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
                version = tls.version() or ""
    except ssl.SSLCertVerificationError as exc:
        return (
            [
                _finding(
                    "web.tls-certificate-invalid",
                    "high",
                    "TLS certificate did not validate",
                    location,
                    target=target,
                    evidence=str(exc),
                    recommendation="Install a valid certificate chain trusted for this hostname.",
                )
            ],
            [],
        )
    except (ssl.SSLError, socket.timeout, OSError) as exc:
        return [], [f"TLS check could not complete for {host}:{port}: {exc}"]

    findings: list[Finding] = []
    findings.extend(_certificate_expiry(location, cert, target))
    if version in _WEAK_TLS_VERSIONS:
        findings.append(
            _finding(
                "web.weak-tls-version",
                "medium",
                f"Server negotiated a weak TLS version ({version})",
                location,
                target=target,
                evidence=f"Negotiated protocol: {version}",
                recommendation="Disable TLS 1.1 and earlier; require TLS 1.2 or TLS 1.3.",
            )
        )
    return findings, []


# --- analysis helpers -------------------------------------------------------


def _security_headers(url: str, headers: dict[str, str], is_https: bool, target: str) -> list[Finding]:
    findings: list[Finding] = []
    csp = headers.get("content-security-policy", "")

    if is_https and "strict-transport-security" not in headers:
        findings.append(
            _finding(
                "web.missing-hsts",
                "medium",
                "Missing HTTP Strict-Transport-Security (HSTS) header",
                url,
                target=target,
                recommendation="Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.",
            )
        )
    if not csp:
        findings.append(
            _finding(
                "web.missing-csp",
                "medium",
                "Missing Content-Security-Policy header",
                url,
                target=target,
                recommendation="Define a Content-Security-Policy to limit script/style/connect sources.",
            )
        )
    if headers.get("x-content-type-options", "").lower() != "nosniff":
        findings.append(
            _finding(
                "web.missing-x-content-type-options",
                "low",
                "Missing 'X-Content-Type-Options: nosniff' header",
                url,
                target=target,
                recommendation="Send 'X-Content-Type-Options: nosniff' to stop MIME sniffing.",
            )
        )
    if "x-frame-options" not in headers and "frame-ancestors" not in csp.lower():
        findings.append(
            _finding(
                "web.missing-frame-protection",
                "medium",
                "Missing clickjacking protection (X-Frame-Options / frame-ancestors)",
                url,
                target=target,
                recommendation="Send 'X-Frame-Options: DENY' or a CSP 'frame-ancestors' directive.",
            )
        )
    if "referrer-policy" not in headers:
        findings.append(
            _finding(
                "web.missing-referrer-policy",
                "low",
                "Missing Referrer-Policy header",
                url,
                target=target,
                recommendation="Send a Referrer-Policy such as 'strict-origin-when-cross-origin'.",
            )
        )
    if "permissions-policy" not in headers:
        findings.append(
            _finding(
                "web.missing-permissions-policy",
                "info",
                "Missing Permissions-Policy header",
                url,
                target=target,
                recommendation="Send a Permissions-Policy to restrict powerful browser features.",
            )
        )
    return findings


def _cookie_flags(url: str, set_cookies: Sequence[str], is_https: bool, target: str) -> list[Finding]:
    if not set_cookies:
        return []
    missing_secure: list[str] = []
    missing_httponly: list[str] = []
    missing_samesite: list[str] = []
    for raw in set_cookies:
        name = raw.split("=", 1)[0].strip() or "(unnamed)"
        attributes = {part.strip().lower() for part in raw.split(";")[1:]}
        has_secure = "secure" in attributes
        has_httponly = "httponly" in attributes
        has_samesite = any(attr.startswith("samesite") for attr in attributes)
        if is_https and not has_secure:
            missing_secure.append(name)
        if not has_httponly:
            missing_httponly.append(name)
        if not has_samesite:
            missing_samesite.append(name)

    findings: list[Finding] = []
    if missing_secure:
        findings.append(
            _finding(
                "web.cookie-missing-secure",
                "medium",
                "Cookie set without the Secure flag over HTTPS",
                url,
                target=target,
                evidence=f"Cookies: {', '.join(missing_secure)}",
                recommendation="Add the 'Secure' attribute so cookies are only sent over HTTPS.",
            )
        )
    if missing_httponly:
        findings.append(
            _finding(
                "web.cookie-missing-httponly",
                "low",
                "Cookie set without the HttpOnly flag",
                url,
                target=target,
                evidence=f"Cookies: {', '.join(missing_httponly)}",
                recommendation="Add 'HttpOnly' to keep cookies out of reach of JavaScript.",
            )
        )
    if missing_samesite:
        findings.append(
            _finding(
                "web.cookie-missing-samesite",
                "low",
                "Cookie set without a SameSite attribute",
                url,
                target=target,
                evidence=f"Cookies: {', '.join(missing_samesite)}",
                recommendation="Add 'SameSite=Lax' or 'SameSite=Strict' to reduce CSRF exposure.",
            )
        )
    return findings


def _information_disclosure(url: str, headers: dict[str, str], target: str) -> list[Finding]:
    findings: list[Finding] = []
    server = headers.get("server", "")
    if server and any(char.isdigit() for char in server):
        findings.append(
            _finding(
                "web.server-version-disclosure",
                "low",
                "Server header discloses software version",
                url,
                target=target,
                evidence=f"Server: {server}",
                recommendation="Suppress or generalize the 'Server' header so it omits version details.",
            )
        )
    powered_by = headers.get("x-powered-by", "")
    if powered_by:
        findings.append(
            _finding(
                "web.x-powered-by-disclosure",
                "low",
                "X-Powered-By header discloses technology stack",
                url,
                target=target,
                evidence=f"X-Powered-By: {powered_by}",
                recommendation="Remove the 'X-Powered-By' header.",
            )
        )
    return findings


def _cors(url: str, headers: dict[str, str], target: str) -> list[Finding]:
    origin = headers.get("access-control-allow-origin", "").strip()
    if origin != "*":
        return []
    credentials = headers.get("access-control-allow-credentials", "").strip().lower() == "true"
    if credentials:
        return [
            _finding(
                "web.cors-wildcard-credentials",
                "high",
                "CORS allows any origin together with credentials",
                url,
                target=target,
                evidence="Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true",
                recommendation="Never combine a wildcard origin with credentials; echo an explicit allowlisted origin.",
            )
        ]
    return [
        _finding(
            "web.cors-wildcard",
            "low",
            "CORS allows any origin (Access-Control-Allow-Origin: *)",
            url,
            target=target,
            evidence="Access-Control-Allow-Origin: *",
            recommendation="Restrict CORS to the specific origins that need cross-site access.",
        )
    ]


def _certificate_expiry(url: str, cert: Mapping[str, object] | None, target: str) -> list[Finding]:
    if not cert:
        # Verified connection but no cert detail (rare); nothing actionable to report.
        return []
    not_after = cert.get("notAfter")
    if not isinstance(not_after, str):
        return []
    try:
        expires = datetime.fromtimestamp(ssl.cert_time_to_seconds(not_after), tz=timezone.utc)
    except ValueError:
        return []
    days_left = (expires - datetime.now(timezone.utc)).days
    if days_left < 0:
        return [
            _finding(
                "web.tls-certificate-expired",
                "critical",
                "TLS certificate has expired",
                url,
                target=target,
                evidence=f"notAfter: {not_after}",
                recommendation="Renew and deploy a valid certificate immediately.",
            )
        ]
    if days_left <= _CERT_EXPIRY_WARN_DAYS:
        return [
            _finding(
                "web.tls-certificate-expiring",
                "medium",
                f"TLS certificate expires in {days_left} day(s)",
                url,
                target=target,
                evidence=f"notAfter: {not_after}",
                recommendation="Renew the certificate before it expires and automate renewal.",
            )
        ]
    return []


def _lower_headers(headers: Mapping[str, str] | Iterable[tuple[str, str]]) -> dict[str, str]:
    items = headers.items() if isinstance(headers, Mapping) else headers
    lowered: dict[str, str] = {}
    for name, value in items:
        key = name.lower()
        # Preserve the first value; join duplicates so evidence stays informative.
        lowered[key] = f"{lowered[key]}, {value}" if key in lowered else value
    return lowered


def _finding(
    rule_id: str,
    severity: str,
    title: str,
    url: str,
    *,
    target: str = "",
    evidence: str = "",
    recommendation: str = "",
) -> Finding:
    return Finding(
        rule_id=rule_id,
        category="web",
        severity=severity,
        title=title,
        path=Path(url),
        target=target,
        evidence=evidence,
        description="Live web posture check (non-destructive HTTP/TLS inspection).",
        recommendation=recommendation,
    )
