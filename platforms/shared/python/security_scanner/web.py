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

import http.cookiejar
import os
import re
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import deque
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import replace
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path

from .models import Finding

_USER_AGENT = "KODA-web-scanner (+https://github.com/jhny-kor/koda)"
# Certificates expiring within this window are surfaced before they break TLS.
_CERT_EXPIRY_WARN_DAYS = 21
_WEAK_TLS_VERSIONS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
# Only parse HTML bodies below this size for links (crawl); larger responses are
# still analyzed for headers but not followed.
_MAX_BODY_BYTES = 2 * 1024 * 1024
_USER_FIELD_RE = re.compile(r"user|email|login|\bid\b|userid|username", re.IGNORECASE)
_PASS_FIELD_RE = re.compile(r"pass|pwd", re.IGNORECASE)


def check_web(
    url: str,
    *,
    timeout: float = 15.0,
    opener: urllib.request.OpenerDirector | None = None,
    extra_headers: Mapping[str, str] | None = None,
) -> tuple[list[Finding], list[str]]:
    """Run all live web checks against a single ``url``.

    Returns ``(findings, warnings)``. Thin wrapper over :func:`crawl_web` with a
    one-page budget, so single-page behaviour and crawl share one code path.
    """

    findings, warnings, _ = crawl_web(
        url,
        timeout=timeout,
        max_pages=1,
        max_depth=0,
        delay=0.0,
        opener=opener,
        extra_headers=extra_headers,
    )
    return findings, warnings


def crawl_web(
    seed_url: str,
    *,
    timeout: float = 15.0,
    max_pages: int = 50,
    max_depth: int = 3,
    delay: float = 0.3,
    opener: urllib.request.OpenerDirector | None = None,
    extra_headers: Mapping[str, str] | None = None,
    render: bool = False,
    seeds: Sequence[str] = (),
    discover_assets: bool = False,
    capture_network: bool = False,
    interact: bool = False,
    max_clicks: int = 20,
    max_assets: int = 20,
    scan_js_secrets: bool = False,
    ingest_sitemap: bool = False,
    probe_paths: bool = False,
) -> tuple[list[Finding], list[str], int]:
    """Crawl same-host pages from ``seed_url`` and run web checks on each.

    Breadth-first over links that stay on the seed's host, bounded by
    ``max_pages`` and ``max_depth`` with a ``delay`` between requests. Header,
    cookie and CORS checks run per page; TLS is checked once per host. Findings
    that repeat across pages (e.g. a missing CSP header) are collapsed to one
    representative each. Returns ``(findings, warnings, pages_scanned)``.

    Link discovery combines several sources so JavaScript-heavy apps (SPAs) that
    expose no ``<a href>`` links are still reached:

    - ``render``: load each page in a headless browser (Playwright extra) to see
      JS-rendered anchors.
    - ``capture_network``: while rendering, record same-host URLs the page
      fetches (its API/route surface). Requires ``render``.
    - ``interact``: while rendering, click bounded candidate elements and record
      routes they navigate to (``max_clicks`` cap). Requires ``render``.
    - ``discover_assets``: fetch the page's same-host JS bundles and extract
      path-like route/endpoint strings (``max_assets`` cap). Works without a
      browser.
    - ``seeds``: extra same-host URLs to enqueue up front (known routes, a
      sitemap dump, an OpenAPI path list).
    - ``scan_js_secrets``: scan fetched same-host JS bundles for leaked secrets
      (API keys, tokens) using the shared secret rules.
    - ``ingest_sitemap``: read ``/robots.txt`` and ``/sitemap.xml`` and enqueue
      the same-host URLs (and Disallow paths) they list.
    - ``probe_paths``: probe a fixed list of well-known sensitive paths
      (``/.env``, ``/.git/config``, ``/openapi.json`` …) and flag exposed ones,
      guarding against SPA catch-all 200s.

    Falls back to stdlib link extraction with a one-time warning when the
    browser-based options are requested but Playwright is unavailable.
    """

    parsed = urllib.parse.urlparse(seed_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return [], [f"Web scan skipped: not an http(s) URL: {seed_url}"], 0

    target = parsed.netloc
    if opener is None:
        opener = urllib.request.build_opener()
    headers = {"User-Agent": _USER_AGENT}
    if extra_headers:
        headers.update(extra_headers)

    warnings: list[str] = []
    collected: list[Finding] = []
    tls_checked_hosts: set[str] = set()
    visited: set[str] = set()
    queue: deque[tuple[str, int]] = deque([(seed_url, 0)])
    # E: enqueue caller-supplied same-host seeds (known routes / sitemap / API paths).
    for seed in seeds:
        absolute = urllib.parse.urljoin(seed_url, seed)
        if _same_host(seed_url, absolute):
            queue.append((absolute, 0))
    pages_scanned = 0
    render_warned = False
    assets_seen: set[str] = set()  # A: JS bundles already scraped (global budget)

    if ingest_sitemap:
        for url in _ingest_sitemaps(seed_url, opener, headers, timeout):
            if _same_host(seed_url, url):
                queue.append((url, 0))
    if probe_paths:
        collected.extend(_probe_sensitive_paths(seed_url, opener, headers, timeout, target))

    while queue and pages_scanned < max_pages:
        current, depth = queue.popleft()
        canonical = _canonical(current)
        if canonical in visited:
            continue
        visited.add(canonical)

        if pages_scanned and delay:
            time.sleep(delay)

        fetched = _fetch(opener, current, headers, timeout)
        if fetched is None:
            # Only the seed's unreachability is worth a finding; sub-pages degrade
            # to a warning so one dead link never dominates the report.
            if pages_scanned == 0:
                collected.append(
                    _finding(
                        "web.connection-failed",
                        "info",
                        "Website could not be reached",
                        current,
                        target=target,
                        evidence="request failed",
                        recommendation="Confirm the URL, that the service is running, and that TLS is valid.",
                    )
                )
            warnings.append(f"Web scan could not reach {current}")
            continue

        final_url, header_items, set_cookies, body = fetched
        pages_scanned += 1

        collected.extend(analyze_response(final_url, header_items, set_cookies, target=target))

        if urllib.parse.urlparse(current).scheme == "http" and urllib.parse.urlparse(final_url).scheme != "https":
            collected.append(
                _finding(
                    "web.no-https-redirect",
                    "medium",
                    "HTTP is not redirected to HTTPS",
                    final_url,
                    target=target,
                    evidence=f"GET {current} did not upgrade to https (final URL {final_url}).",
                    recommendation="Redirect all HTTP traffic to HTTPS and serve HSTS on the HTTPS response.",
                )
            )

        final = urllib.parse.urlparse(final_url)
        if final.scheme == "https" and final.hostname and final.hostname not in tls_checked_hosts:
            tls_checked_hosts.add(final.hostname)
            tls_findings, tls_warnings = check_tls(
                final.hostname, final.port or 443, timeout=timeout, target=target, url=final_url
            )
            collected.extend(tls_findings)
            warnings.extend(tls_warnings)

        if depth < max_depth:
            candidates: set[str] = set()
            link_source = body
            if render:
                rendered, extra_urls, render_error = _render_page(
                    final_url,
                    timeout=timeout,
                    extra_headers=headers,
                    capture_network=capture_network,
                    interact=interact,
                    max_clicks=max_clicks,
                )
                if rendered is not None:
                    # Rendered DOM is a superset of the raw HTML for link discovery.
                    link_source = rendered
                    candidates.update(extra_urls)  # C/D: network + interaction URLs
                elif render_error and not render_warned:
                    warnings.append(render_error)
                    render_warned = True
            if link_source:
                candidates.update(_extract_links(final_url, link_source))
            if (discover_assets or scan_js_secrets) and body:
                # A: mine same-host JS bundles for routes and/or leaked secrets.
                routes, secret_findings = _scan_assets(
                    final_url, body, opener, headers, timeout, assets_seen, max_assets, target,
                    extract_routes=discover_assets, scan_secrets=scan_js_secrets,
                )
                candidates.update(routes)
                collected.extend(secret_findings)
            for link in candidates:
                if (
                    _same_host(seed_url, link)
                    and not _is_static_asset(link)
                    and _canonical(link) not in visited
                ):
                    queue.append((link, depth + 1))

    findings = _dedupe_findings(collected)
    findings.sort(key=lambda finding: finding.sort_key())
    return findings, warnings, pages_scanned


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


# --- crawling / auth helpers ------------------------------------------------


def _fetch(
    opener: urllib.request.OpenerDirector,
    url: str,
    headers: Mapping[str, str],
    timeout: float,
) -> tuple[str, list[tuple[str, str]], list[str], bytes] | None:
    """Fetch ``url`` returning ``(final_url, header_items, set_cookies, body)``.

    ``body`` is the response bytes for html responses under ``_MAX_BODY_BYTES``
    (empty otherwise, so non-html/large pages are analyzed but not crawled).
    Returns ``None`` on a connection-level failure so the caller can degrade.
    """

    request = urllib.request.Request(url, headers=dict(headers), method="GET")
    try:
        with opener.open(request, timeout=timeout) as response:
            final_url = response.geturl()
            header_items = list(response.headers.items())
            set_cookies = response.headers.get_all("Set-Cookie") or []
            body = _read_html_body(response)
            return final_url, header_items, set_cookies, body
    except urllib.error.HTTPError as exc:
        # An error status still carries the response headers we want to inspect.
        header_items = list(exc.headers.items()) if exc.headers else []
        set_cookies = exc.headers.get_all("Set-Cookie") if exc.headers else []
        return url, header_items, set_cookies, b""
    except (urllib.error.URLError, ssl.SSLError, socket.timeout, OSError):
        return None


def _read_html_body(response) -> bytes:
    content_type = (response.headers.get("Content-Type") or "").lower()
    if "html" not in content_type:
        return b""
    return response.read(_MAX_BODY_BYTES)


def _ensure_bundled_browsers_path() -> None:
    """Point Playwright at a browser bundled with the install, if one ships.

    The Windows/Linux installers place the Chromium build under an
    ``ms-playwright`` folder so rendering works offline without a separate
    ``playwright install``. An explicit ``PLAYWRIGHT_BROWSERS_PATH`` always wins;
    otherwise use the first bundled folder found next to the frozen executable or
    the installed package tree.
    """

    if os.environ.get("PLAYWRIGHT_BROWSERS_PATH"):
        return
    candidates: list[str] = []
    if getattr(sys, "frozen", False):
        base = getattr(sys, "_MEIPASS", os.path.dirname(sys.executable))
        candidates.append(os.path.join(base, "ms-playwright"))
    # .../<app_root>/security_scanner/web.py -> app_root, and its parent (install prefix).
    app_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    candidates.append(os.path.join(app_root, "ms-playwright"))
    candidates.append(os.path.join(os.path.dirname(app_root), "ms-playwright"))
    for path in candidates:
        if os.path.isdir(path):
            os.environ["PLAYWRIGHT_BROWSERS_PATH"] = path
            return


# Injected before interaction (D): record every route the SPA router pushes so
# clicks that navigate via history.pushState are captured without leaving the page.
_ROUTE_HOOK_JS = """
window.__koda_routes = [];
for (const fn of ['pushState', 'replaceState']) {
  const orig = history[fn];
  history[fn] = function(state, title, url) {
    try { if (url) window.__koda_routes.push(new URL(url, location.href).href); } catch (e) {}
    return orig.apply(this, arguments);
  };
}
"""


def _render_page(
    url: str,
    *,
    timeout: float,
    extra_headers: Mapping[str, str] | None = None,
    capture_network: bool = False,
    interact: bool = False,
    max_clicks: int = 20,
) -> tuple[str | None, set[str], str]:
    """Render ``url`` in headless Chromium; return ``(html, extra_urls, error)``.

    ``extra_urls`` holds URLs discovered beyond the DOM anchors: same-origin
    requests the page made (``capture_network``) and routes reached by clicking
    bounded candidate elements (``interact``). Returns ``(None, set(), message)``
    when Playwright is unavailable or rendering fails, so the caller falls back
    to stdlib extraction.
    """

    _ensure_bundled_browsers_path()
    try:
        from playwright.sync_api import Error as PlaywrightError
        from playwright.sync_api import sync_playwright
    except ImportError:
        return None, set(), (
            "JS 렌더링 크롤을 건너뜁니다: Playwright 미설치. "
            "설치: pip install \"local-security-scanner[render]\" && python -m playwright install chromium"
        )

    headers = {k: v for k, v in (extra_headers or {}).items() if k.lower() != "user-agent"}
    captured: set[str] = set()
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            try:
                context = browser.new_context(user_agent=_USER_AGENT)
                if headers:
                    context.set_extra_http_headers(headers)
                page = context.new_page()
                if capture_network:
                    page.on("request", lambda req: captured.add(req.url))
                if interact:
                    page.add_init_script(_ROUTE_HOOK_JS)
                page.goto(url, wait_until="networkidle", timeout=timeout * 1000)
                html = page.content()
                if interact:
                    captured.update(_interact_page(page, max_clicks))
                return html, captured, ""
            finally:
                browser.close()
    except PlaywrightError as exc:
        return None, set(), f"JS 렌더링 실패 {url}: {exc}"
    except Exception as exc:  # defensive: rendering must never abort the scan
        return None, set(), f"JS 렌더링 오류 {url}: {exc}"


def _interact_page(page, max_clicks: int) -> set[str]:
    """D: click bounded candidate elements, collecting routes they navigate to.

    Best-effort and defensive — a single click that throws, opens a dialog, or
    navigates away never aborts the crawl. Records router pushes (via the init
    hook) and any full URL change, resetting back to the start page after a
    hard navigation so later candidates start from the same state.
    """

    found: set[str] = set()
    start = page.url
    try:
        elements = page.query_selector_all("a:not([href]), button, [role=button], [onclick]")
    except Exception:
        return found
    for element in elements[:max_clicks]:
        try:
            element.click(timeout=1000, no_wait_after=True)
            page.wait_for_timeout(150)
        except Exception:
            continue
        try:
            if page.url != start:
                found.add(page.url)
                page.go_back(wait_until="domcontentloaded", timeout=2000)
        except Exception:
            pass
    try:
        routes = page.evaluate("window.__koda_routes || []")
        found.update(routes)
    except Exception:
        pass
    return found


class _LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.hrefs: list[str] = []
        self.scripts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        data = dict(attrs)
        if tag == "a" and data.get("href"):
            self.hrefs.append(data["href"])
        elif tag == "script" and data.get("src"):
            self.scripts.append(data["src"])


def _parse_html(base_url: str, body: bytes | str) -> _LinkParser | None:
    parser = _LinkParser()
    text = body.decode("utf-8", "replace") if isinstance(body, bytes) else body
    try:
        parser.feed(text)
    except Exception:
        return None
    return parser


def _extract_links(base_url: str, body: bytes | str) -> set[str]:
    parser = _parse_html(base_url, body)
    if parser is None:
        return set()
    links: set[str] = set()
    for href in parser.hrefs:
        absolute = urllib.parse.urljoin(base_url, href)
        links.add(urllib.parse.urldefrag(absolute).url)
    return links


# Path-like string literals inside JS bundles (route tables, fetch() calls).
_ROUTE_LITERAL_RE = re.compile(r"""["'`](/[A-Za-z0-9][\w\-/\[\]]*)["'`]""")
# Segments that are framework/asset noise, not app routes/endpoints.
_ROUTE_NOISE_RE = re.compile(r"(^/_)|(/node_modules/)|(\.[A-Za-z0-9]{1,5}$)")


def _read_asset(
    opener: urllib.request.OpenerDirector,
    url: str,
    headers: Mapping[str, str],
    timeout: float,
) -> str | None:
    """Read a JS/text asset in full (not just HTML like ``_fetch``) for scraping."""
    request = urllib.request.Request(url, headers=dict(headers), method="GET")
    try:
        with opener.open(request, timeout=timeout) as response:
            return response.read(_MAX_BODY_BYTES).decode("utf-8", "replace")
    except (urllib.error.HTTPError, urllib.error.URLError, ssl.SSLError, socket.timeout, OSError):
        return None


def _scan_assets(
    page_url: str,
    body: bytes | str,
    opener: urllib.request.OpenerDirector,
    headers: Mapping[str, str],
    timeout: float,
    assets_seen: set[str],
    max_assets: int,
    target: str,
    *,
    extract_routes: bool,
    scan_secrets: bool,
) -> tuple[set[str], list[Finding]]:
    """Fetch same-host JS bundles once and mine them for routes (A) and secrets.

    Fetches each not-yet-seen same-host ``<script src>`` (bounded by
    ``max_assets`` across the whole crawl). ``extract_routes`` pulls quoted path
    literals (dropping framework/asset noise); ``scan_secrets`` runs the shared
    secret rules over the bundle text. Returns ``(routes, findings)``.
    """

    parser = _parse_html(page_url, body)
    if parser is None:
        return set(), []
    routes: set[str] = set()
    findings: list[Finding] = []
    for src in parser.scripts:
        if len(assets_seen) >= max_assets:
            break
        asset_url = urllib.parse.urldefrag(urllib.parse.urljoin(page_url, src)).url
        if not _same_host(page_url, asset_url) or asset_url in assets_seen:
            continue
        assets_seen.add(asset_url)
        text = _read_asset(opener, asset_url, headers, timeout)
        if text is None:
            continue
        if extract_routes:
            for path in _ROUTE_LITERAL_RE.findall(text):
                if path == "/" or _ROUTE_NOISE_RE.search(path):
                    continue
                routes.add(urllib.parse.urljoin(page_url, path))
        if scan_secrets:
            findings.extend(_scan_text_for_secrets(text, asset_url, target))
    return routes, findings


def _scan_text_for_secrets(text: str, asset_url: str, target: str) -> list[Finding]:
    """#1: run the shared secret rules over JS-bundle text; redacted, deduped."""
    from .checks.secrets import SECRET_RULES, _looks_like_placeholder, _redact_line

    findings: list[Finding] = []
    counts: dict[str, int] = {}
    for rule in SECRET_RULES:
        for match in rule.pattern.finditer(text):
            if counts.get(rule.rule_id, 0) >= 3:
                break
            secret = match.group(rule.secret_group)
            if _looks_like_placeholder(secret):
                continue
            snippet = text[max(0, match.start() - 24): match.end() + 24]
            findings.append(
                _finding(
                    f"web.js-{rule.rule_id}",
                    rule.severity,
                    f"Secret exposed in client JS: {rule.title}",
                    asset_url,
                    target=target,
                    evidence=_redact_line(snippet, secret),
                    recommendation="Remove the secret from client-side JavaScript and rotate it; keep secrets server-side.",
                )
            )
            counts[rule.rule_id] = counts.get(rule.rule_id, 0) + 1
    return findings


# --- #2: robots.txt / sitemap.xml ingestion --------------------------------


def _ingest_sitemaps(
    seed_url: str,
    opener: urllib.request.OpenerDirector,
    headers: Mapping[str, str],
    timeout: float,
) -> set[str]:
    """Read robots.txt + sitemap.xml from the seed origin; return listed URLs.

    robots.txt yields ``Sitemap:`` locations (followed, bounded) and same-host
    ``Disallow`` paths (worth scanning). sitemap.xml / sitemap-index ``<loc>``
    entries are collected. Best-effort; failures are ignored.
    """

    origin = _origin(seed_url)
    found: set[str] = set()
    sitemaps: list[str] = [urllib.parse.urljoin(origin, "/sitemap.xml")]

    robots = _read_asset(opener, urllib.parse.urljoin(origin, "/robots.txt"), headers, timeout)
    if robots:
        for line in robots.splitlines():
            key, _, value = line.partition(":")
            key, value = key.strip().lower(), value.strip()
            if key == "sitemap" and value:
                sitemaps.append(urllib.parse.urljoin(origin, value))
            elif key == "disallow" and value and value != "/":
                found.add(urllib.parse.urljoin(origin, value.split()[0]))

    seen_sitemaps: set[str] = set()
    index = 0
    while index < len(sitemaps) and len(seen_sitemaps) < 10:
        sitemap_url = sitemaps[index]
        index += 1
        if sitemap_url in seen_sitemaps:
            continue
        seen_sitemaps.add(sitemap_url)
        xml = _read_asset(opener, sitemap_url, headers, timeout)
        if not xml:
            continue
        for loc in re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", xml):
            absolute = urllib.parse.urljoin(origin, loc.strip())
            if absolute.endswith(".xml"):
                sitemaps.append(absolute)  # sitemap index -> nested sitemap
            else:
                found.add(absolute)
    return found


# --- #3: sensitive-path probing --------------------------------------------

_SENSITIVE_PATHS: tuple[tuple[str, str, str], ...] = (
    # (path, severity, signature the body must contain to count as a real hit)
    ("/.env", "high", "="),
    ("/.git/config", "high", "[core]"),
    ("/.git/HEAD", "high", "ref:"),
    ("/openapi.json", "medium", "openapi"),
    ("/swagger.json", "medium", "swagger"),
    ("/.well-known/security.txt", "info", "contact"),
    ("/.DS_Store", "low", "Bud1"),
    ("/config.json", "low", "{"),
)


def _probe_sensitive_paths(
    seed_url: str,
    opener: urllib.request.OpenerDirector,
    headers: Mapping[str, str],
    timeout: float,
    target: str,
) -> list[Finding]:
    """Probe well-known sensitive paths, guarding against SPA catch-all 200s.

    Fetches a random nonexistent path first as a baseline; a path only counts as
    exposed when it returns 200, differs from that baseline (or the host 404s
    unknown paths), and its body carries the expected signature.
    """

    origin = _origin(seed_url)
    baseline = _fetch_meta(opener, urllib.parse.urljoin(origin, f"/koda-probe-{int(time.time())}-nope"), headers, timeout)
    baseline_is_catch_all = baseline is not None and baseline[0] == 200

    findings: list[Finding] = []
    for path, severity, signature in _SENSITIVE_PATHS:
        meta = _fetch_meta(opener, urllib.parse.urljoin(origin, path), headers, timeout)
        if meta is None or meta[0] != 200:
            continue
        status, body = meta
        # On SPA catch-all hosts, only trust a hit whose body carries the signature
        # (and isn't just the same HTML shell the baseline returned).
        if baseline_is_catch_all and (signature.lower() not in body.lower() or body == baseline[1]):
            continue
        if signature and signature.lower() not in body.lower():
            continue
        findings.append(
            _finding(
                "web.sensitive-path-exposed",
                severity,
                f"Sensitive path is publicly accessible: {path}",
                urllib.parse.urljoin(origin, path),
                target=target,
                evidence=f"GET {path} returned {status} with expected content.",
                recommendation="Block public access to this path (deny rule / auth) and remove it from the web root.",
            )
        )
    return findings


def _fetch_meta(
    opener: urllib.request.OpenerDirector,
    url: str,
    headers: Mapping[str, str],
    timeout: float,
) -> tuple[int, str] | None:
    """GET returning ``(status, body_prefix)`` for probe comparison."""
    request = urllib.request.Request(url, headers=dict(headers), method="GET")
    try:
        with opener.open(request, timeout=timeout) as response:
            return response.status, response.read(4096).decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, ""
    except (urllib.error.URLError, ssl.SSLError, socket.timeout, OSError):
        return None


def _origin(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def _same_host(seed_url: str, candidate: str) -> bool:
    seed = urllib.parse.urlparse(seed_url)
    other = urllib.parse.urlparse(candidate)
    return other.scheme in {"http", "https"} and other.netloc == seed.netloc


def _same_host(seed_url: str, candidate: str) -> bool:
    seed = urllib.parse.urlparse(seed_url)
    other = urllib.parse.urlparse(candidate)
    return other.scheme in {"http", "https"} and other.netloc == seed.netloc


# Static assets carry the same per-host headers as pages, so scanning them adds
# noise and wasted requests (and rendering a font/image errors). Discover them,
# but keep them out of the scan frontier.
_STATIC_ASSET_RE = re.compile(
    r"\.(?:js|mjs|css|map|png|jpe?g|gif|svg|ico|webp|avif|woff2?|ttf|otf|eot|mp4|webm|pdf|zip|gz)(?:$|\?)",
    re.IGNORECASE,
)


def _is_static_asset(url: str) -> bool:
    return bool(_STATIC_ASSET_RE.search(urllib.parse.urlparse(url).path))


def _canonical(url: str) -> str:
    """Strip the fragment so ``/a`` and ``/a#x`` are not scanned twice."""
    return urllib.parse.urldefrag(url).url


def _dedupe_findings(findings: list[Finding]) -> list[Finding]:
    """Collapse repeats of the same rule to one representative.

    A missing-CSP header appears on every page; keep the first occurrence and,
    when it recurred, note how many pages were affected in the evidence.
    """

    seen: dict[tuple[str, str], Finding] = {}
    counts: dict[tuple[str, str], int] = {}
    for finding in findings:
        key = (finding.rule_id, finding.target)
        counts[key] = counts.get(key, 0) + 1
        seen.setdefault(key, finding)

    result: list[Finding] = []
    for key, finding in seen.items():
        count = counts[key]
        if count > 1:
            suffix = f"{count} page(s) affected"
            evidence = f"{finding.evidence}; {suffix}" if finding.evidence else suffix
            finding = replace(finding, evidence=evidence)
        result.append(finding)
    return result


def build_auth_opener() -> urllib.request.OpenerDirector:
    """Build a cookie-aware opener that keeps a form-login session across requests.

    A pasted browser ``Cookie`` header is applied separately via the crawl's
    ``extra_headers`` (see :func:`crawl_web`), so no login is needed to reuse an
    existing session.
    """

    jar = http.cookiejar.CookieJar()
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))


class _FormParser(HTMLParser):
    """Collect the first <form> plus its <input> name/value pairs."""

    def __init__(self) -> None:
        super().__init__()
        self.in_form = False
        self.done = False
        self.action = ""
        self.method = "get"
        self.fields: dict[str, str] = {}

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        data = {name: (value or "") for name, value in attrs}
        if tag == "form" and not self.done:
            self.in_form = True
            self.action = data.get("action", "")
            self.method = (data.get("method") or "get").lower()
        elif tag == "input" and self.in_form:
            name = data.get("name")
            if name:
                self.fields[name] = data.get("value", "")

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self.in_form:
            self.in_form = False
            self.done = True


def login(
    opener: urllib.request.OpenerDirector,
    login_url: str,
    username: str,
    password: str,
    *,
    user_field: str | None = None,
    pass_field: str | None = None,
    timeout: float = 15.0,
) -> list[str]:
    """Perform a best-effort form login, keeping the session in ``opener``'s jar.

    Parses the login form (preserving hidden/CSRF inputs), fills the username and
    password fields (auto-detected by name when not given), and POSTs to the
    form action. Failures degrade to a returned warning instead of raising; the
    scan then proceeds unauthenticated.
    """

    warnings: list[str] = []
    request = urllib.request.Request(login_url, headers={"User-Agent": _USER_AGENT})
    try:
        with opener.open(request, timeout=timeout) as response:
            page_url = response.geturl()
            body = response.read(_MAX_BODY_BYTES).decode("utf-8", "replace")
    except (urllib.error.URLError, ssl.SSLError, socket.timeout, OSError) as exc:
        return [f"Login page could not be loaded ({login_url}): {getattr(exc, 'reason', exc)}"]

    parser = _FormParser()
    parser.feed(body)
    if not parser.done:
        return [f"No login form found at {login_url}; scanning unauthenticated."]

    user_key = user_field or _match_field(parser.fields, _USER_FIELD_RE)
    pass_key = pass_field or _match_field(parser.fields, _PASS_FIELD_RE)
    if not user_key or not pass_key:
        return [f"Could not identify login fields at {login_url}; scanning unauthenticated."]

    fields = dict(parser.fields)
    fields[user_key] = username
    fields[pass_key] = password
    action_url = urllib.parse.urljoin(page_url, parser.action) if parser.action else page_url
    cookies_before = _cookie_count(opener)

    data = urllib.parse.urlencode(fields).encode("utf-8")
    post = urllib.request.Request(
        action_url,
        data=data,
        headers={"User-Agent": _USER_AGENT, "Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    try:
        with opener.open(post, timeout=timeout) as response:
            final_url = response.geturl()
    except urllib.error.HTTPError as exc:
        final_url = exc.geturl() if hasattr(exc, "geturl") else action_url
    except (urllib.error.URLError, ssl.SSLError, socket.timeout, OSError) as exc:
        return [f"Login POST failed ({action_url}): {getattr(exc, 'reason', exc)}"]

    got_cookie = _cookie_count(opener) > cookies_before
    redirected_away = _canonical(final_url) != _canonical(action_url)
    if not (got_cookie or redirected_away):
        warnings.append(f"Login may have failed at {login_url}; no session cookie set. Scanning may be unauthenticated.")
    return warnings


def _match_field(fields: Mapping[str, str], pattern: re.Pattern[str]) -> str | None:
    for name in fields:
        if pattern.search(name):
            return name
    return None


def _cookie_count(opener: urllib.request.OpenerDirector) -> int:
    for handler in opener.handlers:
        jar = getattr(handler, "cookiejar", None)
        if jar is not None:
            return len(jar)
    return 0


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
