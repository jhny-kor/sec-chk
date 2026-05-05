from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from ..models import Finding, TargetConfig
from .common import is_text_candidate, read_text_lines


CODE_EXTENSIONS = {
    ".c",
    ".cc",
    ".cpp",
    ".cs",
    ".cxx",
    ".go",
    ".h",
    ".hpp",
    ".html",
    ".java",
    ".js",
    ".jsx",
    ".kt",
    ".php",
    ".py",
    ".rb",
    ".rs",
    ".swift",
    ".ts",
    ".tsx",
    ".vue",
}


@dataclass(frozen=True)
class CodePatternRule:
    rule_id: str
    title: str
    severity: str
    pattern: re.Pattern[str]
    description: str
    recommendation: str
    extensions: frozenset[str] = frozenset(CODE_EXTENSIONS)


UNTRUSTED_SOURCE = r"(req\.|request\.|\$_(GET|POST|REQUEST|FILES)|params|query|body|location\.|input\(|sys\.argv|ARGV)"

CODE_PATTERN_RULES = (
    CodePatternRule(
        "code.xss-dom-sink",
        "Potential XSS through unsafe HTML sink",
        "high",
        re.compile(
            rf"\b(innerHTML|outerHTML|insertAdjacentHTML|document\.write|dangerouslySetInnerHTML)\b.*{UNTRUSTED_SOURCE}",
            re.IGNORECASE,
        ),
        "Untrusted input appears to flow into an HTML-rendering sink.",
        "Use safe text rendering, contextual output encoding, or a vetted sanitizer before rendering user-controlled HTML.",
        frozenset({".html", ".js", ".jsx", ".ts", ".tsx", ".vue"}),
    ),
    CodePatternRule(
        "code.sql-dynamic-query",
        "Potential SQL injection through dynamic query",
        "high",
        re.compile(
            r"\b(execute|executemany|query|raw|prepareStatement|createQuery)\s*\("
            r"[^#\n;]*(SELECT|INSERT|UPDATE|DELETE|WHERE)[^#\n;]*(\+|%\s|\{|\$\{|\.format\()",
            re.IGNORECASE,
        ),
        "SQL text appears to be assembled dynamically before execution.",
        "Use parameterized queries or ORM binding APIs instead of string-built SQL.",
        frozenset({".cs", ".go", ".java", ".js", ".jsx", ".kt", ".php", ".py", ".rb", ".rs", ".ts", ".tsx"}),
    ),
    CodePatternRule(
        "code.command-injection",
        "Potential command injection",
        "high",
        re.compile(
            rf"\b(os\.system|os\.popen|subprocess\.(run|call|Popen|check_output)|child_process\.(exec|execSync)|"
            rf"shell_exec|passthru|Runtime\.getRuntime\(\)\.exec)\s*\([^#\n]*({UNTRUSTED_SOURCE}|shell\s*=\s*True|\+)",
            re.IGNORECASE,
        ),
        "A shell or process execution API appears to receive dynamic or user-controlled input.",
        "Avoid shell execution for user input; pass fixed argument arrays and validate allowlisted values.",
        frozenset({".cs", ".go", ".java", ".js", ".jsx", ".kt", ".php", ".py", ".rb", ".rs", ".ts", ".tsx"}),
    ),
    CodePatternRule(
        "code.path-traversal",
        "Potential path traversal",
        "medium",
        re.compile(
            rf"\b(open|send_file|FileResponse|readFile|readFileSync|createReadStream|writeFile|writeFileSync)\s*"
            rf"\([^#\n]*({UNTRUSTED_SOURCE}|path\.join\([^)]*(req|request|params|query)|\.\.)",
            re.IGNORECASE,
        ),
        "A filesystem API appears to use user-controlled path data.",
        "Resolve paths against an allowlisted base directory and reject traversal before opening files.",
        frozenset({".cs", ".go", ".java", ".js", ".jsx", ".kt", ".php", ".py", ".rb", ".rs", ".ts", ".tsx"}),
    ),
    CodePatternRule(
        "code.csrf-disabled",
        "CSRF protection appears disabled",
        "medium",
        re.compile(
            r"(@cs" r"rf_exempt|cs" r"rf\s*:\s*false|cs" r"rf\.disable|verify_cs" r"rf_token.*false|"
            r"skip_before_action\s+:verify_authenticity_token|protect_from_forgery\s+except:)",
            re.IGNORECASE,
        ),
        "The code appears to disable CSRF protection for a route or application.",
        "Keep CSRF protection enabled for browser-authenticated state-changing requests, or document a compensating control.",
        frozenset({".cs", ".go", ".java", ".js", ".jsx", ".kt", ".php", ".py", ".rb", ".ts", ".tsx"}),
    ),
    CodePatternRule(
        "code.auth-disabled-endpoint",
        "Authentication or authorization appears disabled",
        "medium",
        re.compile(
            r"(@Allow" r"Anonymous|@Public\(\)|permit" r"All\(\)|auth\s*:\s*false|Allow" r"Any|"
            r"permission_classes\s*=\s*\[\s*\]|skip_before_action\s+:authenticate)",
            re.IGNORECASE,
        ),
        "An endpoint or handler appears to explicitly bypass authentication or authorization.",
        "Confirm the endpoint is intentionally public and enforce authorization checks on sensitive operations.",
        frozenset({".cs", ".go", ".java", ".js", ".jsx", ".kt", ".php", ".py", ".rb", ".ts", ".tsx"}),
    ),
    CodePatternRule(
        "code.eval-user-input",
        "Potential code injection through eval-like API",
        "high",
        re.compile(
            rf"\b(eval|exec|Function|setTimeout|setInterval|instance_eval|class_eval)\s*\([^#\n]*{UNTRUSTED_SOURCE}",
            re.IGNORECASE,
        ),
        "User-controlled input appears to reach an eval-like code execution API.",
        "Remove dynamic code execution or replace it with a fixed dispatch table over allowlisted operations.",
        frozenset({".html", ".js", ".jsx", ".php", ".py", ".rb", ".ts", ".tsx"}),
    ),
    CodePatternRule(
        "code.unsafe-deserialization",
        "Unsafe deserialization API",
        "high",
        re.compile(
            r"\b(pick" r"le\.loads?|ya" r"ml\.load\s*\(|Object" r"InputStream|Binary" r"Formatter|"
            r"unser" r"ialize\s*\(|Marshal\.load|readObject\s*\()",
            re.IGNORECASE,
        ),
        "A dangerous deserialization API appears in code.",
        "Use safe parsers for untrusted data and restrict deserialization to signed, trusted inputs only.",
        frozenset({".cs", ".java", ".php", ".py", ".rb"}),
    ),
    CodePatternRule(
        "code.ssrf-user-url",
        "Potential SSRF through user-controlled URL fetch",
        "high",
        re.compile(
            rf"\b(requests|httpx|urllib\.request|axios|fetch|http\.get|https\.get|RestTemplate|WebClient)"
            rf"[^#\n]*(get|post|open|request|\()[^#\n]*{UNTRUSTED_SOURCE}",
            re.IGNORECASE,
        ),
        "A server-side HTTP client appears to fetch a URL derived from user input.",
        "Fetch only allowlisted hosts, block private network ranges, and avoid forwarding arbitrary user-provided URLs.",
        frozenset({".cs", ".go", ".java", ".js", ".jsx", ".kt", ".php", ".py", ".rb", ".rs", ".ts", ".tsx"}),
    ),
    CodePatternRule(
        "code.unrestricted-file-upload",
        "Potential unrestricted file upload",
        "medium",
        re.compile(
            r"(move_uploaded_file\s*\(\s*\$_FILES|\.save\s*\([^#\n]*(filename|originalname|req\.file)|"
            r"multer\s*\(\s*\{\s*dest\s*:)",
            re.IGNORECASE,
        ),
        "Uploaded file data appears to be saved using client-controlled filename or permissive storage.",
        "Validate content type and extension, generate server-side filenames, and store uploads outside executable paths.",
        frozenset({".js", ".jsx", ".php", ".py", ".ts", ".tsx"}),
    ),
    CodePatternRule(
        "code.dangerous-c-buffer-api",
        "Dangerous C/C++ buffer API",
        "medium",
        re.compile(r"\b(gets|strcpy|strcat|sprintf|vsprintf)\s*\(", re.IGNORECASE),
        "The code uses legacy C/C++ APIs commonly associated with buffer overflows.",
        "Use bounded alternatives and verify destination buffer sizes before copying or formatting data.",
        frozenset({".c", ".cc", ".cpp", ".cxx", ".h", ".hpp"}),
    ),
    CodePatternRule(
        "code.unbounded-request-body",
        "Request body parsing without an obvious size limit",
        "low",
        re.compile(r"\b(express\.json|bodyParser\.json|express\.urlencoded|bodyParser\.urlencoded)\s*\(\s*\)", re.IGNORECASE),
        "Request body parsing appears to be enabled without an explicit size limit.",
        "Set conservative request body limits and reject oversized requests early.",
        frozenset({".js", ".jsx", ".ts", ".tsx"}),
    ),
)


def check_file(path: Path, target: TargetConfig) -> list[Finding]:
    if not is_text_candidate(path) or path.suffix.lower() not in CODE_EXTENSIONS:
        return []

    lines = read_text_lines(path, target.max_file_size_bytes)
    if lines is None:
        return []

    findings: list[Finding] = []
    per_rule_counts: dict[str, int] = {}
    for line_number, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line or _is_comment(line):
            continue
        for rule in CODE_PATTERN_RULES:
            if path.suffix.lower() not in rule.extensions:
                continue
            if per_rule_counts.get(rule.rule_id, 0) >= 5:
                continue
            if rule.pattern.search(line):
                findings.append(
                    Finding(
                        rule_id=rule.rule_id,
                        category="code",
                        severity=rule.severity,
                        title=rule.title,
                        path=path,
                        line=line_number,
                        evidence=_trim_evidence(line),
                        description=rule.description,
                        recommendation=rule.recommendation,
                    )
                )
                per_rule_counts[rule.rule_id] = per_rule_counts.get(rule.rule_id, 0) + 1
    return findings


def _is_comment(line: str) -> bool:
    return line.startswith(("#", "//", "/*", "*", "<!--"))


def _trim_evidence(line: str) -> str:
    return line if len(line) <= 240 else f"{line[:237]}..."
