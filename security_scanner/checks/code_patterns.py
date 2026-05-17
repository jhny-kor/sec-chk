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
    ".conf",
    ".config",
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
    ".properties",
    ".py",
    ".rb",
    ".rs",
    ".swift",
    ".ts",
    ".tsx",
    ".vue",
    ".xml",
    ".md",
    ".txt",
}

CODE_FILENAMES = {
    ".htaccess",
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
LOGGING_API = (
    r"(console\.(log|debug|info|warn|error)|logger\.(debug|info|warning|warn|error|exception)|"
    r"logging\.(debug|info|warning|warn|error|exception)|print|System\.out\.println|NSLog|Log\.(d|i|w|e))"
)
SENSITIVE_NAME = r"(pass" r"(word)?|pwd|secret|token|api[_-]?key|authorization|credential|session|cookie)"
XML_PARSER_API = (
    r"(Document" r"BuilderFactory|SAX" r"ParserFactory|Xml" r"ReaderSettings|Xml" r"Document)"
)

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
    CodePatternRule(
        "code.logging-sensitive-data",
        "Sensitive data may be written to logs",
        "medium",
        re.compile(rf"\b{LOGGING_API}\s*\([^#\n]*{SENSITIVE_NAME}", re.IGNORECASE),
        "A logging or console output call appears to include credential, token, session, or cookie data.",
        "Remove sensitive values from logs and record only redacted identifiers or security-safe event metadata.",
        frozenset({".cs", ".go", ".java", ".js", ".jsx", ".kt", ".php", ".py", ".rb", ".swift", ".ts", ".tsx"}),
    ),
    CodePatternRule(
        "code.empty-exception-handler",
        "Exception appears to be silently ignored",
        "low",
        re.compile(r"(\bexcept\b[^:\n]*:\s*pass\b|\bcatch\s*(\([^)]*\))?\s*\{\s*\})", re.IGNORECASE),
        "An exception handler appears to swallow errors without logging, recovery, or a clear security decision.",
        "Handle expected exceptions explicitly and log security-relevant failures with sanitized context.",
        frozenset({".cs", ".go", ".java", ".js", ".jsx", ".kt", ".php", ".py", ".rb", ".swift", ".ts", ".tsx"}),
    ),
    CodePatternRule(
        "code.stack-trace-exposure",
        "Stack trace output may expose internals",
        "low",
        re.compile(r"\b(printStackTrace|traceback\.print_exc|console\.trace|logger\.exception)\s*\(", re.IGNORECASE),
        "A stack trace output API appears in application code and may expose internals if enabled in user-facing flows.",
        "Route exceptions through centralized error handling and avoid returning or printing raw stack traces outside local debugging.",
        frozenset({".cs", ".go", ".java", ".js", ".jsx", ".kt", ".php", ".py", ".rb", ".swift", ".ts", ".tsx"}),
    ),
    CodePatternRule(
        "code.unversioned-api-route",
        "API route appears to be unversioned",
        "low",
        re.compile(
            r"(?:@\w+\.route|(?:app|router|routes|server)\.(?:get|post|put|patch|delete|use)|Route|path)"
            r"\s*\([^#\n]*[\"']/api/(?!v\d+(?:/|$))[^\"']+[\"']",
            re.IGNORECASE,
        ),
        "A public-looking API route is declared without an obvious version segment.",
        "Inventory public APIs and prefer explicit versioned routes such as /api/v1/... for lifecycle management.",
        frozenset({".cs", ".go", ".java", ".js", ".jsx", ".kt", ".php", ".py", ".rb", ".rs", ".swift", ".ts", ".tsx"}),
    ),
    CodePatternRule(
        "code.insecure-temp-file",
        "Temporary file use may be predictable or race-prone",
        "medium",
        re.compile(
            r"(\b(tempfile\.mktemp|mktemp|tmpnam)\s*\(|\b(open|writeFile|readFile|fopen)\s*\([^#\n]*[\"']/tmp/[^\"']+[\"'])",
            re.IGNORECASE,
        ),
        "The code appears to use a predictable temporary filename or a direct /tmp path in a file operation.",
        "Use secure temporary file APIs that create files atomically and avoid predictable shared paths.",
        frozenset({".c", ".cc", ".cpp", ".cs", ".go", ".h", ".hpp", ".java", ".js", ".jsx", ".kt", ".php", ".py", ".rb", ".rs", ".swift", ".ts", ".tsx"}),
    ),
    CodePatternRule(
        "code.wildcard-cors",
        "CORS appears to allow every origin",
        "medium",
        re.compile(
            r"(Access-Control-Allow-Origin[\"']?\s*[:,]\s*[\"']\*|allow_origins\s*=\s*\[\s*[\"']\*|"
            r"origins?\s*[:=]\s*[\"']\*|allowedOrigins\s*\(\s*[\"']\*)",
            re.IGNORECASE,
        ),
        "CORS configuration appears to allow requests from any origin.",
        "Restrict allowed origins to trusted application domains and avoid combining wildcard origins with credentials.",
        frozenset({".cs", ".go", ".java", ".js", ".jsx", ".kt", ".php", ".py", ".rb", ".rs", ".swift", ".ts", ".tsx"}),
    ),
    CodePatternRule(
        "code.public-bind-all-interfaces",
        "Service appears to bind all network interfaces",
        "low",
        re.compile(
            r"(\b(app\.run|uvicorn\.run|server\.listen|listen|http\.ListenAndServe)\s*\([^#\n]*[\"']0\.0\.0\.0[\"']|"
            r"\b(host|bind_address|listen_address)\s*[:=]\s*[\"']0\.0\.0\.0[\"']|--host\s+0\.0\.0\.0)",
            re.IGNORECASE,
        ),
        "A service binding appears to listen on all interfaces, which can expose local services more broadly than intended.",
        "Bind development services to localhost by default and require explicit configuration for public exposure.",
        frozenset({".cs", ".go", ".java", ".js", ".jsx", ".kt", ".php", ".py", ".rb", ".rs", ".swift", ".ts", ".tsx"}),
    ),
    CodePatternRule(
        "code.insecure-cookie-settings",
        "Session cookie settings appear insecure",
        "medium",
        re.compile(
            r"(SESSION_COOKIE_(SECURE|HTTPONLY)\s*=\s*False|"
            r"(secure|httpOnly|httponly)\s*[:=]\s*false|"
            r"sameSite\s*[:=]\s*[\"']none[\"'][^#\n]*(secure\s*[:=]\s*false)?)",
            re.IGNORECASE,
        ),
        "Cookie or session settings appear to disable Secure or HttpOnly protections.",
        "Set Secure, HttpOnly, and appropriate SameSite attributes for session cookies and avoid weakening them outside local-only development.",
        frozenset({".cs", ".go", ".java", ".js", ".jsx", ".kt", ".php", ".py", ".rb", ".swift", ".ts", ".tsx"}),
    ),
    CodePatternRule(
        "code.directory-listing-enabled",
        "Web directory listing appears enabled",
        "medium",
        re.compile(
            r"(Options\s+(\+?Indexes|.*\bIndexes\b)|autoindex\s+on|DirectoryBrowse\s+On)",
            re.IGNORECASE,
        ),
        "Web server configuration appears to expose directory listings.",
        "Disable directory listing and serve only explicitly intended files through controlled routes or static asset configuration.",
        frozenset({".conf", ".config", ".htaccess", ".properties", ".xml"}),
    ),
    CodePatternRule(
        "code.webdav-enabled",
        "WebDAV appears enabled",
        "medium",
        re.compile(r"(\bDAV\s+On\b|mod_dav|webdav|httpPutEnabled\s*=\s*[\"']?true)", re.IGNORECASE),
        "WebDAV or HTTP PUT-style publishing support appears enabled.",
        "Disable WebDAV unless explicitly required, and restrict authoring methods with authentication and network controls.",
        frozenset({".conf", ".config", ".htaccess", ".properties", ".xml"}),
    ),
    CodePatternRule(
        "code.legacy-board-software",
        "Legacy bulletin board software marker",
        "medium",
        re.compile(r"\b(tech" r"note|zero" r"board)\b", re.IGNORECASE),
        "The project contains markers of legacy bulletin board software historically associated with recurring web compromise.",
        "Confirm the component is still used, update or remove it, and isolate legacy upload/download functionality behind compensating controls.",
        frozenset({".html", ".inc", ".js", ".php"}),
    ),
    CodePatternRule(
        "code.weak-hash",
        "Weak hash algorithm appears in security-sensitive code",
        "medium",
        re.compile(r"\b(md" r"5|sha" r"1)\s*\(", re.IGNORECASE),
        "The code appears to use MD5 or SHA-1, which are unsuitable for passwords, signatures, and collision-resistant integrity checks.",
        "Use modern password hashing for credentials and SHA-256 or stronger approved algorithms for integrity where appropriate.",
        frozenset({".cs", ".go", ".java", ".js", ".jsx", ".kt", ".php", ".py", ".rb", ".rs", ".swift", ".ts", ".tsx"}),
    ),
    CodePatternRule(
        "code.xml-external-entity",
        "XML parser may allow external entity processing",
        "high",
        re.compile(
            rf"(resolve_entities\s*=\s*True|load_dtd\s*=\s*True|{XML_PARSER_API}[^#\n]*(parse|load|newInstance|\())",
            re.IGNORECASE,
        ),
        "XML parsing appears to use APIs that can be unsafe when external entity processing is not disabled.",
        "Disable DTD and external entity resolution, or use hardened XML parser configurations for untrusted XML.",
        frozenset({".cs", ".java", ".kt", ".py", ".xml"}),
    ),
    CodePatternRule(
        "code.llm-prompt-user-concat",
        "LLM prompt appears to concatenate user input",
        "medium",
        re.compile(
            rf"(system|developer|prompt|messages?)\s*[:=][^#\n]*(\+|f[\"']|`\$\{{)[^#\n]*{UNTRUSTED_SOURCE}",
            re.IGNORECASE,
        ),
        "User-controlled input appears to be concatenated into a privileged prompt or message.",
        "Keep system/developer instructions fixed, place user content in separate message fields, and add prompt-injection tests.",
        frozenset({".js", ".jsx", ".py", ".ts", ".tsx"}),
    ),
    CodePatternRule(
        "code.llm-tool-unrestricted",
        "LLM tool or function call appears unrestricted",
        "high",
        re.compile(
            r"(tool_choice\s*[:=]\s*[\"']auto|function_call\s*[:=]\s*[\"']auto|tools\s*[:=]\s*\[[^\]]*(exec|shell|browser|http|file|database))",
            re.IGNORECASE,
        ),
        "The model appears able to call broad tools without an obvious allowlist or confirmation boundary.",
        "Constrain tools by task, validate tool arguments, require confirmation for side effects, and log tool decisions.",
        frozenset({".js", ".jsx", ".py", ".ts", ".tsx"}),
    ),
    CodePatternRule(
        "code.llm-sensitive-data-in-prompt",
        "Sensitive data may be sent to an LLM prompt",
        "medium",
        re.compile(rf"(openai|anthropic|chat\.completions|responses\.create|generateContent)[^#\n]*{SENSITIVE_NAME}", re.IGNORECASE),
        "A prompt or LLM request appears to include credential, session, cookie, or other sensitive fields.",
        "Redact sensitive values before LLM calls and document whether prompts may leave the local trust boundary.",
        frozenset({".js", ".jsx", ".py", ".ts", ".tsx"}),
    ),
)


def check_file(path: Path, target: TargetConfig) -> list[Finding]:
    if not is_text_candidate(path) or (path.suffix.lower() not in CODE_EXTENSIONS and path.name not in CODE_FILENAMES):
        return []

    lines = read_text_lines(path, target.max_file_size_bytes)
    if lines is None:
        return []

    findings: list[Finding] = []
    per_rule_counts: dict[str, int] = {}
    suffix = path.suffix.lower()
    filename = path.name
    for line_number, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line or _is_comment(line):
            continue
        for rule in CODE_PATTERN_RULES:
            if suffix not in rule.extensions and filename not in rule.extensions:
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
