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
    ".jsp",
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


# Remote, attacker-supplied input. `ctx` needs a request-shaped member: a bare
# `ctx.` also matches a canvas 2D context, a crypto context, and most other
# graphics or codec handles.
REMOTE_SOURCE = (
    r"\b(?:req|request)\s*(?:\.|\[)|"
    r"\bctx\s*(?:\.\s*(?:request|req|query|params|body|headers|cookies)\b|\[)|"
    r"\$_(?:GET|POST|REQUEST|FILES)\b|"
    r"\blocation\.(?:hash|search|href)\b"
)
# Operator-supplied input. Reading the file named on your own command line is
# what a CLI is for, so these raise review candidates but never confirm a flow.
LOCAL_SOURCE = r"\binput\s*\(|\bsys\.argv\b|\bARGV\b"
UNTRUSTED_SOURCE = rf"(?:{REMOTE_SOURCE}|{LOCAL_SOURCE})"
LOGGING_API = (
    r"(console\.(log|debug|info|warn|error)|logger\.(debug|info|warning|warn|error|exception)|"
    r"logging\.(debug|info|warning|warn|error|exception)|print|System\.out\.println|NSLog|Log\.(d|i|w|e))"
)
# Bounded so `passed`, `bypass`, `tokenize` and `cache_token` are not secrets,
# while the compound names that really do carry credentials still match.
SENSITIVE_NAME = (
    r"\b(?:pass" r"(?:word)?|passwd|pwd|secret|credentials?|authorization|"
    r"(?:access|refresh|auth|id|bearer|csrf|xsrf|session)[_-]?tokens?|tokens?|"
    r"api[_-]?keys?|secret[_-]?keys?|private[_-]?keys?|session[_-]?ids?|sessions?|cookies?)\b"
)
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
            rf"(?:(?<![.\w])open|\b(?:os|io|codecs|shutil|aiofiles)\.open|"
            rf"\b(?:send_file|FileResponse|readFile|readFileSync|createReadStream|writeFile|writeFileSync))\s*"
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
            # setTimeout/setInterval only execute code when their first argument
            # is a string; a callback that merely mentions `request` is normal.
            # `Function` stays case-sensitive: the JS `function` keyword is not a sink.
            rf"(?:\b(?:eval|exec|(?-i:Function)|instance_eval|class_eval)\s*\([^#\n]*{UNTRUSTED_SOURCE}"
            rf"|\b(?:setTimeout|setInterval)\s*\(\s*[\"'`][^#\n]*{UNTRUSTED_SOURCE})",
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
        re.compile(r"\b(printStackTrace|traceback\.print_exc|console\.trace)\s*\(", re.IGNORECASE),
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
        "code.jwt-verification-disabled",
        "JWT signature verification appears disabled",
        "high",
        re.compile(
            r"(verify_signature\s*[:=]\s*False|verify\s*[:=]\s*false|jwt\.decode\s*\([^#\n]*(verify\s*=\s*False|options\s*=\s*\{[^}]*verify_signature[^}]*False))",
            re.IGNORECASE,
        ),
        "JWT decoding appears to disable signature verification or token validation.",
        "Require signature, issuer, audience, expiry, and algorithm validation for every trusted JWT.",
        frozenset({".cs", ".go", ".java", ".js", ".jsx", ".kt", ".php", ".py", ".rb", ".ts", ".tsx"}),
    ),
    CodePatternRule(
        "code.jwt-none-algorithm",
        "JWT none algorithm appears allowed",
        "high",
        re.compile(r"(algorithms?\s*[:=]\s*\[[^\]]*[\"']none[\"']|alg\s*[:=]\s*[\"']none[\"'])", re.IGNORECASE),
        "JWT configuration appears to allow the none algorithm.",
        "Use an explicit allowlist of approved signing algorithms and reject unsigned tokens.",
        frozenset({".cs", ".go", ".java", ".js", ".jsx", ".kt", ".php", ".py", ".rb", ".ts", ".tsx"}),
    ),
    CodePatternRule(
        "code.session-long-expiry",
        "Session or token expiry appears excessive",
        "low",
        re.compile(
            r"(SESSION_COOKIE_AGE\s*=\s*(?:[7-9]\d{5,}|[1-9]\d{6,})|maxAge\s*[:=]\s*(?:[7-9]\d{8,}|[1-9]\d{9,})|expiresIn\s*[:=]\s*[\"'](?:365d|[2-9]\d{2,}d|[1-9]\d+y)[\"'])",
            re.IGNORECASE,
        ),
        "Session or token lifetime appears very long for an application credential.",
        "Use short-lived access tokens, rotate refresh tokens, and document any long-lived session exception.",
        frozenset({".cs", ".go", ".java", ".js", ".jsx", ".kt", ".php", ".py", ".rb", ".swift", ".ts", ".tsx"}),
    ),
    CodePatternRule(
        "code.api-route-missing-auth",
        "Sensitive API route appears to lack an auth guard",
        "medium",
        re.compile(
            r"((app|router|server)\.(get|post|put|patch|delete)\s*\([\"'][^\"']*/api/[^\"']*(admin|user|account|payment|order|profile|secret|token)[^\"']*[\"'][^#\n]*\(?\s*(req|request|ctx)\s*\)?\s*=>)",
            re.IGNORECASE,
        ),
        "A sensitive-looking API route is declared inline without an obvious authentication or authorization guard nearby.",
        "Require explicit route-level authentication and object/function authorization checks before sensitive API handlers run.",
        frozenset({".js", ".jsx", ".ts", ".tsx"}),
    ),
    CodePatternRule(
        "code.api-mass-assignment",
        "API handler appears to mass-assign request body data",
        "medium",
        re.compile(
            r"(\b(create|update|assign|save|insert|merge)\s*\([^#\n]*(req\.body|request\.body|body|params)|\.\.\.\s*(req\.body|request\.body|body))",
            re.IGNORECASE,
        ),
        "Request body data appears to be assigned directly to a model or persistence call.",
        "Map only allowed fields explicitly and reject unexpected object properties before persistence.",
        frozenset({".cs", ".go", ".java", ".js", ".jsx", ".kt", ".php", ".py", ".rb", ".ts", ".tsx"}),
    ),
    CodePatternRule(
        "code.api-missing-rate-limit",
        "API server appears to lack rate limiting",
        "low",
        re.compile(r"(express\s*\(\)|FastAPI\s*\(|new\s+Koa\s*\(|SpringApplication\.run)", re.IGNORECASE),
        "An API framework bootstrap was found; KODA did not see route-level rate limiting from this line.",
        "Add rate limits, request quotas, and abuse controls for login, signup, password reset, and high-cost API routes.",
        frozenset({".java", ".js", ".jsx", ".kt", ".py", ".ts", ".tsx"}),
    ),
    CodePatternRule(
        "code.external-api-no-timeout",
        "External API call appears to omit a timeout",
        "low",
        re.compile(
            r"\b(requests\.(get|post|put|patch|delete)|httpx\.(get|post|put|patch|delete)|axios\.(get|post|put|patch|delete)|fetch)\s*\([^#\n]*(https?://|url|endpoint)(?![^#\n]*(timeout|signal|AbortController))",
            re.IGNORECASE,
        ),
        "An outbound API call appears to be made without an explicit timeout or abort signal.",
        "Set conservative timeouts, retries with backoff, and allowlisted destinations for outbound API integrations.",
        frozenset({".js", ".jsx", ".py", ".ts", ".tsx"}),
    ),
    CodePatternRule(
        "code.pii-logging",
        "Personal data may be written to logs",
        "medium",
        re.compile(
            rf"\b{LOGGING_API}\s*\([^#\n]*(email|phone|mobile|address|birth|dob|ssn|resident|rrn|jumin|주민|전화|주소|생년|card[_-]?number)",
            re.IGNORECASE,
        ),
        "A logging or console output call appears to include personal or regulated data fields.",
        "Redact personal data in logs, use event IDs instead of raw identifiers, and document retention limits.",
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
        "code.open-redirect-user-input",
        "Potential open redirect from user input",
        "medium",
        re.compile(
            rf"(\bsendRedirect\s*\([^#\n]*request\.getParameter|"
            rf"\b(res|response|ctx)\.redirect\s*\([^#\n]*{UNTRUSTED_SOURCE}|"
            rf"\bredirect\s*\(\s*[^#\n)]*{UNTRUSTED_SOURCE})",
            re.IGNORECASE,
        ),
        "A redirect target appears to be built from user-controlled input without an allowlist.",
        "Redirect only to allowlisted internal paths, or map user input to fixed destinations instead of raw URLs.",
        frozenset({".java", ".jsp", ".js", ".jsx", ".kt", ".php", ".py", ".rb", ".ts", ".tsx"}),
    ),
    CodePatternRule(
        "code.xml-injection",
        "Potential XML injection through string assembly",
        "medium",
        re.compile(
            rf"([\"'`][^\"'`\n]*<[A-Za-z][\w:-]*>[^\"'`\n]*[\"'`]\s*(\+|%)\s*[^#\n]*{UNTRUSTED_SOURCE}|"
            rf"f[\"'][^\"'\n]*<[A-Za-z][\w:-]*>[^\"'\n]*\{{[^}}\n]*(req|request|params|query|body|input))",
            re.IGNORECASE,
        ),
        "User-controlled input appears to be concatenated into an XML document body without escaping.",
        "Build XML with a serializer or escape user input for XML content instead of concatenating strings.",
        frozenset({".java", ".js", ".jsx", ".kt", ".php", ".py", ".ts", ".tsx"}),
    ),
    CodePatternRule(
        "code.ldap-injection",
        "Potential LDAP injection through filter assembly",
        "high",
        re.compile(
            r"([\"']\(*[&|]?\(*(uid|cn|sAMAccountName|mail|memberOf|objectClass)=[^\"'\n]*[\"']\s*(\+|%|\.format\()|"
            r"\b(LdapTemplate|DirContext|InitialDirContext|InitialLdapContext)\b[^#\n]*\bsearch\b[^#\n]*(\+|\.format\(|f[\"'])|"
            r"\bldap\w*[^#\n]*\bsearch(_s|_ext)?\s*\([^#\n]*(%s|\+|\.format\(|f[\"']))",
            re.IGNORECASE,
        ),
        "An LDAP filter appears to be assembled from dynamic input without escaping.",
        "Escape LDAP filter metacharacters or use parameterized LDAP query APIs for user-supplied values.",
        frozenset({".java", ".kt", ".py"}),
    ),
    CodePatternRule(
        "code.http-response-splitting",
        "Potential HTTP response splitting via header value",
        "medium",
        re.compile(
            rf"\b(setHeader|addHeader|set_header|writeHead)\s*\([^#\n]*{UNTRUSTED_SOURCE}",
            re.IGNORECASE,
        ),
        "User-controlled input appears to flow into an HTTP response header without CR/LF filtering.",
        "Strip or reject CR/LF characters and validate user input before writing it into response headers.",
        frozenset({".cs", ".go", ".java", ".jsp", ".js", ".jsx", ".kt", ".php", ".py", ".rb", ".ts", ".tsx"}),
    ),
    CodePatternRule(
        "code.format-string-user-input",
        "Format string may be attacker-controlled",
        "high",
        re.compile(
            r"(\b(printf|vprintf|syslog)\s*\(\s*[a-zA-Z_][\w>.\-\[\]]*\s*\)|"
            r"\bf?printf\s*\(\s*(stderr|stdout)\s*,\s*[a-zA-Z_][\w>.\-\[\]]*\s*\)|"
            r"\bString\.format\s*\(\s*(?!Locale\b)[a-zA-Z_][\w.\[\]]*\s*[,)])",
            re.IGNORECASE,
        ),
        "A variable is used directly as a format string, which allows format specifier injection.",
        "Pass a constant format string and supply dynamic data as arguments (e.g. printf(\"%s\", value)).",
        frozenset({".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".java", ".kt"}),
    ),
    CodePatternRule(
        "code.insufficient-key-length",
        "Cryptographic key length appears insufficient",
        "medium",
        re.compile(
            r"(\bRSA\b[^#\n]{0,60}\b(512|768|1024)\b|\b(512|768|1024)\b[^#\n]{0,30}\bRSA\b|"
            r"\bKeyPairGenerator\b[^#\n]*initialize\s*\(\s*(512|768|1024)\b|"
            r"\b(DSA|DiffieHellman|DH)\b[^#\n]{0,40}\b(512|768|1024)\b)",
            re.IGNORECASE,
        ),
        "An asymmetric key appears to be generated with fewer than 2048 bits.",
        "Use RSA/DSA/DH keys of at least 2048 bits (or modern elliptic-curve algorithms) for new keys.",
        frozenset({".cs", ".go", ".java", ".js", ".jsx", ".kt", ".py", ".ts", ".tsx"}),
    ),
    CodePatternRule(
        "code.insecure-random-security-use",
        "Non-cryptographic randomness used in a security context",
        "medium",
        re.compile(
            r"\b(token|otp|nonce|salt|session[_-]?id|secret|password|api[_-]?key|auth[_-]?code|verification[_-]?code|reset[_-]?code)\w*\s*[:=]"
            r"[^#\n]*(Math\.random|java\.util\.Random|new\s+Random\s*\(|\brandom\.(random|randint|choice|choices|randrange|getrandbits)\s*\(|\brand\s*\(\s*\))",
            re.IGNORECASE,
        ),
        "A security-purpose value appears to be generated with a non-cryptographic random API.",
        "Use a CSPRNG (secrets, SecureRandom, crypto.randomBytes/getRandomValues) for tokens, codes, keys, and salts.",
        frozenset({".cs", ".java", ".js", ".jsx", ".kt", ".php", ".py", ".rb", ".ts", ".tsx"}),
    ),
    CodePatternRule(
        "code.tls-certificate-verification-disabled",
        "TLS certificate verification appears disabled",
        "high",
        re.compile(
            r"(\bverify\s*=\s*False\b|rejectUnauthorized\s*[:=]\s*false|InsecureSkipVerify\s*:\s*true|"
            r"NODE_TLS_REJECT_UNAUTHORIZED[\"']?\s*[:=]\s*[\"']?0|TrustAllCerts|ALLOW_ALL_HOSTNAME_VERIFIER|"
            r"setHostnameVerifier\s*\([^)#\n]*->\s*true|CURLOPT_SSL_VERIFYPEER\s*,\s*(0|false)|"
            r"check_hostname\s*=\s*False|ssl\.CERT_NONE)",
            re.IGNORECASE,
        ),
        "TLS certificate or hostname verification appears to be turned off for an outbound connection.",
        "Keep certificate and hostname verification enabled; pin or provision proper trust anchors instead of disabling checks.",
        frozenset({".cs", ".go", ".java", ".js", ".jsx", ".kt", ".php", ".py", ".rb", ".ts", ".tsx"}),
    ),
    CodePatternRule(
        "code.password-hash-without-salt",
        "Password appears hashed without a salt or KDF",
        "medium",
        re.compile(
            r"(\b(password|passwd|pwd|pin|credential)\w*\b[^#\n]*\b(hashlib\.(md5|sha1|sha256)|MessageDigest\.getInstance|DigestUtils\.(md5|sha1|sha256)\w*|crypto\.createHash)\b|"
            r"\b(hashlib\.(md5|sha1|sha256)|crypto\.createHash)\b[^#\n]*\b(password|passwd|pwd|pin)\b)",
            re.IGNORECASE,
        ),
        "A credential appears to be hashed directly with a fast hash instead of a salted password KDF.",
        "Hash passwords with a dedicated KDF (bcrypt, scrypt, Argon2, PBKDF2) that applies a unique salt per credential.",
        frozenset({".cs", ".java", ".js", ".jsx", ".kt", ".php", ".py", ".rb", ".ts", ".tsx"}),
    ),
    CodePatternRule(
        "code.null-pointer-dereference",
        "Potential null pointer dereference",
        "medium",
        # Java/Kotlin nullability needs state tracking, so the real detector is
        # `_java_null_pointer_findings` rather than a line-only expression.
        re.compile(r"(?!)"),
        "A value that is null or returned by a known nullable lookup appears to be dereferenced.",
        "Check for null before dereferencing, return a non-null type, or use a fail-closed wrapper such as Objects.requireNonNull or Optional.orElseThrow.",
        frozenset({".java", ".kt"}),
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


_JAVA_XML_FACTORY = re.compile(
    r"\b(?:DocumentBuilderFactory\s+)?([A-Za-z_$][\w$]*)\s*=\s*DocumentBuilderFactory\s*\.\s*newInstance\s*\(\s*\)",
)
_JAVA_XML_UNTRUSTED_INPUT = re.compile(
    r"\b(request|req|body|payload|input|stream|reader|upload|xml)\w*\b|getInputStream\s*\(|getReader\s*\(",
    re.IGNORECASE,
)

_JAVA_ASSIGNMENT = re.compile(
    r"^\s*(?:(?:final|var|val)\s+)?(?:[A-Za-z_$][\w$<>\[\].,?]*\s+)?"
    r"([A-Za-z_$][\w$]*)\s*=\s*(.+?)\s*;?\s*$"
)
_JAVA_NULL_GUARD = re.compile(
    r"\bif\s*\(\s*([A-Za-z_$][\w$]*)\s*==\s*null\s*\)|"
    r"\bif\s*\(\s*null\s*==\s*([A-Za-z_$][\w$]*)\s*\)"
)
_JAVA_NONNULL_GUARD = re.compile(
    r"\bif\s*\(\s*([A-Za-z_$][\w$]*)\s*!=\s*null\s*\)|"
    r"\bif\s*\(\s*null\s*!=\s*([A-Za-z_$][\w$]*)\s*\)"
)
_JAVA_MAP_DECLARATION = re.compile(
    r"\b(?:Map|HashMap|ConcurrentHashMap|SortedMap|NavigableMap)\s*<[^;=]+>\s*([A-Za-z_$][\w$]*)"
)
_JAVA_KNOWN_NULLABLE_CALL = re.compile(
    r"(?:\brequest\s*\.\s*getParameter|\bSystem\s*\.\s*(?:getenv|getProperty)|"
    r"\b(?:[A-Za-z_$][\w$]*(?:Map|Cache|Repository|Repo|Dao)|map|cache|users|items|records)"
    r"\s*\.\s*(?:get|findBy\w*|lookup\w*))\s*\([^;]*?\)",
    re.IGNORECASE,
)
_JAVA_NULL_SAFE_CHAIN = re.compile(
    r"\.(?:orElseThrow|orElseGet|orElse|ifPresent|isPresent)\s*\(|"
    r"\bObjects\s*\.\s*requireNonNull\s*\(",
    re.IGNORECASE,
)


def _java_guard_exits(lines: list[str], start: int) -> bool:
    """Return true when a small null-guard block exits before fall-through."""
    if "{" not in lines[start]:
        return bool(re.search(r"\b(?:return|throw)\b", lines[start]))
    depth = 0
    saw_block = False
    for index in range(start, min(len(lines), start + 7)):
        line = lines[index]
        if "{" in line:
            saw_block = True
        depth += line.count("{") - line.count("}")
        if re.search(r"\b(?:return|throw)\b", line):
            return True
        if saw_block and index > start and depth <= 0:
            break
    return False


def _java_null_pointer_findings(path: Path, lines: list[str], analysis_lines: list[str]) -> list[Finding]:
    """Conservative intra-file Java/Kotlin null-state analysis.

    Definite ``x = null; x.member`` paths are confirmed. Dereferences of a
    small allowlist of APIs whose contracts permit null are review candidates.
    Arbitrary method returns are deliberately not inferred.
    """
    rule = _RULE_BY_ID["code.null-pointer-dereference"]
    definitely_null: set[str] = set()
    possibly_null: set[str] = set()
    nullable_receivers: set[str] = set()
    nonnull_scopes: list[tuple[str, int]] = []
    nonnull_next_statement: dict[str, int] = {}
    brace_depth = 0
    findings: list[Finding] = []
    seen_lines: set[int] = set()

    for index, line in enumerate(analysis_lines):
        stripped = line.strip()
        if not stripped:
            continue

        nonnull_next_statement = {
            name: statement_index
            for name, statement_index in nonnull_next_statement.items()
            if statement_index >= index
        }
        if re.search(r"\belse\b", stripped):
            # A fact established by the positive branch is not valid in else.
            nonnull_scopes.clear()
        nonnull_scopes = [(name, depth) for name, depth in nonnull_scopes if brace_depth >= depth]
        map_declaration = _JAVA_MAP_DECLARATION.search(stripped)
        if map_declaration:
            nullable_receivers.add(map_declaration.group(1))

        nonnull_guard = _JAVA_NONNULL_GUARD.search(stripped)
        nonnull_on_line: str | None = None
        if nonnull_guard:
            name = nonnull_guard.group(1) or nonnull_guard.group(2)
            if "{" in stripped:
                nonnull_scopes.append((name, brace_depth + 1))
            else:
                next_statement = next(
                    (candidate for candidate in range(index + 1, len(analysis_lines)) if analysis_lines[candidate].strip()),
                    index,
                )
                if next_statement == index:
                    nonnull_on_line = name
                else:
                    nonnull_next_statement[name] = next_statement

        required_nonnull = re.search(
            r"\bObjects\s*\.\s*requireNonNull\s*\(\s*([A-Za-z_$][\w$]*)\s*\)\s*;",
            stripped,
        )
        if required_nonnull:
            name = required_nonnull.group(1)
            definitely_null.discard(name)
            possibly_null.discard(name)

        guard = _JAVA_NULL_GUARD.search(stripped)
        if guard and _java_guard_exits(analysis_lines, index):
            name = guard.group(1) or guard.group(2)
            definitely_null.discard(name)
            possibly_null.discard(name)
            continue

        for name in sorted(definitely_null | possibly_null):
            if not re.search(rf"\b{re.escape(name)}\s*\.(?!\s*class\b)", stripped):
                continue
            if (
                name == nonnull_on_line
                or nonnull_next_statement.get(name) == index
                or any(scope_name == name for scope_name, _ in nonnull_scopes)
            ):
                continue
            if _JAVA_NULL_SAFE_CHAIN.search(stripped):
                continue
            line_number = index + 1
            if line_number in seen_lines:
                continue
            confirmed = name in definitely_null
            findings.append(
                Finding(
                    rule_id=rule.rule_id,
                    category="code",
                    severity=rule.severity,
                    title=rule.title,
                    path=path,
                    line=line_number,
                    evidence=_trim_evidence(lines[index].strip()),
                    description=rule.description,
                    recommendation=rule.recommendation,
                    verification_status="confirmed" if confirmed else "needs_review",
                    verification_note=(
                        "동일 파일에서 null 대입 후 방어 없이 멤버를 참조하는 흐름을 확인했습니다."
                        if confirmed
                        else "null을 반환할 수 있는 API 결과를 즉시 참조합니다. API 계약과 입력 조건을 검토해야 합니다."
                    ),
                )
            )
            seen_lines.add(line_number)

        typed_map_chain = any(
            re.search(rf"\b{re.escape(receiver)}\s*\.\s*get\s*\([^;]*?\)\s*\.\s*[A-Za-z_$]", stripped)
            for receiver in nullable_receivers
        )
        if (_JAVA_KNOWN_NULLABLE_CALL.search(stripped) or typed_map_chain) and re.search(r"\)\s*\.\s*[A-Za-z_$]", stripped):
            if not _JAVA_NULL_SAFE_CHAIN.search(stripped):
                line_number = index + 1
                if line_number not in seen_lines:
                    findings.append(
                        Finding(
                            rule_id=rule.rule_id,
                            category="code",
                            severity=rule.severity,
                            title=rule.title,
                            path=path,
                            line=line_number,
                            evidence=_trim_evidence(lines[index].strip()),
                            description=rule.description,
                            recommendation=rule.recommendation,
                            verification_status="needs_review",
                            verification_note="null을 반환할 수 있는 조회 API의 결과를 즉시 참조합니다. 조회 실패 경로를 확인해야 합니다.",
                        )
                    )
                    seen_lines.add(line_number)

        assignment = _JAVA_ASSIGNMENT.match(stripped)
        if assignment:
            name, expression = assignment.groups()
            normalized_expression = expression.rstrip(";").strip()
            typed_map_lookup = any(
                re.search(rf"\b{re.escape(receiver)}\s*\.\s*get\s*\(", expression)
                for receiver in nullable_receivers
            )
            if normalized_expression == "null" or normalized_expression in definitely_null:
                definitely_null.add(name)
                possibly_null.discard(name)
            elif normalized_expression in possibly_null or (
                (_JAVA_KNOWN_NULLABLE_CALL.search(expression) or typed_map_lookup)
                and not _JAVA_NULL_SAFE_CHAIN.search(expression)
            ):
                definitely_null.discard(name)
                possibly_null.add(name)
            else:
                definitely_null.discard(name)
                possibly_null.discard(name)

        brace_depth += stripped.count("{") - stripped.count("}")

    # Bound report noise without allowing early review candidates to hide a
    # later definite dereference.
    return sorted(
        findings,
        key=lambda finding: (finding.verification_status != "confirmed", finding.line or 0),
    )[:5]


def _java_document_builder_xxe_findings(path: Path, lines: list[str], analysis_lines: list[str]) -> list[Finding]:
    """Find DocumentBuilder XXE paths only when an unsafe builder reaches untrusted XML."""
    findings: list[Finding] = []

    for factory_index, raw_line in enumerate(analysis_lines):
        factory_match = _JAVA_XML_FACTORY.search(raw_line)
        if not factory_match:
            continue

        factory = factory_match.group(1)
        factory_ref = re.escape(factory)
        next_factory_index = next(
            (
                index
                for index in range(factory_index + 1, len(analysis_lines))
                if _JAVA_XML_FACTORY.search(analysis_lines[index])
            ),
            len(analysis_lines),
        )
        builder_pattern = re.compile(
            rf"\b(?:DocumentBuilder\s+)?([A-Za-z_$][\w$]*)\s*=\s*{factory_ref}\s*\.\s*newDocumentBuilder\s*\(\s*\)",
        )
        builder_match: re.Match[str] | None = None
        builder_index: int | None = None
        for index in range(factory_index + 1, next_factory_index):
            builder_match = builder_pattern.search(analysis_lines[index])
            if builder_match:
                builder_index = index
                break

        if builder_match is None or builder_index is None:
            continue

        builder = builder_match.group(1)
        parse_pattern = re.compile(rf"\b{re.escape(builder)}\s*\.\s*parse\s*\((.*)", re.IGNORECASE)
        parse_match: re.Match[str] | None = None
        parse_index: int | None = None
        for index in range(builder_index + 1, next_factory_index):
            candidate = parse_pattern.search(analysis_lines[index])
            if candidate and _JAVA_XML_UNTRUSTED_INPUT.search(candidate.group(1)):
                parse_match = candidate
                parse_index = index
                break

        if parse_match is None or parse_index is None:
            continue

        configuration_lines = analysis_lines[factory_index + 1 : builder_index]
        if _java_xml_factory_is_hardened(factory, configuration_lines):
            continue

        evidence = lines[parse_index].strip()
        findings.append(
            Finding(
                rule_id="code.xml-external-entity",
                category="code",
                severity="high",
                title="XML parser may allow external entity processing",
                path=path,
                line=parse_index + 1,
                evidence=_trim_evidence(evidence),
                description=(
                    "Potentially untrusted XML reaches DocumentBuilder.parse() before safe DTD or external entity "
                    "configuration is confirmed."
                ),
                recommendation=(
                    "Disable DOCTYPE declarations, or disable external general entities, external parameter entities, "
                    "external DTD loading, XInclude, and entity expansion before newDocumentBuilder()."
                ),
            )
        )
        if len(findings) >= 5:
            break

    return findings


_SLASH_COMMENT_SUFFIXES = frozenset(
    {
        ".c", ".cc", ".cpp", ".cs", ".cxx", ".go", ".h", ".hpp", ".java", ".js",
        ".jsx", ".kt", ".php", ".rs", ".swift", ".ts", ".tsx", ".vue",
    }
)
_HASH_COMMENT_SUFFIXES = frozenset({".conf", ".config", ".php", ".properties", ".py", ".rb"})
_HTML_COMMENT_SUFFIXES = frozenset({".html", ".jsp", ".vue", ".xml"})
_TRIPLE_QUOTE_SUFFIXES = frozenset({".py"})
_BACKTICK_STRING_SUFFIXES = frozenset({".go", ".js", ".jsx", ".ts", ".tsx", ".vue"})


def _code_view(lines: list[str], suffix: str) -> list[str]:
    """Return the file with comments removed, keeping line numbers aligned.

    Every rule runs against this view instead of the raw line so that
    commented-out code, block comments, and multi-line docstrings are never
    reported as live findings. String *contents* are preserved because rules
    such as dynamic-SQL detection need the literal text; only multi-line
    string bodies (Python docstrings) are dropped, since a rule cannot tell
    prose from code inside them.
    """
    line_tokens: tuple[str, ...] = ()
    if suffix in _SLASH_COMMENT_SUFFIXES:
        line_tokens += ("//",)
    if suffix in _HASH_COMMENT_SUFFIXES:
        line_tokens += ("#",)
    block_open, block_close = ("/*", "*/") if suffix in _SLASH_COMMENT_SUFFIXES else ("", "")
    html_comments = suffix in _HTML_COMMENT_SUFFIXES
    triples = ('"""', "'''") if suffix in _TRIPLE_QUOTE_SUFFIXES else ()
    quotes = {'"', "'"} | ({"`"} if suffix in _BACKTICK_STRING_SUFFIXES else set())

    if not line_tokens and not block_open and not html_comments:
        return lines

    stripped: list[str] = []
    open_block: str | None = None
    open_triple: str | None = None

    for raw_line in lines:
        output: list[str] = []
        # Single-quote strings never span lines in these languages, so quote
        # state must reset per line or one stray apostrophe blinds the rest.
        quote: str | None = None
        escaped = False
        index = 0
        # Indexed scanning, never slicing: a minified line is a single very long
        # line, and `raw_line[index:]` per character makes that quadratic.
        while index < len(raw_line):
            if open_triple is not None:
                end = raw_line.find(open_triple, index)
                if end < 0:
                    break
                index = end + len(open_triple)
                open_triple = None
                continue
            if open_block is not None:
                end = raw_line.find(open_block, index)
                if end < 0:
                    break
                index = end + len(open_block)
                open_block = None
                continue
            current = raw_line[index]
            if quote:
                output.append(current)
                if escaped:
                    escaped = False
                elif current == "\\":
                    escaped = True
                elif current == quote:
                    quote = None
                index += 1
                continue
            triple = next((token for token in triples if raw_line.startswith(token, index)), None)
            if triple is not None:
                end = raw_line.find(triple, index + len(triple))
                if end < 0:
                    open_triple = triple
                    break
                # Opened and closed on one line: a normal string literal.
                output.append(raw_line[index : end + len(triple)])
                index = end + len(triple)
                continue
            if any(raw_line.startswith(token, index) for token in line_tokens):
                break
            if block_open and raw_line.startswith(block_open, index):
                end = raw_line.find(block_close, index + len(block_open))
                if end < 0:
                    open_block = block_close
                    break
                index = end + len(block_close)
                continue
            if html_comments and raw_line.startswith("<!--", index):
                end = raw_line.find("-->", index + 4)
                if end < 0:
                    open_block = "-->"
                    break
                index = end + 3
                continue
            if current in quotes:
                quote = current
                output.append(current)
                index += 1
                continue
            output.append(current)
            index += 1
        stripped.append("".join(output))
    return stripped


def _last_java_boolean_call(factory_ref: str, method: str, configuration: str) -> bool | None:
    matches = list(
        re.finditer(
            rf"\b{factory_ref}\s*\.\s*{method}\s*\(\s*(true|false)\s*\)",
            configuration,
            re.IGNORECASE,
        )
    )
    return matches[-1].group(1).lower() == "true" if matches else None


def _java_xml_factory_is_hardened(factory: str, configuration_lines: list[str]) -> bool:
    configuration = "\n".join(configuration_lines)
    factory_ref = re.escape(factory)

    # A swallowed parser-configuration failure makes the control fail open.
    for catch in re.finditer(
        r"catch\s*\([^)]*(?:ParserConfigurationException|SAXNotRecognizedException|SAXNotSupportedException)[^)]*\)\s*\{([^}]*)\}",
        configuration,
        re.IGNORECASE | re.DOTALL,
    ):
        if not re.search(r"\b(throw|return)\b", catch.group(1)):
            return False

    feature_states: dict[str, bool] = {}
    feature_pattern = re.compile(
        rf"\b{factory_ref}\s*\.\s*setFeature\s*\(\s*[\"']([^\"']+)[\"']\s*,\s*(true|false)\s*\)",
        re.IGNORECASE,
    )
    for feature in feature_pattern.finditer(configuration):
        feature_states[feature.group(1).lower()] = feature.group(2).lower() == "true"

    if feature_states.get("http://apache.org/xml/features/disallow-doctype-decl") is True:
        return True

    external_entities_disabled = all(
        feature_states.get(feature) is False
        for feature in (
            "http://xml.org/sax/features/external-general-entities",
            "http://xml.org/sax/features/external-parameter-entities",
            "http://apache.org/xml/features/nonvalidating/load-external-dtd",
        )
    )
    xinclude_disabled = _last_java_boolean_call(factory_ref, "setXIncludeAware", configuration) is False
    entity_expansion_disabled = (
        _last_java_boolean_call(factory_ref, "setExpandEntityReferences", configuration) is False
    )
    if external_entities_disabled and xinclude_disabled and entity_expansion_disabled:
        return True

    return False


_RULE_BY_ID = {rule.rule_id: rule for rule in CODE_PATTERN_RULES}
_ASSIGNMENT = re.compile(
    r"^\s*(?:(?:const|let|var|final)\s+)?"
    r"(?:(?:[A-Za-z_$][\w$<>\[\].,?]*\s+))?"
    r"([A-Za-z_$][\w$]*)\s*(?::[^=]+)?=\s*(.+)$"
)
# The confirming dataflow pass only follows remote input; a local CLI argument
# is not enough evidence to call a flow proven.
_UNTRUSTED = re.compile(rf"(?:{REMOTE_SOURCE})", re.IGNORECASE)
# Mass assignment is about binding a whole request body onto a model, not about
# any call that happens to mention the request.
_REQUEST_BODY = re.compile(
    r"\b(?:req|request)\s*\.\s*(?:body|data|json|POST|form|params|query|values)\b",
    re.IGNORECASE,
)
_SANITIZERS = re.compile(
    r"\b(DOMPurify\.sanitize|sanitizeHtml|escapeHtml|html\.escape|encodeForHTML|"
    r"secure_filename|Path\.GetFileName|basename|realpath|canonicalPath|"
    r"allowlist|allowed_hosts?|validate(?:Url|Path|Host|Redirect|Input)|"
    r"escapeLdap|encodeForLDAP|stripCrLf|sanitizeHeader)\b",
    re.IGNORECASE,
)

_CONTEXT_SINKS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("code.sql-dynamic-query", re.compile(r"\b(execute|executemany|query|raw|prepareStatement|createQuery)\s*\(", re.IGNORECASE)),
    ("code.xss-dom-sink", re.compile(r"\b(innerHTML|outerHTML|insertAdjacentHTML|document\.write|dangerouslySetInnerHTML)\b", re.IGNORECASE)),
    ("code.command-injection", re.compile(r"\b(os\.system|os\.popen|subprocess\.(?:run|call|Popen|check_output)|child_process\.(?:exec|execSync)|shell_exec|passthru|Runtime\.getRuntime\(\)\.exec)\s*\(", re.IGNORECASE)),
    # Bare `open(` or an explicit filesystem module only: `self.parent.open()`
    # in a URL opener is not a file API.
    ("code.path-traversal", re.compile(r"(?<![.\w])open\s*\(|\b(?:os|io|codecs|shutil|aiofiles)\.open\s*\(|\b(send_file|FileResponse|readFile|readFileSync|createReadStream|writeFile|writeFileSync)\s*\(", re.IGNORECASE)),
    ("code.eval-user-input", re.compile(r"\b(eval|exec|(?-i:Function)|instance_eval|class_eval)\s*\(", re.IGNORECASE)),
    ("code.eval-user-input", re.compile(r"\b(?:setTimeout|setInterval)\s*\(\s*[\"'`]", re.IGNORECASE)),
    ("code.ssrf-user-url", re.compile(r"\b(requests\.(?:get|post|put|patch|delete|request)|httpx\.(?:get|post|put|patch|delete|request)|urllib\.request\.urlopen|axios\.(?:get|post|put|patch|delete)|fetch|http\.get|https\.get|RestTemplate|WebClient)\b", re.IGNORECASE)),
    ("code.open-redirect-user-input", re.compile(r"\b(sendRedirect|redirect|(?:res|response|ctx)\.redirect)\s*\(", re.IGNORECASE)),
    (
        "code.ldap-injection",
        re.compile(
            r"\b(?:ldap(?:[_-]?(?:client|connection|template))?|dirContext)\s*\.\s*(?:search|search_s|search_ext)\s*\(",
            re.IGNORECASE,
        ),
    ),
    ("code.http-response-splitting", re.compile(r"\b(setHeader|addHeader|set_header|writeHead)\s*\(", re.IGNORECASE)),
    ("code.unsafe-deserialization", re.compile(r"\b(pickle\.loads?|yaml\.load|ObjectInputStream|BinaryFormatter|unserialize|Marshal\.load|readObject)\b", re.IGNORECASE)),
    ("code.unrestricted-file-upload", re.compile(r"\b(move_uploaded_file|save|writeFile|writeFileSync)\s*\(", re.IGNORECASE)),
    ("code.api-mass-assignment", re.compile(r"\b(create|update|assign|save|insert|merge)\s*\(", re.IGNORECASE)),
    ("code.format-string-user-input", re.compile(r"\b(printf|vprintf|syslog|fprintf|String\.format)\s*\(", re.IGNORECASE)),
    ("code.xml-injection", re.compile(r"(?:<[A-Za-z][\w:-]*>|XML|Document)\b.*(?:\+|%|\.format\(|\$\{)", re.IGNORECASE)),
    ("code.llm-prompt-user-concat", re.compile(r"\b(system|developer|prompt|messages?)\b.*(?:\+|f[\"']|`\$\{)", re.IGNORECASE)),
)


# Rules that match a sensitive *word*. Plain English inside a string literal
# ("session established") is prose, not data being logged, so these rules are
# re-checked against the line with literal prose removed.
_PROSE_SENSITIVE_RULES = frozenset(
    {"code.logging-sensitive-data", "code.pii-logging", "code.llm-sensitive-data-in-prompt"}
)
_STRING_LITERAL = re.compile(r"(['\"`])(?:\\.|(?!\1).)*?\1")
# Only interpolated expressions stay. A bare label inside a literal is prose:
# `"shlex: token="` is a debug caption, not a credential reaching the log.
_LITERAL_KEEP = re.compile(r"\$\{[^}]*\}|\{[^{}]*\}")


def _mask_literal_prose(line: str) -> str:
    def replace(match: re.Match[str]) -> str:
        kept = " ".join(item.group(0) for item in _LITERAL_KEEP.finditer(match.group(0)))
        return f'"{kept}"'

    return _STRING_LITERAL.sub(replace, line)


def _contains_name(expression: str, names: set[str]) -> bool:
    return any(re.search(rf"\b{re.escape(name)}\b", expression) for name in names)


def _without_sanitizer_calls(expression: str) -> str:
    """Remove balanced sanitizer-call expressions before checking remaining taint.

    This keeps `sanitize(trusted) + tainted` unsafe while treating
    `sanitize(tainted)` as a guarded value. It is deliberately parser-light and
    falls back to the original text when a call is incomplete.
    """
    output = expression
    offset = 0
    for match in list(_SANITIZERS.finditer(expression)):
        start = match.start() + offset
        cursor = match.end() + offset
        while cursor < len(output) and output[cursor].isspace():
            cursor += 1
        if cursor >= len(output) or output[cursor] != "(":
            continue
        depth = 0
        quote: str | None = None
        escaped = False
        end = cursor
        while end < len(output):
            char = output[end]
            if quote:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == quote:
                    quote = None
            elif char in {'"', "'"}:
                quote = char
            elif char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                if depth == 0:
                    end += 1
                    break
            end += 1
        if depth != 0:
            continue
        output = output[:start] + (" " * (end - start)) + output[end:]
        offset = len(output) - len(expression)
    return output


def _has_unsanitized_taint(expression: str, tainted: set[str]) -> bool:
    remaining = _without_sanitizer_calls(expression)
    return bool(_UNTRUSTED.search(remaining) or _contains_name(remaining, tainted))


def _safe_command_arguments(line: str) -> bool:
    return bool(
        re.search(r"\bsubprocess\.(?:run|call|Popen|check_output)\s*\(\s*\[", line, re.IGNORECASE)
        and not re.search(r"shell\s*=\s*True", line, re.IGNORECASE)
    )


def _safe_sql_binding(line: str) -> bool:
    return bool(
        re.search(
            r"\b(execute|executemany|query|prepareStatement|createQuery)\s*\(\s*[furb]*[\"'][^\"']*(?:\?|%s|:\w+|\$\d+)[^\"']*[\"']\s*,",
            line,
            re.IGNORECASE,
        )
    )


def _candidate_is_suppressed(
    rule_id: str,
    line: str,
    document: str,
    lines: list[str] | None = None,
    line_number: int | None = None,
) -> bool:
    if lines is not None and line_number is not None:
        start = max(0, line_number - 6)
        end = min(len(lines), line_number + 5)
        nearby = "\n".join(lines[start:end])
    else:
        nearby = line
    if rule_id == "code.api-missing-rate-limit" and re.search(
        r"\b(express-rate-limit|rateLimit\s*\(|RateLimiter|SlowAPIMiddleware|@\w*limiter\.limit|Bucket4j|resilience4j[^\n]*ratelimit)",
        document,
        re.IGNORECASE,
    ):
        return True
    if rule_id == "code.api-route-missing-auth" and re.search(
        r"\b(app|router|server)\.use\s*\([^\n]*(?:authenticate|authorize|requireAuth|requireAdmin)|"
        r"\b(?:SecurityFilterChain|OncePerRequestFilter|AuthMiddleware|AuthorizationMiddleware)\b",
        document,
        re.IGNORECASE,
    ):
        return True
    if rule_id == "code.unsafe-deserialization" and re.search(
        r"yaml\.load\s*\([^\n]*(?:Loader\s*=\s*yaml\.SafeLoader|SafeLoader)", line, re.IGNORECASE
    ):
        return True
    if rule_id == "code.command-injection" and _safe_command_arguments(line):
        return True
    if rule_id == "code.sql-dynamic-query" and _safe_sql_binding(line):
        return True
    if rule_id == "code.format-string-user-input":
        constant = re.search(r"\bString\.format\s*\(\s*([A-Z][A-Z0-9_]*)\s*[,)]", line)
        if constant and re.search(
            rf"\b(?:static\s+)?final\s+String\s+{re.escape(constant.group(1))}\s*=\s*[\"']",
            document,
        ):
            return True
    if rule_id in {
        "code.xss-dom-sink",
        "code.path-traversal",
        "code.ssrf-user-url",
        "code.open-redirect-user-input",
        "code.ldap-injection",
        "code.http-response-splitting",
    } and _SANITIZERS.search(line):
        return True
    if rule_id == "code.api-route-missing-auth" and re.search(
        r"\b(requireAuth|requireAdmin|authenticate|authorize|isAuthenticated|checkPermission)\b", line, re.IGNORECASE
    ):
        return True
    # `usedforsecurity=False` is the caller declaring this hash is not a
    # security control; `\b` would miss `file_checksum`, because `_` is itself
    # a word character.
    if rule_id == "code.weak-hash" and (
        re.search(r"usedforsecurity\s*=\s*False", line, re.IGNORECASE)
        or re.search(
            r"\w*(?:checksum|etag|cache[_-]?key|content[_-]?hash|file[_-]?hash)\w*", nearby, re.IGNORECASE
        )
    ):
        return True
    if rule_id in _PROSE_SENSITIVE_RULES and not _RULE_BY_ID[rule_id].pattern.search(_mask_literal_prose(line)):
        return True
    if rule_id == "code.external-api-no-timeout" and re.search(
        r"\b(timeout|signal|AbortController)\s*[:=]", nearby, re.IGNORECASE
    ):
        return True
    if rule_id == "code.stack-trace-exposure" and re.search(
        r"\b(?:if|guard)\b[^\n]*(?:DEBUG|development|isDev|devMode)", nearby, re.IGNORECASE
    ):
        return True
    return False


_MAX_CONTINUATION_LINES = 4


def _open_depth(text: str) -> int:
    depth = 0
    quote: str | None = None
    escaped = False
    for char in text:
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in {'"', "'", "`"}:
            quote = char
        elif char in {"(", "["}:
            depth += 1
        elif char in {")", "]"}:
            depth -= 1
    return depth


def _logical_lines(code_lines: list[str]) -> list[str]:
    """Join argument lists that continue onto following lines.

    A statement split over several lines is still one statement, and matching
    each fragment alone is exactly the single-line reading this scanner avoids.
    A line ending in ``{`` opens a block rather than an argument list, so a
    route handler is never merged into its own declaration.
    """
    joined: list[str] = []
    for index, line in enumerate(code_lines):
        text = line
        if not line.rstrip().endswith("{"):
            cursor = index
            while (
                _open_depth(text) > 0
                and cursor + 1 < len(code_lines)
                and cursor - index < _MAX_CONTINUATION_LINES
            ):
                cursor += 1
                text = f"{text} {code_lines[cursor].strip()}"
        joined.append(text)
    return joined


def _call_arguments(line: str, call_end: int) -> str | None:
    """Return the argument text of a call whose name ends at ``call_end``.

    Returns ``None`` when the sink is not a call (for example an ``innerHTML``
    assignment) so the caller can fall back to line scope.
    """
    cursor = call_end
    while cursor < len(line) and line[cursor].isspace():
        cursor += 1
    if cursor >= len(line) or line[cursor] != "(":
        return None
    depth = 0
    quote: str | None = None
    escaped = False
    for index in range(cursor, len(line)):
        char = line[index]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in {'"', "'", "`"}:
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return line[cursor + 1 : index]
    # Unbalanced (call continues on the next line): treat the remainder as args.
    return line[cursor + 1 :]


def _contextual_dataflow_findings(path: Path, lines: list[str], code_lines: list[str]) -> list[Finding]:
    """Confirm simple intra-file source-to-sink flows and sanitizer boundaries.

    This intentionally stays conservative: aliases and direct assignments are
    followed, while unresolved inter-procedural or project-wide context remains
    a review candidate instead of being promoted to a violation.
    """
    findings: list[Finding] = []
    tainted: set[str] = set()
    sanitized: set[str] = set()

    for line_number, code_line in enumerate(code_lines, start=1):
        line = code_line.strip()
        if not line or _is_comment(line):
            continue

        assignment = _ASSIGNMENT.match(line)
        if assignment:
            name, expression = assignment.groups()
            if _has_unsanitized_taint(expression, tainted):
                tainted.add(name)
                sanitized.discard(name)
            elif _SANITIZERS.search(expression):
                tainted.discard(name)
                sanitized.add(name)
            else:
                tainted.discard(name)
                sanitized.discard(name)

        reaches_sink = _has_unsanitized_taint(line, tainted)
        if not reaches_sink:
            continue

        for rule_id, sink in _CONTEXT_SINKS:
            match = sink.search(line)
            if not match:
                continue
            # Taint anywhere on the line is not enough for a call sink: the
            # untrusted value has to be an argument of that call, otherwise
            # `ctx.save()` next to unrelated request handling reads as a flow.
            arguments = _call_arguments(line, match.end())
            if arguments is not None and not _has_unsanitized_taint(arguments, tainted):
                continue
            if rule_id == "code.command-injection" and _safe_command_arguments(line):
                continue
            if rule_id == "code.sql-dynamic-query" and _safe_sql_binding(line):
                continue
            if rule_id == "code.api-mass-assignment" and not _REQUEST_BODY.search(arguments or line):
                continue
            rule = _RULE_BY_ID[rule_id]
            findings.append(
                Finding(
                    rule_id=rule.rule_id,
                    category="code",
                    severity=rule.severity,
                    title=rule.title,
                    path=path,
                    line=line_number,
                    evidence=_trim_evidence(lines[line_number - 1].strip()),
                    description=rule.description,
                    recommendation=rule.recommendation,
                    verification_status="confirmed",
                    verification_note="동일 파일에서 외부 입력이 방어 처리 없이 위험 동작까지 전달되는 흐름을 확인했습니다.",
                )
            )
            break
        if len(findings) >= 45:
            break
    return findings


def check_file(path: Path, target: TargetConfig) -> list[Finding]:
    if not is_text_candidate(path) or (path.suffix.lower() not in CODE_EXTENSIONS and path.name not in CODE_FILENAMES):
        return []

    lines = read_text_lines(path, target.max_file_size_bytes)
    if lines is None:
        return []

    # Recognized dependency sources are inventory input, not meaningful
    # application source for line-regex analysis. A banner alone is insufficient:
    # first-party bundles often include a library banner before application code.
    if path.suffix.lower() in {".js", ".mjs", ".cjs"}:
        parts = {part.lower().replace("-", "_") for part in path.parts}
        banner = "\n".join(lines[:5])[:2000]
        is_dependency_path = bool(parts.intersection({"node_modules", "vendor", "vendors", "thirdparty", "third_party"}))
        has_library_banner = bool(re.search(
            r"(?i)\b(jquery|lodash|bootstrap|angular|react|vue|moment)\b[^\n]{0,100}\bv?\d+(?:\.\d+)+",
            banner,
        ))
        versioned_library_file = re.match(
            r"(?i)^(jquery|lodash|bootstrap|angular|react(?:\.production)?|vue(?:\.runtime)?|moment)"
            r"[._-]?v?\d+(?:\.\d+)*(?:\.min)?\.(?:js|mjs|cjs)$",
            path.name,
        )
        named_library_file = re.match(
            r"(?i)^(jquery|lodash|bootstrap|angular|react(?:\.production)?|vue(?:\.runtime)?|moment)"
            r"(?:\.min)?\.(?:js|mjs|cjs)$",
            path.name,
        )
        if versioned_library_file or (named_library_file and (is_dependency_path or has_library_banner)) or (
            is_dependency_path and has_library_banner
        ):
            return []

    suffix = path.suffix.lower()
    # Every rule below reads the whole-file code view, not the raw line, so a
    # single line is never judged out of its file context.
    code_lines = _code_view(lines, suffix)
    statements = _logical_lines(code_lines)
    findings = _java_document_builder_xxe_findings(path, lines, code_lines) if suffix in {".java", ".kt"} else []
    if suffix in {".java", ".kt"}:
        findings.extend(_java_null_pointer_findings(path, lines, code_lines))
    findings.extend(_contextual_dataflow_findings(path, lines, statements))
    per_rule_counts: dict[str, int] = {}
    seen_locations: set[tuple[str, int | None]] = set()
    for finding in findings:
        per_rule_counts[finding.rule_id] = per_rule_counts.get(finding.rule_id, 0) + 1
        seen_locations.add((finding.rule_id, finding.line))
    document = "\n".join(code_lines)
    filename = path.name
    for line_number, code_line in enumerate(statements, start=1):
        line = code_line.strip()
        if not line or _is_comment(line):
            continue
        for rule in CODE_PATTERN_RULES:
            if suffix not in rule.extensions and filename not in rule.extensions:
                continue
            if (
                rule.rule_id == "code.xml-external-entity"
                and suffix in {".java", ".kt"}
                and "DocumentBuilderFactory" in line
            ):
                continue
            if per_rule_counts.get(rule.rule_id, 0) >= 5:
                continue
            if rule.pattern.search(line):
                if (rule.rule_id, line_number) in seen_locations:
                    continue
                if _candidate_is_suppressed(rule.rule_id, line, document, code_lines, line_number):
                    continue
                findings.append(
                    Finding(
                        rule_id=rule.rule_id,
                        category="code",
                        severity=rule.severity,
                        title=rule.title,
                        path=path,
                        line=line_number,
                        evidence=_trim_evidence(lines[line_number - 1].strip()),
                        description=rule.description,
                        recommendation=rule.recommendation,
                        verification_status="needs_review",
                        verification_note=(
                            "소스 파일 전체의 설정과 방어 패턴을 함께 확인했지만 위험 흐름을 확정할 "
                            "충분한 근거가 없습니다. 함수 간 호출과 업무 중요도를 추가 검토해야 합니다."
                        ),
                    )
                )
                per_rule_counts[rule.rule_id] = per_rule_counts.get(rule.rule_id, 0) + 1
    return findings


def _is_comment(line: str) -> bool:
    return line.startswith(("#", "//", "/*", "*", "<!--"))


def _trim_evidence(line: str) -> str:
    return line if len(line) <= 240 else f"{line[:237]}..."
