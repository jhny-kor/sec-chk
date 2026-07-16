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
