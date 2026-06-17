# KODA 보안 점검 리포트

- 생성 시각: 2026-05-16 00:16:36
- 점검 대상: 1
- 스캔 파일: 60
- 위험 점수: 580

## 위험점수 계산

위험 점수는 치명 100점, 높음 40점, 중간 10점, 낮음 3점, 정보 1점을 발견 항목별로 더한 값입니다.

## 위험군별 분포

- 치명: 2
- 높음: 6
- 중간: 14
- 낮음: 0
- 정보: 0

## 경고

- 예외 파일(koda-ignore.yml)로 3건 제외: security

## 발견 항목

| 심각도 | 발견 항목 | Rule | 분류 | 경로 | 근거 | 조치 |
| --- | --- | --- | --- | --- | --- | --- |
| 치명 | 개인 키가 파일에 포함됨 | secret.private-key | 비밀값 | security/platforms/macos/KODA/KODA/NativeSecurityScanner.swift:959 | if line.contains("-----BEGIN") && line.contains("PRIVATE KEY-----") { | 개인 키를 즉시 폐기하고 안전한 비밀 관리 저장소로 이동하세요. |
| 치명 | 개인 키가 파일에 포함됨 | secret.private-key | 비밀값 | security/security_scanner/checks/secrets.py:37 | re.compile(r"-----BEGIN (?:RSA \|DSA \|EC \|OPENSSH \|PGP )?PRIVATE KEY-----"), | 개인 키를 즉시 폐기하고 안전한 비밀 관리 저장소로 이동하세요. |
| 높음 | 사용자 입력 URL 요청으로 인한 SSRF 위험 | code.ssrf-user-url | 코드 패턴 | security/docs/security-dashboard-research.md:49 | - Code-pattern heuristics: common risky sinks such as dynamic SQL, unsafe HTML rendering, shell execution, path use, SSRF fetches, disabled CSRF/auth checks, unsafe deserialization, file upload saves, request body parsin | 허용된 호스트만 요청하고 사설망 대역 접근을 차단하세요. |
| 높음 | 위험한 역직렬화 사용 | code.unsafe-deserialization | 코드 패턴 | security/platforms/macos/KODA/KODA/NativeSecurityScanner.swift:1222 | if matches(#"(?i)(pickle\\.loads\|yaml\\.load\|ObjectInputStream\|unserialize\\()"#, line) { | 신뢰할 수 없는 입력의 역직렬화를 금지하고 안전 로더를 사용하세요. |
| 높음 | 사용자 입력 URL 요청으로 인한 SSRF 위험 | code.ssrf-user-url | 코드 패턴 | security/platforms/macos/KODA/KODA/NativeSecurityScanner.swift:1225 | if matches(#"(?i)\\b(requests\|httpx\|urllib\\.request\|axios\|fetch\|http\\.get\|https\\.get\|RestTemplate\|WebClient).*(get\|post\|open\|request\|\\().*(req\\.\|request\\.\|\\$_(GET\|POST\|REQUEST\|FILES)\|params\|query\|body\|location\\.\|input\\(\|s | 허용된 호스트만 요청하고 사설망 대역 접근을 차단하세요. |
| 높음 | XML 외부 엔티티 처리가 허용될 수 있음 | code.xml-external-entity | 코드 패턴 | security/platforms/macos/KODA/KODA/NativeSecurityScanner.swift:1273 | if matches(#"(?i)(resolve_entities\\s*=\\s*True\|load_dtd\\s*=\\s*True\|DocumentBuilderFactory\|SAXParserFactory\|XmlReaderSettings\|XmlDocument)"#, line) { | DTD와 외부 엔티티 해석을 비활성화한 안전한 XML parser 설정을 사용하세요. |
| 높음 | DOM XSS 위험 sink | code.xss-dom-sink | 코드 패턴 | security/tests/test_scanner.py:652 | archive.writestr("web/views.js", "document.body.innerHTML = location.hash\\n") | 신뢰할 수 없는 입력을 HTML로 직접 삽입하지 말고 escaping 또는 textContent를 사용하세요. |
| 높음 | DOM XSS 위험 sink | code.xss-dom-sink | 코드 패턴 | security/tests/test_scanner.py:910 | "document.body.innerHTML = location.hash\\n", | 신뢰할 수 없는 입력을 HTML로 직접 삽입하지 말고 escaping 또는 textContent를 사용하세요. |
| 중간 | 경로 조작 위험 | code.path-traversal | 코드 패턴 | security/platforms/macos/KODA/KODA/NativeSecurityScanner.swift:1210 | if matches(#"(?i)(send_file\|sendfile\|readFile\|createReadStream).*(request\|req\\.\|params\|query)"#, line) { | 사용자 입력 경로를 정규화하고 허용된 루트 내부인지 검증하세요. |
| 중간 | CSRF 보호가 비활성화된 것으로 보임 | code.csrf-disabled | 코드 패턴 | security/platforms/macos/KODA/KODA/NativeSecurityScanner.swift:1213 | if matches(#"(?i)(@csrf_exempt\|csrf\\s*:\\s*false\|csrf\\.disable\|verify_csrf_token.*false\|skip_before_action\\s+:verify_authenticity_token\|protect_from_forgery\\s+except:)"#, line) { | 브라우저 인증 기반 상태 변경 요청에는 CSRF 보호를 유지하세요. |
| 중간 | 인증 또는 인가가 우회된 엔드포인트 | code.auth-disabled-endpoint | 코드 패턴 | security/platforms/macos/KODA/KODA/NativeSecurityScanner.swift:1216 | if matches(#"(?i)(@AllowAnonymous\|@Public\\(\\)\|permitAll\\(\\)\|auth\\s*:\\s*false\|AllowAny\|permission_classes\\s*=\\s*\\[\\s*\\]\|skip_before_action\\s+:authenticate)"#, line) { | 공개 의도가 명확한지 확인하고 민감 기능에는 권한 검사를 적용하세요. |
| 중간 | 와일드카드 CORS 설정 | code.wildcard-cors | 코드 패턴 | security/platforms/macos/KODA/KODA/NativeSecurityScanner.swift:1252 | if matches(#"(?i)(CORS\|Access-Control-Allow-Origin).*(\\*\|origins\\s*=\\s*['\\"]\\*)"#, line) { | 허용 origin을 명시적으로 제한하세요. |
| 중간 | 레거시 게시판 소프트웨어 흔적 | code.legacy-board-software | 코드 패턴 | security/platforms/macos/KODA/KODA/NativeSecurityScanner.swift:1270 | if matches(#"(?i)\\b(technote\|zeroboard)\\b"#, line) { | 컴포넌트 사용 여부를 확인하고 최신 버전으로 교체하거나 제거하세요. |
| 중간 | WebDAV 활성화 흔적 | code.webdav-enabled | 코드 패턴 | security/platforms/macos/KODA/KODA/NativeSecurityScanner.swift:2188 | case "code.webdav-enabled": return "WebDAV enabled" | 필요하지 않은 WebDAV 기능을 비활성화하세요. |
| 중간 | 와일드카드 CORS 설정 | code.wildcard-cors | 코드 패턴 | security/security_scanner/checks/code_patterns.py:269 | r"(Access-Control-Allow-Origin[\\"']?\\s*[:,]\\s*[\\"']\\*\|allow_origins\\s*=\\s*\\[\\s*[\\"']\\*\|" | 허용 origin을 명시적으로 제한하세요. |
| 중간 | 하드코딩된 비밀값 의심 대입 | secret.generic-assignment | 비밀값 | security/security_scanner/cli.py:204 | api_key = args.api_key or api_key_from_env(args.api_key_env) | 코드에 값을 직접 두지 말고 런타임 비밀 주입을 사용하세요. |
| 중간 | 레거시 게시판 소프트웨어 흔적 | code.legacy-board-software | 코드 패턴 | security/security_scanner/standards.py:1188 | "technote", | 컴포넌트 사용 여부를 확인하고 최신 버전으로 교체하거나 제거하세요. |
| 중간 | 레거시 게시판 소프트웨어 흔적 | code.legacy-board-software | 코드 패턴 | security/security_scanner/standards.py:1189 | {"en": "Technote", "ko": "테크노트"}, | 컴포넌트 사용 여부를 확인하고 최신 버전으로 교체하거나 제거하세요. |
| 중간 | 레거시 게시판 소프트웨어 흔적 | code.legacy-board-software | 코드 패턴 | security/security_scanner/standards.py:1194 | "zeroboard", | 컴포넌트 사용 여부를 확인하고 최신 버전으로 교체하거나 제거하세요. |
| 중간 | 레거시 게시판 소프트웨어 흔적 | code.legacy-board-software | 코드 패턴 | security/security_scanner/standards.py:1195 | {"en": "Zeroboard", "ko": "제로보드"}, | 컴포넌트 사용 여부를 확인하고 최신 버전으로 교체하거나 제거하세요. |
| 중간 | 디렉터리 리스팅 활성화 | code.directory-listing-enabled | 코드 패턴 | security/tests/test_scanner.py:1089 | (root / ".htaccess").write_text("Options Indexes\\n", encoding="utf-8") | 디렉터리 인덱싱을 비활성화하세요. |
| 중간 | WebDAV 활성화 흔적 | code.webdav-enabled | 코드 패턴 | security/tests/test_scanner.py:1090 | (root / "web.config").write_text("<add name=\\"WebDAVModule\\" />\\n", encoding="utf-8") | 필요하지 않은 WebDAV 기능을 비활성화하세요. |