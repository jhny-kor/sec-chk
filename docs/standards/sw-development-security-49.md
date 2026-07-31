# 소프트웨어 개발보안 49 (SW_DEV_SECURITY_49)

행정안전부·KISA 「소프트웨어 보안약점 진단가이드」의 **구현단계 보안약점 49개**를 KODA에서 기준별로 추적하는 프로파일입니다. 기준연도는 진단가이드 2021 개정판(7개 유형 · 49개 보안약점 체계)입니다.

공식 기준 원문: [행정안전부 소프트웨어 개발보안 가이드(2021.11.30 개정)](https://www.mois.go.kr/frt/bbs/type001/commonSelectBoardArticle.do?bbsId=BBSMSTR_000000000015&nttId=88956)

표의 번호는 공식 가이드의 유형·항목 번호이며, 괄호 안의 `I-01`~`A-02`는 KODA에서 유지하는 안정 식별자입니다. CWE는 각 보안약점을 설명하고 교차참조하기 위한 참조 분류이며, 공식 가이드의 항목 번호를 대체하지 않습니다.

## 동작 원칙

- 공식 기준 49개가 각각 독립된 `SecurityControl`로 등록됩니다 (`security_scanner/standards.py`의 `SW49_CONTROLS`).
- 하나의 공식 기준에 여러 KODA 룰이 연결될 수 있으며, 반대로 일반 KODA 룰을 무관한 기준에 연결하지 않습니다.
- **탐지 0건은 준수를 의미하지 않습니다.** 판정 상태는 다음과 같이 구분됩니다.

| 판정 | 의미 |
| --- | --- |
| `PASS` (통과) | 완전 자동 지원 기준의 룰이 실제로 실행되었고 취약 패턴이 없음 |
| `VULNERABLE` (취약) | 외부 입력에서 위험 동작까지의 흐름과 방어 부재를 결정론적으로 확인함 |
| `NEEDS_REVIEW` (수동 검토 필요) | 부분 자동 또는 수동 검토 기준 — 정적 분석만으로 최종 판정 불가 |
| `UNSUPPORTED` (미지원) | 현재 프로파일에는 없으며, 향후 지원 제거 시에만 사용 |
| `NOT_APPLICABLE` (해당 없음) | 대상 기술에서 적용되지 않음 |
| `NOT_SCANNED` (미실행) | 필요한 스캔 카테고리가 실행되지 않음 |

- 수동 검토·부분 점검·미실행 기준은 절대 근거 없이 `PASS`로 표시되지 않습니다.
- 부분 자동(`partial`) 기준은 탐지 0건이어도 `NEEDS_REVIEW`로 남습니다. 자동화가 기준의 일부만 다루기 때문입니다.
- 각 발견은 `verification_status`가 `confirmed` 또는 `needs_review`입니다. 위험 API·설정 한 줄만 일치한 결과는 `needs_review`이며 취약 확정 건수나 실패 게이트에 포함하지 않습니다.
- 파일 내에서 확인 가능한 입력원, 변수 전달, sanitizer/allowlist, parameter binding, sink를 함께 분석합니다. 함수·파일·프로젝트 경계를 넘는 전역 설정과 업무 중요도는 검토 대상으로 남깁니다.

## 지원 수준 요약

| 지원 수준 | 개수 |
| --- | --- |
| 자동 (automated) | 0 |
| 부분 자동 (partial) | 49 |
| 수동 검토 (manual-review) | 0 |
| 미지원 (unsupported) | 0 |

## 기준별 매핑

### 입력데이터 검증 및 표현 (17)

| 기준 | CWE | 지원 수준 | KODA 룰 | 지원 언어 | 비고 |
| --- | --- | --- | --- | --- | --- |
| 1.1 (I-01) SQL 삽입 | 89 | 부분 자동 | code.sql-dynamic-query, web.sql-injection-error-verified | 웹 언어 전반 | web.* 룰은 웹 점검 실행 시에만 |
| 1.2 (I-02) 코드 삽입 | 94, 95 | 부분 자동 | code.eval-user-input | JS/TS/Python/PHP/Ruby | |
| 1.3 (I-03) 경로 조작 및 자원 삽입 | 22, 99 | 부분 자동 | code.path-traversal | 웹 언어 전반 | |
| 1.4 (I-04) 크로스사이트 스크립트 | 79, 80 | 부분 자동 | code.xss-dom-sink, web.reflected-xss-verified | HTML/JS/TS | 서버측 템플릿 XSS는 부분 탐지 |
| 1.5 (I-05) 운영체제 명령어 삽입 | 78 | 부분 자동 | code.command-injection | 웹 언어 전반 | |
| 1.6 (I-06) 위험한 형식 파일 업로드 | 434 | 부분 | code.unrestricted-file-upload | JS/TS/PHP/Python | 검증 로직 완전성은 수동 |
| 1.7 (I-07) 신뢰되지 않는 URL 주소로 자동접속 연결 | 601 | 부분 자동 | code.open-redirect-user-input, web.open-redirect-verified | 웹 언어 전반 | 신규 룰 |
| 1.8 (I-08) 부적절한 XML 외부 개체 참조 | 611 | 부분 자동 | code.xml-external-entity | Java/Kotlin/C#/Python | |
| 1.9 (I-09) XML 삽입 | 91 | 부분 | code.xml-injection | Java/Kotlin/JS/TS/Python/PHP | 신규 룰, XXE와 별도 |
| 1.10 (I-10) LDAP 삽입 | 90 | 부분 | code.ldap-injection | Java/Kotlin/Python | 신규 룰 |
| 1.11 (I-11) 크로스사이트 요청 위조 | 352 | 부분 | code.csrf-disabled | 웹 언어 전반 | 명시적 비활성화만 탐지 |
| 1.12 (I-12) 서버사이드 요청 위조 | 918 | 부분 자동 | code.ssrf-user-url | 웹 언어 전반 | |
| 1.13 (I-13) HTTP 응답분할 | 113 | 부분 | code.http-response-splitting | 웹 언어 전반 | 신규 룰 |
| 1.14 (I-14) 정수형 오버플로우 | 190 | 부분 | code.integer-overflow-user-input | C/C++/Java/Kotlin/C# | 동일 함수 외부 정수 입력의 범위 검증 후보 |
| 1.15 (I-15) 보안기능 결정에 사용되는 부적절한 입력값 | 807, 20 | 부분 | code.security-decision-user-input | 웹 언어 전반 | 요청 제어 결정값의 동일 함수 흐름 |
| 1.16 (I-16) 메모리 버퍼 오버플로우 | 119–122 | 부분 | code.dangerous-c-buffer-api | C/C++ | |
| 1.17 (I-17) 포맷 스트링 삽입 | 134 | 부분 | code.format-string-user-input | C/C++/Java/Kotlin | 신규 룰 (버퍼 API 룰에서 분리) |

### 보안기능 (16)

| 기준 | CWE | 지원 수준 | KODA 룰 | 비고 |
| --- | --- | --- | --- | --- |
| 2.1 (S-01) 적절한 인증 없는 중요기능 허용 | 306 | 부분 | code.auth-disabled-endpoint, code.api-route-missing-auth | 기능 중요도 판단은 수동 |
| 2.2 (S-02) 부적절한 인가 | 862, 863 | 부분 | code.authorization-check-missing | 중요 기능 주변의 권한 검사 후보 |
| 2.3 (S-03) 중요한 자원에 대한 잘못된 권한 설정 | 732 | 부분 | code.insecure-resource-permissions | 명시적 world-writable/full-control 설정 |
| 2.4 (S-04) 취약한 암호화 알고리즘 사용 | 327 | 부분 | code.weak-hash | 대칭키 설정은 수동 |
| 2.5 (S-05) 암호화되지 않은 중요정보 | 311, 319 | 부분 | config.env-file-present, config.private-key-like-file, dependency.node-insecure-url, dependency.python-insecure-url, config.docker-add-http | 저장 암호화는 수동 |
| 2.6 (S-06) 하드코드된 중요정보 | 259, 321, 798 | 부분 자동 | secret.* 6종 | |
| 2.7 (S-07) 충분하지 않은 키 길이 사용 | 326 | 부분 | code.insufficient-key-length | 신규 룰, RSA/DSA/DH ≤1024 |
| 2.8 (S-08) 적절하지 않은 난수 값 사용 | 330, 338 | 부분 | code.insecure-random-security-use | 신규 룰, 보안 문맥 결합 탐지 |
| 2.9 (S-09) 취약한 비밀번호 허용 | 521 | 부분 | code.weak-password-policy | 명시적 최소 길이 8자 미만 |
| 2.10 (S-10) 부적절한 전자서명 확인 | 347 | 부분 | code.jwt-verification-disabled, code.jwt-none-algorithm | JWT 외 영역은 수동 |
| 2.11 (S-11) 부적절한 인증서 유효성 검증 | 295 | 부분 자동 | code.tls-certificate-verification-disabled | 신규 룰 |
| 2.12 (S-12) 사용자 하드디스크에 저장되는 쿠키를 통한 정보 노출 | 539 | 부분 | code.persistent-sensitive-cookie | 민감 값과 영속 속성이 같은 쿠키 저장 지점에 있을 때만 후보 |
| 2.13 (S-13) 주석문 안에 포함된 시스템 주요정보 | 615 | 부분 | secret.sensitive-comment | 신규 룰, 증거 마스킹 |
| 2.14 (S-14) 솔트 없이 일방향 해쉬 함수 사용 | 759 | 부분 | code.password-hash-without-salt | 신규 룰, 비밀번호 문맥 결합 |
| 2.15 (S-15) 무결성 검사 없는 코드 다운로드 | 494 | 부분 | dependency.remote-shell-script, dependency.docker-remote-shell, config.docker-add-http, prevention.github-actions-unpinned | 기존 공급망 룰 재사용 |
| 2.16 (S-16) 반복된 인증시도 제한 기능 부재 | 307 | 부분 | code.auth-attempt-protection-missing | 실제 인증 흐름과 제한·잠금·추가 인증 통제를 함께 확인 |

### 시간 및 상태 (2)

| 기준 | CWE | 지원 수준 | KODA 룰 | 비고 |
| --- | --- | --- | --- | --- |
| 3.1 (T-01) 경쟁조건: 검사 시점과 사용 시점(TOCTOU) | 367 | 부분 | code.insecure-temp-file | 임시파일 사례만, 일반 TOCTOU는 수동 |
| 3.2 (T-02) 종료되지 않는 반복문 또는 재귀 함수 | 835, 674 | 부분 | code.uncontrolled-loop | 동일 함수의 상수 루프·직접 재귀 후보 |

### 에러처리 (3)

| 기준 | CWE | 지원 수준 | KODA 룰 |
| --- | --- | --- | --- |
| 4.1 (E-01) 오류 메시지 정보노출 | 209 | 부분 자동 | config.debug-enabled, code.stack-trace-exposure |
| 4.2 (E-02) 오류 상황 대응 부재 | 390, 755 | 부분 | code.empty-exception-handler |
| 4.3 (E-03) 부적절한 예외 처리 | 754, 755, 396, 397 | 부분 | code.broad-exception-handler |

### 코드오류 (5)

| 기준 | CWE | 지원 수준 | KODA 룰 | 비고 |
| --- | --- | --- | --- | --- |
| 5.1 (C-01) Null Pointer 역참조 | 476 | 부분 | code.null-pointer-dereference | Java/Kotlin 동일 파일의 명시적 null 및 알려진 nullable 조회 API만 탐지; 함수 간 흐름은 외부 SAST 필요 |
| 5.2 (C-02) 부적절한 자원 해제 | 404, 772 | 부분 | code.improper-resource-release | Java/Kotlin 동일 파일 자원 수명 후보 |
| 5.3 (C-03) 해제된 자원 사용 | 416 | 부분 | code.use-after-free | C/C++ 동일 파일 직접 free/use 후보 |
| 5.4 (C-04) 초기화되지 않은 변수 사용 | 457 | 부분 | code.uninitialized-variable | C/C++ 단순 지역변수 직접 흐름 후보 |
| 5.5 (C-05) 신뢰할 수 없는 데이터의 역직렬화 | 502 | 부분 자동 | code.unsafe-deserialization | API 오용에서 이동됨 |

### 캡슐화 (4)

| 기준 | CWE | 지원 수준 | KODA 룰 | 비고 |
| --- | --- | --- | --- | --- |
| 6.1 (P-01) 잘못된 세션에 의한 데이터 정보 노출 | 488 | 부분 | code.session-shared-state | 세션 데이터를 모듈·서블릿 공유 상태에 저장 |
| 6.2 (P-02) 제거되지 않고 남은 디버그 코드 | 489 | 부분 | config.debug-enabled, config.development-environment | 코드 내 디버그 출력은 수동 |
| 6.3 (P-03) Public 메소드부터 반환된 Private 배열 | 495 | 부분 | code.private-array-return | Java/Kotlin/C# 직접 참조 반환 |
| 6.4 (P-04) Private 배열에 Public 데이터 할당 | 496 | 부분 | code.private-array-assignment | Java/Kotlin/C# 방어적 복사 없는 저장 |

### API 오용 (2)

| 기준 | CWE | 지원 수준 | KODA 룰 | 비고 |
| --- | --- | --- | --- | --- |
| 7.1 (A-01) DNS lookup에 의존한 보안결정 | 350, 247 | 부분 | code.dns-security-decision | DNS 결과가 인증·인가·신뢰 비교에 직접 사용되는 동일 파일 흐름 |
| 7.2 (A-02) 취약한 API 사용 | 676 | 부분 | code.dangerous-c-buffer-api, code.dangerous-managed-api | C/C++ 금지 API, J2EE Socket/System.exit, C# Application.Exit |

## 제거·재분류된 기존 매핑

이번 정합성 개선에서 다음 매핑이 `SW_DEV_SECURITY_49` 프로파일에서 제거되었습니다. **룰 자체는 KODA 전체에서 유지됩니다.**

| 룰 | 이전 위치 | 조치 |
| --- | --- | --- |
| code.wildcard-cors | 캡슐화 | 프로파일에서 제거 (일반 설정/웹 보안에 유지) |
| code.public-bind-all-interfaces | 캡슐화 | 프로파일에서 제거 |
| code.logging-sensitive-data | 캡슐화 | 프로파일에서 제거 (민감정보/로깅 프로파일에 유지) |
| code.pii-logging | 캡슐화 | 프로파일에서 제거 (개인정보 프로파일에 유지) |
| dependency.remote-shell-script | API 오용 | S-15 무결성 검사 없는 코드 다운로드로 재분류 |
| dependency.docker-remote-shell | API 오용 | S-15로 재분류 |
| config.docker-add-http | API 오용 | S-05/S-15로 재분류 |
| code.eval-user-input | API 오용 | I-02 코드 삽입으로 재분류 |
| code.unsafe-deserialization | API 오용 | C-05 역직렬화로 재분류 |
| code.dangerous-c-buffer-api | 코드오류 대표 | I-16 버퍼 오버플로우 + A-02 취약 API로 재분류 |
| code.insecure-temp-file | 시간 및 상태 대표 | T-01(partial)로만 제한 연결 |

## 수동 검토 방법

- **S-02/S-03 (인가·권한)**: 엔드포인트별 인가 매트릭스를 작성하고, 객체 소유권 검증(BOLA)과 파일·DB 권한 설정을 코드 리뷰로 확인합니다.
- **I-14 (정수형 오버플로우)**: 외부 입력이 크기 계산·메모리 할당에 쓰이는 경로를 추적합니다.
- **T-02 (무한 반복)**: `while(true)` 계열 루프의 탈출 조건과 재귀 깊이 제한을 확인합니다.
- **C-01 (Null Pointer 역참조)**: KODA의 동일 파일 후보를 우선 검토하고, 함수 간 흐름은 Semgrep/CodeQL/Sparrow 등 데이터 흐름 기반 SAST 결과로 보완합니다.
- **C-02~C-04 (코드오류)**: KODA 동일 파일 후보를 우선 검토하고 함수·분기 간 흐름은 데이터 흐름 기반 SAST로 보완합니다.
- **P-01/P-03/P-04 (캡슐화)**: 세션 저장소 사용과 배열 반환 패턴을 코드 리뷰로 확인합니다.
- **A-01 (DNS lookup에 의존한 보안결정)**: KODA 후보에서 DNS 결과가 실제 인증·인가에 쓰이는지 확인합니다.

## 외부 SAST·DAST가 필요한 항목

- 외부 SAST 보완: I-14, C-01, C-02, C-03, C-04, A-01 (함수 간 데이터 흐름·수명 분석)
- DAST/웹 점검: I-01, I-04, I-07의 web.* 검증 룰은 KODA 웹 점검 실행 시에만 증거가 추가됩니다.

## 보고서 상태의 의미

- 대시보드·Markdown·Excel(SW49 시트)·HWPX·JSON 모두 49개 기준 전체 행을 출력합니다. 발견 0건이어도 표가 생성됩니다.
- 발견 0건이어도 부분·수동 검토 기준은 `NEEDS_REVIEW`, 적용 파일이 없으면 `NOT_APPLICABLE`, 실행되지 않은 전략은 `NOT_SCANNED`로 구분됩니다.
- KODA는 49개 기준의 **전체 자동 점검을 주장하지 않습니다**. 자동·부분 지원 항목의 판정도 패턴 기반 탐지 범위 내에서만 유효합니다.

## 소스 전용 정적 분석 (SW49)

SW49 소스 분석은 Java/Kotlin, JavaScript/TypeScript, Python, C/C++, C#, Go,
Rust, Swift, PHP, Ruby와 HTML/XML, YAML, JSON/TOML, Terraform, plist, 환경설정,
의존성 매니페스트, Dockerfile, GitHub Actions workflow 및 개인키 형태 파일을 점검합니다.
바이너리와 빌드·배포 산출물 디렉터리는 제외합니다.
지원 파일의 전체 프로젝트 매니페스트를 먼저 고정하고 로컬 규칙을 실행합니다.
`--changed-only`에서도 변경되지 않은 지원 파일은 분석 컨텍스트로 유지됩니다.

첫 외부 매핑은 관리자가 별도 환경에서 생성한 CodeQL `2.26.1` Java SARIF를
대상으로 합니다. KODA는 CodeQL이나 빌드 도구를 다운로드·실행하지 않으며,
실행 요청은 `SKIPPED`/`NOT_SCANNED`로 종료합니다. 비샌드박스 실행으로
대체하지 않습니다.

SARIF 2.1.0은 대상 경로 안의 허용된 `(분석기, 규칙)` 쌍만 양성 증거로
가져옵니다. 잘못된 JSON·버전·경로 탈출·초과 크기는 실패하고, 매핑되지 않은
규칙은 경고 후 무시합니다. 빈 파일이나 일치하는 다이제스트도 음성 커버리지나
`PASS`를 인증하지 않습니다.

`VULNERABLE`은 확정 소스 증거, `NEEDS_REVIEW`는 후보/업무 맥락, `NOT_SCANNED`는
분석기·전략 미실행을 뜻합니다. 0건이어도 벤치마크 인증 프로파일의 모든 필수
전략이 완료되지 않으면 `PASS`가 아닙니다. 49개 기준별 검토 fixture 인덱스와
C-01 교차 파일/SARIF 경계 fixture는
[`tests/fixtures/sw49/manifest.json`](../../tests/fixtures/sw49/manifest.json)에 있습니다.
각 로컬 매핑의 positive/negative 쌍은 실제 스캐너로 실행되며, 로컬 룰이 없는 수동 기준은 `NEEDS_REVIEW`/`NOT_RUN`을 검증합니다.
