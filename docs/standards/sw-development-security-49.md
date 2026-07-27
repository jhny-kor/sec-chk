# 소프트웨어 개발보안 49 (SW_DEV_SECURITY_49)

행정안전부·KISA 「소프트웨어 보안약점 진단가이드」의 **구현단계 보안약점 49개**를 KODA에서 기준별로 추적하는 프로파일입니다. 기준연도는 진단가이드 2021 개정판(7개 유형 · 49개 보안약점 체계)입니다.

공식 기준 원문: [행정안전부 소프트웨어 개발보안 가이드(2021.11.30 개정)](https://www.mois.go.kr/frt/bbs/type001/commonSelectBoardArticle.do?bbsId=BBSMSTR_000000000015&nttId=88956)

## 동작 원칙

- 공식 기준 49개가 각각 독립된 `SecurityControl`로 등록됩니다 (`security_scanner/standards.py`의 `SW49_CONTROLS`).
- 하나의 공식 기준에 여러 KODA 룰이 연결될 수 있으며, 반대로 일반 KODA 룰을 무관한 기준에 연결하지 않습니다.
- **탐지 0건은 준수를 의미하지 않습니다.** 판정 상태는 다음과 같이 구분됩니다.

| 판정 | 의미 |
| --- | --- |
| `PASS` (통과) | 완전 자동 지원 기준의 룰이 실제로 실행되었고 취약 패턴이 없음 |
| `VULNERABLE` (취약) | 외부 입력에서 위험 동작까지의 흐름과 방어 부재를 결정론적으로 확인함 |
| `NEEDS_REVIEW` (수동 검토 필요) | 부분 자동 또는 수동 검토 기준 — 정적 분석만으로 최종 판정 불가 |
| `UNSUPPORTED` (미지원) | KODA가 해당 기준을 점검하지 못함 (외부 SAST 필요) |
| `NOT_APPLICABLE` (해당 없음) | 대상 기술에서 적용되지 않음 |
| `NOT_SCANNED` (미실행) | 필요한 스캔 카테고리가 실행되지 않음 |

- 미지원·수동 검토·미실행 기준은 절대 `PASS`로 표시되지 않습니다.
- 부분 자동(`partial`) 기준은 탐지 0건이어도 `NEEDS_REVIEW`로 남습니다. 자동화가 기준의 일부만 다루기 때문입니다.
- 각 발견은 `verification_status`가 `confirmed` 또는 `needs_review`입니다. 위험 API·설정 한 줄만 일치한 결과는 `needs_review`이며 취약 확정 건수나 실패 게이트에 포함하지 않습니다.
- 파일 내에서 확인 가능한 입력원, 변수 전달, sanitizer/allowlist, parameter binding, sink를 함께 분석합니다. 함수·파일·프로젝트 경계를 넘는 전역 설정과 업무 중요도는 검토 대상으로 남깁니다.

## 지원 수준 요약

| 지원 수준 | 개수 |
| --- | --- |
| 자동 (automated) | 0 |
| 부분 자동 (partial) | 35 |
| 수동 검토 (manual-review) | 9 |
| 미지원 (unsupported) | 5 |

## 기준별 매핑

### 입력데이터 검증 및 표현 (17)

| 기준 | CWE | 지원 수준 | KODA 룰 | 지원 언어 | 비고 |
| --- | --- | --- | --- | --- | --- |
| I-01 SQL 삽입 | 89 | 부분 자동 | code.sql-dynamic-query, web.sql-injection-error-verified | 웹 언어 전반 | web.* 룰은 웹 점검 실행 시에만 |
| I-02 코드 삽입 | 94, 95 | 부분 자동 | code.eval-user-input | JS/TS/Python/PHP/Ruby | |
| I-03 경로 조작 및 자원 삽입 | 22, 99 | 부분 자동 | code.path-traversal | 웹 언어 전반 | |
| I-04 크로스사이트 스크립트 | 79, 80 | 부분 자동 | code.xss-dom-sink, web.reflected-xss-verified | HTML/JS/TS | 서버측 템플릿 XSS는 부분 탐지 |
| I-05 운영체제 명령어 삽입 | 78 | 부분 자동 | code.command-injection | 웹 언어 전반 | |
| I-06 위험한 형식 파일 업로드 | 434 | 부분 | code.unrestricted-file-upload | JS/TS/PHP/Python | 검증 로직 완전성은 수동 |
| I-07 신뢰되지 않는 URL 자동접속 | 601 | 부분 자동 | code.open-redirect-user-input, web.open-redirect-verified | 웹 언어 전반 | 신규 룰 |
| I-08 부적절한 XML 외부 개체 참조 | 611 | 부분 자동 | code.xml-external-entity | Java/Kotlin/C#/Python | |
| I-09 XML 삽입 | 91 | 부분 | code.xml-injection | Java/Kotlin/JS/TS/Python/PHP | 신규 룰, XXE와 별도 |
| I-10 LDAP 삽입 | 90 | 부분 | code.ldap-injection | Java/Kotlin/Python | 신규 룰 |
| I-11 크로스사이트 요청 위조 | 352 | 부분 | code.csrf-disabled | 웹 언어 전반 | 명시적 비활성화만 탐지 |
| I-12 서버사이드 요청 위조 | 918 | 부분 자동 | code.ssrf-user-url | 웹 언어 전반 | |
| I-13 HTTP 응답분할 | 113 | 부분 | code.http-response-splitting | 웹 언어 전반 | 신규 룰 |
| I-14 정수형 오버플로우 | 190 | 수동 검토 | — | — | 데이터 흐름 분석 필요 |
| I-15 보안기능 결정에 사용되는 부적절한 입력값 | 807, 20 | 수동 검토 | — | — | |
| I-16 메모리 버퍼 오버플로우 | 119–122 | 부분 | code.dangerous-c-buffer-api | C/C++ | |
| I-17 포맷 스트링 삽입 | 134 | 부분 | code.format-string-user-input | C/C++/Java/Kotlin | 신규 룰 (버퍼 API 룰에서 분리) |

### 보안기능 (16)

| 기준 | CWE | 지원 수준 | KODA 룰 | 비고 |
| --- | --- | --- | --- | --- |
| S-01 적절한 인증 없는 중요기능 허용 | 306 | 부분 | code.auth-disabled-endpoint, code.api-route-missing-auth | 기능 중요도 판단은 수동 |
| S-02 부적절한 인가 | 862, 863 | 수동 검토 | — | 설계·데이터 흐름 검토 필요 |
| S-03 중요한 자원에 대한 잘못된 권한 설정 | 732 | 수동 검토 | — | |
| S-04 취약한 암호화 알고리즘 사용 | 327 | 부분 | code.weak-hash | 대칭키 설정은 수동 |
| S-05 암호화되지 않은 중요정보 | 311, 319 | 부분 | config.env-file-present, config.private-key-like-file, dependency.node-insecure-url, dependency.python-insecure-url, config.docker-add-http | 저장 암호화는 수동 |
| S-06 하드코드된 중요정보 | 798 | 부분 자동 | secret.* 6종 | |
| S-07 충분하지 않은 키 길이 사용 | 326 | 부분 | code.insufficient-key-length | 신규 룰, RSA/DSA/DH ≤1024 |
| S-08 적절하지 않은 난수 값 사용 | 330, 338 | 부분 | code.insecure-random-security-use | 신규 룰, 보안 문맥 결합 탐지 |
| S-09 취약한 비밀번호 허용 | 521 | 수동 검토 | — | |
| S-10 부적절한 전자서명 확인 | 347 | 부분 | code.jwt-verification-disabled, code.jwt-none-algorithm | JWT 외 영역은 수동 |
| S-11 부적절한 인증서 유효성 검증 | 295 | 부분 자동 | code.tls-certificate-verification-disabled | 신규 룰 |
| S-12 저장 쿠키를 통한 정보 노출 | 539 | 부분 | code.insecure-cookie-settings | 실제 민감정보 저장 여부는 수동 |
| S-13 주석문 안에 포함된 시스템 주요정보 | 615 | 부분 | secret.sensitive-comment | 신규 룰, 증거 마스킹 |
| S-14 솔트 없이 일방향 해시 함수 사용 | 759 | 부분 | code.password-hash-without-salt | 신규 룰, 비밀번호 문맥 결합 |
| S-15 무결성 검사 없는 코드 다운로드 | 494 | 부분 | dependency.remote-shell-script, dependency.docker-remote-shell, config.docker-add-http, prevention.github-actions-unpinned | 기존 공급망 룰 재사용 |
| S-16 반복된 인증시도 제한 기능 부재 | 307 | 부분 | code.api-missing-rate-limit | 로그인 경로 확인 없음 → 부분 |

### 시간 및 상태 (2)

| 기준 | CWE | 지원 수준 | KODA 룰 | 비고 |
| --- | --- | --- | --- | --- |
| T-01 경쟁조건(TOCTOU) | 367 | 부분 | code.insecure-temp-file | 임시파일 사례만, 일반 TOCTOU는 수동 |
| T-02 종료되지 않는 반복문/재귀 | 835, 674 | 수동 검토 | — | 제어 흐름 분석 필요 |

### 에러처리 (3)

| 기준 | CWE | 지원 수준 | KODA 룰 |
| --- | --- | --- | --- |
| E-01 오류 메시지 정보노출 | 209 | 부분 자동 | config.debug-enabled, code.stack-trace-exposure |
| E-02 오류 상황 대응 부재 | 390, 755 | 부분 | code.empty-exception-handler |
| E-03 부적절한 예외 처리 | 755, 396, 397 | 부분 | code.empty-exception-handler, code.stack-trace-exposure |

### 코드오류 (5)

| 기준 | CWE | 지원 수준 | KODA 룰 | 비고 |
| --- | --- | --- | --- | --- |
| C-01 Null Pointer 역참조 | 476 | 미지원 | — | 외부 SAST 필요 |
| C-02 부적절한 자원 해제 | 404, 772 | 미지원 | — | 외부 SAST 필요 |
| C-03 해제된 자원 사용 | 416 | 미지원 | — | 외부 SAST 필요 |
| C-04 초기화되지 않은 변수 사용 | 457 | 미지원 | — | 외부 SAST 필요 |
| C-05 신뢰할 수 없는 데이터의 역직렬화 | 502 | 부분 자동 | code.unsafe-deserialization | API 오용에서 이동됨 |

### 캡슐화 (4)

| 기준 | CWE | 지원 수준 | KODA 룰 | 비고 |
| --- | --- | --- | --- | --- |
| P-01 잘못된 세션에 의한 데이터 정보 노출 | 488 | 수동 검토 | — | |
| P-02 제거되지 않고 남은 디버그 코드 | 489 | 부분 | config.debug-enabled, config.development-environment | 코드 내 디버그 출력은 수동 |
| P-03 Public 메소드로부터 반환된 Private 배열 | 495 | 수동 검토 | — | |
| P-04 Private 배열에 Public 데이터 할당 | 496 | 수동 검토 | — | |

### API 오용 (2)

| 기준 | CWE | 지원 수준 | KODA 룰 | 비고 |
| --- | --- | --- | --- | --- |
| A-01 DNS lookup에 의존한 보안 결정 | 350, 247 | 미지원 | — | 의미 분석 필요 |
| A-02 취약한 API 사용 | 676 | 부분 | code.dangerous-c-buffer-api | C/C++ 금지 API 목록 |

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
- **C-01~C-04 (코드오류)**: Semgrep/CodeQL/Sparrow 등 데이터 흐름 기반 SAST 결과를 사용합니다.
- **P-01/P-03/P-04 (캡슐화)**: 세션 저장소 사용과 배열 반환 패턴을 코드 리뷰로 확인합니다.
- **A-01 (DNS 기반 보안 결정)**: 역방향 DNS 결과가 인증·인가에 쓰이는지 확인합니다.

## 외부 SAST·DAST가 필요한 항목

- 외부 SAST: I-14, C-01, C-02, C-03, C-04 (데이터 흐름·수명 분석)
- DAST/웹 점검: I-01, I-04, I-07의 web.* 검증 룰은 KODA 웹 점검 실행 시에만 증거가 추가됩니다.

## 보고서 상태의 의미

- 대시보드·Markdown·Excel(SW49 시트)·HWPX·JSON 모두 49개 기준 전체 행을 출력합니다. 발견 0건이어도 표가 생성됩니다.
- 발견 0건 안내 문구: *"현재 실행된 자동 점검 범위에서는 취약 항목이 탐지되지 않았습니다. 미지원·수동 검토·미실행 기준은 별도로 확인해야 하며, 전체 49개 기준의 준수를 의미하지 않습니다."*
- KODA는 49개 기준의 **전체 자동 점검을 주장하지 않습니다**. 자동·부분 지원 항목의 판정도 패턴 기반 탐지 범위 내에서만 유효합니다.
