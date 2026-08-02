# KODA 21개 웹취약점 자동 점검

`web-audit`은 프로필에 선언된 대상·리소스·정상/거부 oracle만 실행합니다.
ZAP·Playwright·BOAST가 없거나 oracle/cleanup이 완전하지 않으면 PASS로 올리지
않습니다. 대상 소유 또는 명시적 점검 권한이 있는 staging/테스트 환경에서만
사용하세요.

## 실행 흐름

```bash
export KODA_APPROVAL_KEY='operator-managed-secret'
# BOAST /events 인증 secret(base64)은 승인서나 결과에 넣지 않습니다.
export KODA_OAST_SECRET='base64-secret-from-boast'

koda web-audit plan \
  --profile profile.json \
  --out approval-request.json

koda web-audit approve \
  --request approval-request.json \
  --approver '홍길동' \
  --out approval.json

koda web-audit run \
  --profile profile.json \
  --approval approval.json \
  --confirm-origin https://staging.example.com \
  --format json \
  --output reports/web-audit.json
```

`plan`은 프로필 검증과 DNS/IP 확인만 수행합니다. `approve`는 HMAC-SHA256
승인서를 만들고, `run`은 프로필 hash·origin·현재 해석 IP·범위·제한·서명·만료를
검증한 뒤 `~/.koda/web-audit-nonces.sqlite3`에서 nonce를 한 번만 소비합니다.
따라서 승인서 재사용, DNS rebinding, 다른 origin 실행은 거부됩니다.

## 최소 프로필

아래 origin은 예시이므로 실제 승인된 staging origin으로 바꾸세요.

```json
{
  "schema_version": 1,
  "target": {
    "environment": "staging",
    "origins": ["https://staging.example.com"],
    "include_paths": ["/"],
    "exclude_paths": [],
    "allowed_cidrs": [],
    "scopes": ["passive", "state_change_free"],
    "read_only_resources": ["home"],
    "platform": "shared",
    "distribution": "direct",
    "zap": {"enabled": false}
  },
  "limits": {
    "requests": 1000,
    "max_response_bytes": 2097152,
    "max_upload_bytes": 1048576,
    "timeout_seconds": 900,
    "max_rps": 5,
    "redirects": 3,
    "idempotent_retries": 1,
    "state_change_retries": 0,
    "oast_poll_seconds": 120,
    "cleanup_seconds": 30,
    "zap_rps": 2,
    "zap_threads_per_host": 1,
    "zap_minutes": 15,
    "zap_rule_minutes": 2
  },
  "accounts": {
    "userA": {
      "role": "user",
      "headers": {"Authorization": "${ENV:KODA_USERA_AUTH}"}
    }
  },
  "auth": {},
  "resources": [
    {
      "id": "home",
      "path": "/",
      "methods": ["GET"],
      "actors": ["anonymous"],
      "access": {"anonymous": "allow"},
      "read_only": true,
      "state_change_free": true
    }
  ],
  "scenarios": [
    {
      "id": "home-is-available",
      "title": "정상 공개 페이지 응답",
      "control_id": "web.plaintext-transmission",
      "required": true,
      "strategies": ["koda-scenario"],
      "steps": [
        {
          "id": "home",
          "resource": "home",
          "method": "GET",
          "assertions": [{"type": "status_in", "values": [200, 204]}]
        }
      ],
      "mutations": [],
      "cleanup": [],
      "oracle": {}
    }
  ],
"oast": {},
"applicability": {}
}
```

SSRF·코드 삽입에서 실제 callback을 확인하려면 `target.scopes`에 `oast`를
추가하고 다음처럼 BOAST control plane과 승인 IP/CIDR를 선언합니다. KODA는 승인 IP로 고정된
`GET /events`를 등록·polling하며, 새 event가 있으면 `VULNERABLE`, polling이
끝나고 없으면 다른 oracle이 완전한 경우에만 `PASS`입니다. BOAST secret이
없거나 control plane/IP 검증이 실패하면 `UNSUPPORTED` 또는 `NOT_SCANNED`로
남습니다.

```json
"oast": {
  "control_plane_origin": "https://boast.example.net",
  "callback_domain": "callbacks.example.net",
  "allowed_ips": ["203.0.113.10"],
  "poll_seconds": 10
}
```

시나리오의 요청 값에는 `${CAPTURE:OAST_PAYLOAD}`를 사용합니다. 이 값은 실행
중 등록된 BOAST test ID와 callback domain으로만 생성되며, 임의 URL이나 shell을
실행하지 않습니다.

실제 점검에서는 `resources`와 `scenarios`를 21개 표준 ID에 맞춰 확장합니다.
시나리오에 여러 `strategies`를 선언하면 모두 실행하고, 각 전략의 PASS가
확인될 때만 composite coverage를 완료합니다. 지원 전략은 `koda-scenario`,
`passive`, `browser`/`playwright`, `oast`, `zap`/`zap-active`,
`access-control`/`matrix`, `timing`, `state`, `upload`입니다.
HTTP 메서드 점검처럼 실제 허용 목록 밖의 verb를 안전하게 시험할 때는
리소스의 `probe_methods`에만 추가합니다. 일반 `methods`와 중복할 수 없습니다.
`web.authentication`, `web.authorization`, `web.csrf`, `web.password-recovery`,
`web.process-validation`, `web.file-upload` 등 상태·계정·복구가 관련된 항목은
정상 응답뿐 아니라 거부 응답과 상태 불변 assertion, cleanup을 모두 선언해야
PASS가 됩니다. JSON 로그인은 `auth.token_json_path`와 환경변수 기반
`username_env`/`password_env`를 선언하고, 파일 업로드는 `multipart` body와
cleanup을 함께 선언해야 합니다. 만료/재사용 시간 검사는 step의 제한된
`delay_seconds`로 수행하며 전체 timeout을 넘으면 PASS가 아니라 검토 상태입니다.
적용되지 않는 항목은 다음처럼 사유를 적습니다.

```json
"applicability": {
  "web.password-recovery": {
    "status": "NOT_APPLICABLE",
    "reason": "이 서비스는 사용자 비밀번호 복구 기능을 제공하지 않음"
  }
}
```

## 상태 의미

| 상태 | 의미 |
| --- | --- |
| `VULNERABLE` | 검증된 취약 응답, 상태 위반, callback 증거가 있음 |
| `PASS` | 선언된 필수 전략·oracle·cleanup이 모두 완료되고 취약 증거가 없음 |
| `NEEDS_REVIEW` | oracle·OAST·cleanup·일부 표면이 완전하지 않음 |
| `NOT_APPLICABLE` | 프로필이 사유와 함께 명시적으로 제외 |
| `UNSUPPORTED` | 현재 배포판에 필요한 capability가 없음 |
| `NOT_SCANNED` | 승인·프로필·인증·preflight 문제로 실행하지 않음 |

공개 결과에는 `web.*` ID, 상태, coverage, 표면, evidence ID만 남습니다. 쿠키,
토큰, 비밀번호, raw 요청/응답, ZAP plugin ID는 포함하지 않습니다. SourceOnly와
macOS App Store판은 웹 21개 항목을 실제 실행하지 않고 capability 경계를
`UNSUPPORTED(package_capability_missing)` 또는 검토 상태로 표시합니다.

ZAP 이미지와 add-on manifest는 사전에 digest로 고정해야 하며, web-audit 실행은
Docker image를 자동 pull하지 않습니다. 이미지·Playwright browser·BOAST가 없으면
해당 capability를 `UNSUPPORTED` 또는 `NOT_SCANNED`로 남깁니다.
ZAP Automation Framework plan에는 spider/activeScan 제한과 `exitStatus` 결과 검사가
포함되며, ZAP 종료 코드만으로 21개 항목 PASS를 만들지는 않습니다.
