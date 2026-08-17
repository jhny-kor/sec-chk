# KODA + KODA SBOM Tracker 폐쇄망 통합본

이 압축파일 하나에 KODA Docker 오프라인 이미지와 KODA SBOM Tracker의
Dependency-Track·PostgreSQL·포털 이미지를 함께 담았습니다. 실제 비밀번호와 API
키는 포함하지 않습니다.

설치 중 오류가 발생하면 [폐쇄망 설치 장애 대응서](TROUBLESHOOTING.ko.md)의
`증상 → 확인 → 조치 → 정상 기준` 순서로 확인합니다.

## 서버 조건

- Linux x86_64/amd64
- Docker Engine과 `docker compose` 플러그인 선설치
- Docker 권한이 있는 비루트 운영 계정으로 실행
- `python3`, `tar`, `sha256sum`, `flock`, `realpath`
- 압축 해제 공간과 Docker 이미지·DB 공간을 합쳐 최소 15GB 여유 권장

## 최초 설치와 동시 기동

반입 파일의 SHA-256을 먼저 확인합니다.

```bash
sha256sum -c koda-suite-offline-x86_64-@SUITE_VERSION@.tar.gz.sha256
tar -xzf koda-suite-offline-x86_64-@SUITE_VERSION@.tar.gz
cd koda-suite-offline-x86_64-@SUITE_VERSION@
./koda-suite verify
```

운영 환경파일을 준비합니다. 예시의 모든 `change-me-*` 값을 실제 값으로 바꾸고,
`DTRACK_API_BASE_URL`은 브라우저가 접근할 수 있는 Dependency-Track base 주소인
`http://<서버주소>:8088/dependency-track` 형태로 지정합니다. 프론트엔드가 여기에
`/api`를 자동으로 붙이므로 `/dependency-track/api`까지 입력하면 안 됩니다.
관리자 자동화용 `DTRACK_ADMIN_API_BASE_URL`만 `/dependency-track/api`를 포함합니다.
`TRACKER_DEPENDENCY_TRACK_API_KEY`에는 Dependency-Track의 BOM 업로드·프로젝트
생성·조회에 필요한 최소 권한 전용 키를 넣습니다.

```bash
cp config/koda-suite.env.example ./koda-suite.env
chmod 600 ./koda-suite.env
vi ./koda-suite.env
./koda-suite install --env-file ./koda-suite.env
```

위 `install` 한 번이 두 내부 manifest를 검증하고, 모든 이미지를 `docker load`한
뒤 Tracker와 KODA 대시보드를 함께 기동하고 HTTP 상태까지 확인합니다. 압축파일의
`metadata.env`가 `TRACKER_VULNERABILITY_BUNDLE=included`이면 최초 설치에서 Tracker
전용 Grype/NVD/KEV 데이터도 manifest 검증 후 자동 반입합니다. 이 단계는 Docker
volume 반입까지이며, 최초 로그인 후 포털의 `취약점 데이터 → 반입 상태 동기화`를
한 번 실행해야 감사 이력과 기준일이 등록됩니다. 기본 설치
위치는 `$HOME/koda-suite`이며 다른 위치가 필요하면 최초 설치에
`--prefix /원하는/경로`를 추가합니다.

운영 게이트웨이는 반드시 HTTPS로 외부에 게시해야 합니다. 이 번들은 인증서
종료기를 제공하지 않으므로, 앞단 TLS reverse proxy가 원래 Host와 HTTPS scheme을
유지한 채 이 게이트웨이로 전달해야 합니다. `TRACKER_ENVIRONMENT=production`에서는
`GATEWAY_PUBLIC_SCHEME=https`와 `TRACKER_SECURE_COOKIES=true`가 아니면 launcher가
기동을 거부합니다. 개발용 예외는 loopback 전용에서만
`TRACKER_ENVIRONMENT=development`로 명시할 수 있습니다. 최초 Tracker 로그인 후
응답/사용자 관리 화면에서 계정 UUID를 확인하고 KODA 시스템 관리자를 한 번만
bootstrap합니다.

```bash
PREFIX="$HOME/koda-suite"
TRACKER_UUID='Tracker 화면에 표시된 UUID'
"$PREFIX/koda/koda-docker" dashboard bootstrap --tracker-user-id "$TRACKER_UUID"
```

기본 주소:

- Suite: `https://<서버주소>:8088/` (TLS reverse proxy 뒤)
- KODA: `https://<서버주소>:8088/koda/`
- SBOM Tracker: `https://<서버주소>:8088/`
- Dependency-Track: `https://<서버주소>:8088/dependency-track/`

화면 주소는 다음처럼 구분합니다.

- `/`는 KODA-SBOM-Tracker입니다. Tracker에서 수정한 UI는 이 주소에서 확인합니다.
- `/koda/`는 KODA 분석 포털입니다. Tracker에서 승인된 계정은 KODA에도 자동
  활성화되며, KODA 관리자는 필요한 프로젝트 역할만 별도로 배정합니다.
- `/dependency-track/`는 Dependency-Track 화면입니다. 정적 설정 파일 404가 나오면
  새 압축파일의 `install`을 반복하기보다 `./koda-suite status`와
  `docker compose ... logs gateway dtrack-frontend`를 먼저 확인합니다.

Tracker SBOM 업로드 기본 한도는 100MiB이고, KODA 입력 파일은 `/koda/api/`에서
1GiB까지 스트리밍 업로드합니다. 413이 계속되면 앞단 TLS reverse proxy의
`client_max_body_size` 또는 요청 본문 제한도 `/koda/api/` 기준 1GiB 이상으로 맞춥니다.

Tracker UI가 이전 화면으로 보이면 브라우저에서 `Ctrl+Shift+R`로 캐시를 비운 뒤
`/`를 다시 엽니다.

KODA 대시보드의 `SBOM Tracker 열기` 버튼은 기본적으로 same-origin `/`를 엽니다.
별도 Tracker 주소를 사용할 때만 `koda-suite.env`의
`KODA_SSBOM_TRACKER_URL`을 해당 HTTPS 주소로 바꿉니다.
KODA 컨테이너의 8765 포트는 호스트에 게시되지 않고 통합 게이트웨이 전용 Docker
네트워크에서만 접근됩니다. 인증과 권한은 Tracker 계정 및 게이트웨이의
`auth_request` 계약으로 처리됩니다.

## 로그인·계정·권한 계약

- 계정과 로그인 세션의 원본은 KODA SBOM Tracker입니다.
- KODA와 Tracker는 같은 `__Host-koda_session` 쿠키를 사용하므로 한쪽에서
  로그아웃하면 현재 브라우저의 중앙 세션이 폐기되어 양쪽 모두 로그아웃됩니다.
- Tracker의 역할 정책과 KODA의 프로젝트 역할은 별도입니다. 같은 계정이라도
  사이트별로 다른 화면·기능 권한을 가질 수 있습니다.
- 사용자는 로그인 화면에서 가입을 신청합니다. Tracker 관리자가 역할을 확인하고
  활성화하면 같은 계정으로 KODA에도 로그인되며, KODA 프로젝트 역할은 별도입니다.
- KODA의 보안·품질 점검 규칙은 시스템 관리자만 변경합니다. 일반 사용자는
  프로젝트 화면에서 검사 기준과 기준 범위만 선택합니다.
- 로그인 화면의 LDAP 체크박스는 향후 연동용이며 현재 선택하면
  `501 ldap_not_configured`로 실패합니다.

Tracker 장애 시 KODA 보호 화면과 API는 이전 인증 결과를 캐시해 우회하지 않고
`503`으로 실패합니다. `/healthz`, `/api/v1/healthz`, `/koda/live` 같은 명시된
상태 확인 경로만 인증 예외입니다.

## KODA 화면·분석·보고서

- `대시보드`: 프로젝트와 최근 분석 회차를 모아 상태·건수·결과를 검색합니다.
- `새 점검`: 권한이 있는 프로젝트·입력·검사 기준·기준 범위를 선택합니다.
- `프로젝트`: 입력 파일과 회차를 프로젝트별로 관리합니다.
- `점검 결과`: 결과와 실행 당시 정책·요청 계정 스냅샷을 회차별로 보존합니다.
- `비교`: 같은 프로젝트의 회차 결과를 비교합니다.
- `관리자 설정`: 계정 승인, 프로젝트 역할, 보안·품질 규칙과 감사 기록을 관리합니다.

실제 결과 화면, 라이브러리·소스코드·품질 탭과 기능 흐름도는
[KODA 웹 포털 화면과 기능](../../../docs/koda-web-portal.ko.md)에서 확인합니다.

완료 회차의 보고서는 Windows/Linux 공통 CLI 렌더러를 그대로 사용합니다. 화면에서
메인·상세 HTML 보기와 HTML ZIP, PDF, Excel, HWPX, JSON, Markdown을 내려받을 수
있고, SBOM은 CycloneDX 1.6 JSON 또는 국정원 NIS-SBOM 1.0 CSV로 내려받습니다.

웹 분석은 manifest/lockfile에서 정확한 이름·버전·PURL을 얻은 의존성을 번들된
오프라인 Grype DB로 점검합니다. 결과에 라이브러리 취약점이 없으면 입력 파일이
지원 manifest인지와 KODA 컨테이너의 `KODA_GRYPE_BIN`, `GRYPE_DB_CACHE_DIR`를
[장애 대응서](TROUBLESHOOTING.ko.md#koda-웹에서-라이브러리-취약점이-0건)에서
확인합니다. JAR/WAR/EAR 내부 라이브러리는 아래 `jar-scan` 경로를 사용합니다.

## 재기동·상태·중지

```bash
PREFIX="$HOME/koda-suite" # 사용자 지정 설치 경로라면 같은 값으로 변경
"$PREFIX/koda-suite" start
"$PREFIX/koda-suite" status
"$PREFIX/koda-suite" stop
```

`stop`은 컨테이너만 멈추며 PostgreSQL, Dependency-Track, SBOM 원본과 취약점
데이터의 Docker named volume은 삭제하지 않습니다. `start`, `status`, `stop`은 모두
같은 기본·폐쇄망·통합 Compose 파일 조합을 사용하므로 재기동 후에도 KODA는 호스트
포트를 직접 게시하지 않고 통합 게이트웨이로만 접근됩니다.

### 테스트 설치를 완전히 초기화할 때

아래 명령은 계정·세션·프로젝트·SBOM·Dependency-Track DB·취약점 volume과 KODA
포털 SQLite를 모두 삭제합니다. 다른 서비스가 있는 서버에서는 이 목록 외의
`docker system prune`이나 전체 volume/image 삭제를 실행하지 않습니다.

```bash
PREFIX="$HOME/koda-suite"
"$PREFIX/koda-suite" stop || true
docker compose --project-directory "$PREFIX/tracker" --env-file "$PREFIX/tracker/.env" \
  -f "$PREFIX/tracker/compose.yaml" \
  -f "$PREFIX/tracker/compose.airgap.yaml" \
  -f "$PREFIX/tracker/compose.integration.yaml" \
  down --volumes --remove-orphans

# 복구 가능하게 옆으로 보관한 뒤 새 설치에서만 삭제합니다.
if [ -d "$PREFIX/data/koda-portal" ]; then
  mv "$PREFIX/data/koda-portal" \
    "$PREFIX/data/koda-portal.before-reset.$(date -u +%Y%m%dT%H%M%SZ)"
fi

docker image rm \
  koda-offline:0.1.0 \
  local/koda-sbom-portal-web:dev \
  local/koda-sbom-portal-api:dev \
  local/koda-sbom-portal-worker:dev \
  dependencytrack/apiserver:5.0.3 \
  dependencytrack/frontend:5.0.3 \
  postgres:16.10-alpine \
  nginx:1.29.1-alpine \
  anchore/grype:v0.109.1 \
  cyclonedx/cyclonedx-cli:0.30.0 \
  alpine:3.22.1
```

`docker image rm`에서 “image is being used”가 나오면 해당 컨테이너가 아직 남은
것이므로 먼저 `docker ps -a --format '{{.ID}} {{.Names}} {{.Image}}'`로 위 제품의
컨테이너만 확인하고 `docker rm -f <확인한-ID>` 후 다시 실행합니다. 화면에 보이는
다른 제품의 이미지와 `<none>` 이미지는 KODA와 관계가 확인되기 전에는 삭제하지
않습니다. 새 설치는 통합 압축파일의 `./koda-suite install`만 사용합니다.

## 폐쇄망 부분 교체·백업·복원

설치 디렉터리를 통째로 지우거나 내부 image tar를 골라 직접 설치하지 않습니다.
응용프로그램·이미지를 바꿀 때는 새 통합 압축파일을 반입하여 같은 `--prefix`에
덮어 설치합니다. 이 방식은 KODA 포털 디렉터리와 Tracker named volume을 보존합니다.

| 대상 | 실제 저장 위치 | 교체·백업 방법 |
| --- | --- | --- |
| KODA·Tracker·Dependency-Track 응용프로그램/이미지 | Docker 이미지와 `$PREFIX/koda`, `$PREFIX/tracker` | 새 통합 압축파일의 SHA-256과 manifest를 검증한 뒤 같은 prefix에 `install` |
| KODA 사용자 승인·프로젝트 권한·점검 정책·회차 | `$PREFIX/data/koda-portal` | Suite를 중지하고 디렉터리 전체를 tar로 백업·복원 |
| Tracker 계정·역할·세션·서비스·업로드 회차·감사 기록 | `sbom_tracker` DB와 `tracker-artifacts` volume | Tracker `backup-system.sh`/`restore-system.sh` 사용 |
| Dependency-Track 프로젝트·정책·분석 데이터 | `dtrack` DB와 `dtrack-data` volume | 같은 Tracker 전체 백업에 포함 |
| Tracker Grype/NVD/KEV | `vuln-data` volume | 취약점 bundle만 검증·반입·롤백하거나 Tracker 전체 백업 사용 |
| 운영 비밀번호·API 키·TLS 인증서 | `$PREFIX/tracker/.env`와 외부 TLS 종료기 | 릴리스와 분리하여 접근 제한된 암호화 매체에 백업 |
| 원본 소스·SBOM·CLI 보고서 | 운영자가 지정한 호스트 경로 | Suite 백업 대상이 아니므로 해당 디렉터리를 별도 백업 |

### 전체 운영 백업

SQLite와 volume tar의 시점을 맞추려면 유지보수 창에 Suite를 중지한 뒤 백업합니다.
Tracker 백업 스크립트는 필요한 동안 PostgreSQL만 기동합니다. 운영 `.env`는 기본
백업에 포함되지 않으므로 릴리스 압축파일·SHA-256 파일과 함께 별도 암호화 매체에
보관합니다.

```bash
PREFIX="$HOME/koda-suite"
BACKUP_DIR="/media/koda-backup/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$BACKUP_DIR"

"$PREFIX/koda-suite" stop
tar -C "$PREFIX/data" -czf "$BACKUP_DIR/koda-portal.tar.gz" koda-portal
cp "$PREFIX/metadata.env" "$BACKUP_DIR/suite-metadata.env"
(cd "$BACKUP_DIR" && \
  sha256sum koda-portal.tar.gz suite-metadata.env > local-files.sha256)

ENV_FILE="$PREFIX/tracker/.env" BACKUP_ROOT="$BACKUP_DIR/tracker" \
  "$PREFIX/tracker/scripts/backup-system.sh"
ENV_FILE="$PREFIX/tracker/.env" \
  "$PREFIX/tracker/scripts/verify-backup.sh" \
  "$BACKUP_DIR/tracker/<출력된-UTC-시각>"

"$PREFIX/koda-suite" start
"$PREFIX/koda-suite" status
```

Tracker 백업에는 두 PostgreSQL DB와 Tracker 첨부파일, Dependency-Track 데이터,
Tracker 취약점 volume이 포함됩니다. KODA 포털 디렉터리, 운영 `.env`, TLS 인증서,
호스트의 원본/보고서는 포함되지 않으므로 위처럼 각각 보관해야 전체 복원이
가능합니다.

### 응용프로그램·이미지 교체

새 통합 압축파일을 별도 디렉터리에 풀고 무결성을 확인한 뒤 기존 prefix에 설치합니다.
업데이트 전에 위 백업을 만들고, 정상 확인 전에는 이전 릴리스 압축파일과 Docker
이미지를 삭제하거나 `docker system prune`을 실행하지 않습니다.

```bash
PREFIX="$HOME/koda-suite"
cd /media/koda-release
sha256sum -c koda-suite-offline-x86_64-<새버전>.tar.gz.sha256
cd koda-suite-offline-x86_64-<새버전>
./koda-suite verify
./koda-suite install --env-file "$PREFIX/tracker/.env" --prefix "$PREFIX"
./koda-suite status
```

기존 설치를 갱신할 때는 통합본에 취약점 데이터가 들어 있어도 자동 반입하지
않습니다. `metadata.env`의 `TRACKER_VULNERABILITY_BUNDLE=included`를 확인한 뒤 아래
`Tracker 취약점 데이터 저장과 갱신` 절차로 `$PREFIX/tracker/vulnerability-data`를
명시적으로 검증·반입합니다. 특정 컨테이너만 임의 태그로 교체하면 manifest와
Compose 고정 버전 계약이 깨지므로, 한 제품만 수정한 경우에도 새 통합본을 생성하여
같은 절차로 반입합니다.

### 데이터만 복원

KODA 포털 데이터만 되돌릴 때는 백업 해시를 확인하고 현재 디렉터리를 즉시 삭제하지
말고 옆으로 이동해 둡니다.

```bash
PREFIX="$HOME/koda-suite"
BACKUP_DIR=/media/koda-backup/<UTC-시각>
(cd "$BACKUP_DIR" && sha256sum -c local-files.sha256)

"$PREFIX/koda-suite" stop
mv "$PREFIX/data/koda-portal" \
  "$PREFIX/data/koda-portal.before-restore.$(date -u +%Y%m%dT%H%M%SZ)"
tar -C "$PREFIX/data" -xzf "$BACKUP_DIR/koda-portal.tar.gz"
"$PREFIX/koda-suite" start
"$PREFIX/koda-suite" status
```

Tracker·Dependency-Track 데이터를 되돌릴 때는 백업 당시와 호환되는 릴리스와
`.env`를 먼저 준비합니다. 복원 스크립트는 현재 DB와 named volume을 교체하고
PostgreSQL만 기동한 상태로 끝나므로 Suite를 다시 시작해야 합니다.

```bash
PREFIX="$HOME/koda-suite"
TRACKER_BACKUP=/media/koda-backup/<UTC-시각>/tracker/<UTC-시각>

"$PREFIX/koda-suite" stop
ENV_FILE="$PREFIX/tracker/.env" \
  "$PREFIX/tracker/scripts/verify-backup.sh" "$TRACKER_BACKUP"
ENV_FILE="$PREFIX/tracker/.env" \
  "$PREFIX/tracker/scripts/restore-system.sh" "$TRACKER_BACKUP"
"$PREFIX/koda-suite" start
"$PREFIX/koda-suite" status
```

백업과 현재 `.env`의 `COMPOSE_PROJECT_NAME`, DB 이름, volume 이름이 다르면 임의로
복원하지 않습니다. 계정·권한·점검 정책을 관리자 화면에서 대량 변경하기 전에도
Tracker DB와 KODA 포털 디렉터리 중 해당 저장소를 먼저 백업합니다.

## 스캔과 SBOM 전달

KODA CLI는 기존 명령을 그대로 사용합니다.

```bash
PREFIX="$HOME/koda-suite" # 사용자 지정 설치 경로라면 같은 값으로 변경
"$PREFIX/koda/koda-docker" list-categories
"$PREFIX/koda/koda-docker" jar-scan \
  --target /srv/app/app.jar --output-dir /srv/koda-reports
```

화면 버튼은 브라우저 연결점이며 SBOM이나 API 키를 자동 전달하지 않습니다.
Tracker에 CycloneDX SBOM 회차를 올릴 때는 Tracker가 발급한 서비스 토큰으로 기존
업로드 스크립트를 사용합니다.

```bash
KODA_TRACKER_URL=http://127.0.0.1:8088 \
KODA_TRACKER_TOKEN='<서비스 토큰>' \
  "$PREFIX/tracker/scripts/upload-sbom.sh" \
  <service-id> <environment-id> <release> ./bom.cdx.json <build-id>
```

## Tracker 취약점 데이터 저장과 갱신

KODA에 포함된 Grype DB는 버전이 달라 Tracker와 공유하지 않습니다. Tracker 전용
데이터는 기본 Docker named volume `koda-sbom-vuln-data`에 저장되고, API와 worker
컨테이너에는 `/var/lib/sbom-tracker/vuln-data:ro`로 보입니다. 반입 스크립트는
`releases/<버전>/`을 만든 뒤 `current` 링크를 원자적으로 바꾸고 기존 버전은
`previous`로 보존합니다. 현재 bundle의 실제 파일 배치는 다음과 같습니다.

```text
current/
├── grype-db/<schema>/vulnerability.db
├── nvd.json
├── alias-index.json       # 제공한 경우
├── kev.json
├── metadata.env
└── manifest.sha256
```

Tracker의 Grype 실행은 자동 다운로드와 DB 연령 거부를 끄고 이 `current` 데이터만
사용합니다. 포털에 표시되는 기준일을 보고 조직의 갱신 주기에 맞춰 교체합니다.

갱신 bundle은 인터넷 연결 구역에서 Tracker 저장소의
`scripts/build-vuln-bundle.sh`로 생성하고 manifest와 별도 SHA-256을 확인한 뒤
승인된 매체로 반입합니다. 폐쇄망 서버에서는 다음처럼 검증·반입합니다.

```bash
PREFIX="$HOME/koda-suite" # 사용자 지정 설치 경로라면 같은 값으로 변경
BUNDLE=/media/koda-vuln/20260809
"$PREFIX/tracker/scripts/verify-vuln-bundle.sh" "$BUNDLE"
ENV_FILE="$PREFIX/tracker/.env" \
  "$PREFIX/tracker/scripts/import-vuln-bundle.sh" "$BUNDLE"
```

그 다음 포털 관리자 화면의 `취약점 데이터 → 반입 상태 동기화`를 실행합니다.
기존 분석은 자동 재계산되지 않으므로 필요한 SBOM 회차에서 `새 분석 리비전`을
실행하거나 다시 업로드합니다. 이전 데이터로 되돌릴 때는 아래 명령 후 같은
동기화를 다시 실행합니다.

```bash
ENV_FILE="$PREFIX/tracker/.env" \
  "$PREFIX/tracker/scripts/rollback-vuln-bundle.sh"
```

상세 생성 옵션과 NVD 전체 feed 준비 절차는
`$PREFIX/tracker/docs/offline-bundle-ko.md`를 따릅니다.

이 통합본은 `DISTRIBUTION_SCOPE=internal-only`인 KODA 내부 폐쇄망 반입용입니다.
외부 고객·협력사·공개 배포 전에는 포함 이미지와 대응 소스 제공 범위를 별도로
검토해야 합니다.
