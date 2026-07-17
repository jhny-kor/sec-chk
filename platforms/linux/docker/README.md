# KODA 폐쇄망 Docker 전달물

Linux x86_64 폐쇄망 서버에서 KODA JAR/WAR/EAR SBOM·취약점 점검을 Docker로
실행하기 위한 단일 전달물입니다. Docker Engine은 서버에 이미 설치되어 있어야
하며, 이 전달물은 Docker나 호스트 설정을 변경하지 않습니다.

## 구성

```text
koda-docker-offline-x86_64-<version>/
├── install.sh          # 폐쇄망 설치 스크립트
├── koda-docker.sh      # 실행 래퍼 (설치 후 <prefix>/koda-docker)
├── README.md
├── image-ref.txt       # koda-offline:<version>
├── versions.txt        # Syft/Grype/DB/NVD/CISA 기준 정보
├── manifest.sha256     # 전체 파일 SHA-256
└── image/
    └── koda-offline-amd64.tar
```

이미지에는 KODA 소스, Syft, Grype, import 완료된 Grype DB, NVD 피드,
CISA KEV, Playwright Chromium(PDF 렌더러)이 포함됩니다.

## 설치

```bash
cd /home/user0/projects/koda
tar -xzf koda-docker-offline-x86_64-<version>.tar.gz
cd koda-docker-offline-x86_64-<version>
bash install.sh                       # 기본 prefix /home/user0/projects/koda
# KODA_DOCKER_PREFIX=/srv/koda bash install.sh
```

설치 스크립트는 manifest 검증 → Docker 확인 → `docker load` → 아키텍처·라벨
확인 → 무통신 스모크 테스트 → 래퍼 복사 순서로 동작합니다. 같은 버전
재설치는 안전하며 기존 보고서·실행 중 대시보드는 건드리지 않습니다.

## 실행

모든 CLI 실행은 기본적으로 `--network none`, read-only rootfs, 비루트,
capability 제거, CPU/메모리/PID 제한이 적용됩니다. `--target`/`--sbom`/
`--baseline-sbom`은 읽기 전용, `--output-dir`/`--output`만 쓰기 가능으로
동일 절대경로에 자동 마운트됩니다.

```bash
# JAR 취약점 분석
./koda-docker jar-scan \
  --target /jeus/domains/domain1/applications \
  --output-dir /home/user0/projects/koda/reports/java-scan

# 승인 SBOM과 실제 배포 파일 비교
./koda-docker sbom-verify \
  --target /jeus/domains/domain1/applications \
  --sbom /home/user0/projects/koda/reports/approved-sbom.cdx.json \
  --output-dir /home/user0/projects/koda/reports/sbom-verification \
  --strict-hash --fail-on-version-conflict --fail-on-untracked --fail-on-mismatch

# 승인 SBOM + 실제 JAR + 취약점 통합 점검 (jar-scan --verify-sbom 조합)
./koda-docker audit \
  --target /jeus/domains/domain1/applications \
  --baseline /home/user0/projects/koda/approved/production-sbom.cdx.json \
  --reports /home/user0/projects/koda/reports/production
```

종료 코드: `0` 기준 통과, `1` 취약점/SBOM 불일치, `2` 입력·도구·실행 오류.

기본적으로 한 번에 하나의 스캔만 실행됩니다(flock). 병렬 실행이 꼭 필요하면
`KODA_ALLOW_CONCURRENT=1`을 지정하십시오.

자원 제한 조정: `KODA_CPUS`(기본 2), `KODA_MEMORY`(4g),
`KODA_PIDS_LIMIT`(256), `KODA_TMPFS_SIZE`(512m). 추가 docker 옵션은
`KODA_DOCKER_EXTRA_ARGS`(공백 구분)로 제한적으로 전달합니다.

## 대시보드

```bash
./koda-docker dashboard start [--reports /home/user0/projects/koda/reports]
./koda-docker dashboard status
./koda-docker dashboard logs [-f]
./koda-docker dashboard stop
```

기본 바인딩은 `127.0.0.1:8765`입니다. 원격 접속은 SSH 터널을 사용합니다.

```bash
ssh -L 8765:127.0.0.1:8765 user0@<server-ip>
# http://127.0.0.1:8765/security-dashboard.html
```

직접 접속이 승인된 경우에만 `KODA_DASHBOARD_BIND=0.0.0.0`을 명시적으로
지정합니다. 대시보드 네트워크는 전용 브리지에 IP masquerade를 비활성화해
컨테이너 발신 트래픽을 차단합니다. (`--internal` 네트워크는 포트 공개까지
차단하므로 사용하지 않습니다.)

## 갱신과 롤백

갱신은 새 전달물 반입으로만 수행합니다. 컨테이너의 인터넷 업데이트는
비활성화되어 있습니다.

```bash
# 연결된 빌드 PC
bash platforms/linux/package-docker-offline.sh --refresh

# 폐쇄망 서버
tar -xzf koda-docker-offline-x86_64-<new-version>.tar.gz
cd koda-docker-offline-x86_64-<new-version> && bash install.sh
```

이전 버전 이미지는 롤백을 위해 보관됩니다. 롤백은 `image-ref.txt`를 이전
버전 태그로 되돌리거나 `KODA_IMAGE=koda-offline:<old-version>`으로
실행하면 됩니다. 검증 완료 후 구버전은 `docker image rm`으로 정리합니다.

## GitLab 적재 (선택)

폐쇄망 내 다른 서버에 GitLab이 있으면 전달물을 두 가지 방식으로 적재할 수
있습니다. 두 방식 모두 스캔 컨테이너의 `--network none` 격리와는 무관하게
호스트에서 수행하는 작업입니다.

### 1) GitLab Container Registry에 이미지 push (권장)

GitLab에 Container Registry가 활성화되어 있어야 합니다.

```bash
docker login registry.gitlab.example.internal
docker tag koda-offline:<version> \
  registry.gitlab.example.internal/<group>/koda/koda-offline:<version>
docker push registry.gitlab.example.internal/<group>/koda/koda-offline:<version>
```

다른 서버에서는 `docker pull` 후 `image-ref.txt`(또는 `KODA_IMAGE`)를 해당
레퍼런스로 지정하면 래퍼가 그대로 동작합니다. 사설 CA를 쓰는 경우 각 Docker
호스트에 `/etc/docker/certs.d/<registry>/ca.crt`를 배치해야 하며,
`--insecure-registry` 설정은 권장하지 않습니다.

### 2) Generic Package Registry에 tar.gz 업로드

Registry가 없거나 파일 그대로 보관하려는 경우:

```bash
curl --header "PRIVATE-TOKEN: <token>" \
  --upload-file koda-docker-offline-x86_64-<version>.tar.gz \
  "https://gitlab.example.internal/api/v4/projects/<id>/packages/generic/koda-docker-offline/<version>/koda-docker-offline-x86_64-<version>.tar.gz"
```

주의: GitLab 저장소(git)에 544MB+ tar.gz를 직접 커밋하지 마십시오. 서버
기본 업로드 제한(`max_import_size`, nginx `client_max_body_size`)보다 큰
파일은 업로드 전에 관리자 설정 확인이 필요합니다. 토큰은 만료 기한이 있는
프로젝트 전용(Deploy Token / Project Access Token, `write_registry` 또는
`api` 최소 범위)을 사용하십시오.

### 스캔 결과 적재

보고서(JSON/HTML/Markdown)를 GitLab CI 아티팩트나 저장소로 적재하려면
`platforms/linux/examples/gitlab-ci.yml`을 참고해 러너에서
`koda-docker jar-scan ... --output-dir "$CI_PROJECT_DIR/reports"`를 실행하고
`artifacts: paths: [reports/]`로 수집하면 됩니다.

## 보안 기본값 확인

```bash
docker inspect <container> --format \
  '{{.HostConfig.NetworkMode}} {{.HostConfig.ReadonlyRootfs}} {{.HostConfig.CapDrop}} {{.HostConfig.SecurityOpt}} {{.HostConfig.PidsLimit}} {{.HostConfig.Memory}} {{.HostConfig.NanoCpus}} {{.Config.User}}'
```

Docker socket 마운트, privileged, host network/PID/IPC는 사용하지 않습니다.
