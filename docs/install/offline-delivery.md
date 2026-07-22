# KODA 폐쇄망 배포 개요

폐쇄망 서버에서 JAR/WAR/EAR SBOM·취약점 점검을 실행하기 위한 배포물과 설치
흐름을 정리합니다. 세 가지 전달 방식이 있으며 모두 같은 스캐너 엔진
(`platforms/shared/python/security_scanner/`)을 사용합니다.

| 방식 | 대상 | 반입 파일 | 데이터 위치 |
| --- | --- | --- | --- |
| Docker 전달물 | Docker Engine이 있는 Linux x86_64 | 1개 (tar.gz) | 이미지 내부 |
| Linux tarball | Python 3.10+ 있는 Linux x86_64 | 1개 (tar.gz) | 설치 폴더 내부 |
| Windows 설치본 + 데이터 zip | Windows 10/11 | 2개 (exe + zip) | 설치 폴더 옆 `vuln-data\` |

빌드는 항상 인터넷에 연결된 빌드 PC(macOS/Linux, Windows 설치본은 Windows)에서
수행하고, 결과물만 폐쇄망으로 반입합니다.

## 점검 파이프라인

세 방식 모두 동일합니다.

```text
JAR/WAR/EAR
  → Syft로 CycloneDX SBOM 생성 (내장 식별기로 보강)
  → Grype 로컬 DB 매칭으로 CVE 추출
  → NVD 결합 (CVSS·CWE·설명 보강)
  → CISA KEV 결합 (실제 악용 여부)
  → HTML·JSON·Markdown 보고서
```

* 최초 취약점 매칭은 **Grype DB** 기준입니다. NVD·CISA만으로 직접 판정하지
  않습니다.
* KNVD 자료는 사용하지 않습니다.
* Grype 자동 DB 업데이트는 비활성화된 상태로 실행됩니다.

### 운영 게이트와 종료 코드

| 코드 | 의미 |
| --- | --- |
| 0 | 설정한 기준 통과 |
| 1 | `--fail-on` 심각도 이상 또는 `--fail-on-kev` 악용 취약점 발견, 또는 SBOM 불일치 |
| 2 | 입력·도구·DB·실행 오류. `--fail-on-kev`를 켰는데 CISA KEV 자료가 없으면 여기에 해당(게이트를 조용히 통과시키지 않음) |

## 1. Docker 전달물 (Linux x86_64)

가장 격리 수준이 높은 방식입니다. Docker Engine은 서버에 이미 있어야 하며
전달물은 Docker나 호스트 설정을 변경하지 않습니다.

**빌드**

```bash
bash platforms/linux/package-docker-offline.sh --refresh
# → dist/linux/koda-docker-offline-x86_64-<version>.tar.gz
```

다단계 이미지(digest 고정 base, Grype DB 빌드 중 import, 비루트)를 만들고
무통신 스모크 테스트 후 이미지·설치 스크립트·래퍼를 tar.gz 하나로 묶습니다.

**설치**

```bash
cd /home/user0/projects/koda
tar -xzf koda-docker-offline-x86_64-<version>.tar.gz
cd koda-docker-offline-x86_64-<version>
bash install.sh
```

`install.sh`가 manifest 검증 → Docker 확인 → `docker load` → 아키텍처·라벨
확인 → 스모크 테스트 → 래퍼 설치를 수행합니다.

**실행** — 모든 CLI가 기본적으로 `--network none`, read-only rootfs, 비루트,
cap-drop ALL, CPU/메모리/PID 제한으로 실행됩니다. 대상 JAR은 읽기 전용, 보고서
경로만 쓰기 가능으로 자동 마운트됩니다.

```bash
./koda-docker jar-scan --target /jeus/domains/domain1/applications \
  --output-dir reports/java-scan --fail-on high --fail-on-kev

./koda-docker audit --target /jeus/domains/domain1/applications \
  --baseline approved/production-sbom.cdx.json --reports reports/production

./koda-docker dashboard start   # 기본 127.0.0.1:8765
```

상세: [platforms/linux/docker/README.md](../../platforms/linux/docker/README.md)

## 2. Linux tarball (호스트 직접 설치)

Docker 없이 Python 3.10+만 있는 서버용입니다.

```bash
# 빌드
bash platforms/linux/package-offline.sh --refresh
# → dist/linux/koda-linux-x86_64-<version>.tar.gz

# 폐쇄망 설치
tar -xzf koda-linux-x86_64-<version>.tar.gz
cd koda-linux-x86_64-<version>
bash install.sh                 # 기본 prefix /home/user0/koda

# 실행
/home/user0/koda/koda jar-scan --target /deploy/app \
  --output-dir reports/java-scan --fail-on high --fail-on-kev
```

Syft·Grype·Grype DB·NVD·CISA·Playwright/Chromium이 모두 번들에 포함되며
설치 시 자동으로 경로가 잡힙니다. 상세:
[platforms/linux/README-offline.md](../../platforms/linux/README-offline.md)

## 3. Windows 설치본 + 데이터 zip

설치본에는 앱·Syft·Grype·Grype DB·Chromium이 들어가고, **매일 바뀌는 NVD·CISA
KEV는 별도 데이터 zip으로 분리**됩니다. 데이터를 분리하는 이유는 갱신 때마다
설치본을 재빌드·재서명·재승인하지 않고 zip만 교체하기 위해서입니다.

```powershell
# 설치본 빌드 (Windows 빌드 PC)
powershell -File platforms\windows\scripts\build-koda-windows-installer.ps1
# → dist\Windows\KODASetup.exe

# 설치 (관리자 권한 불필요, %LOCALAPPDATA%\KODA)
KODASetup.exe
```

```bash
# 데이터 zip 빌드 (macOS/Linux 빌드 PC)
bash platforms/linux/package-offline.sh --vuln-data-only
# → dist/Windows/koda-vuln-data-<date>.zip
```

Windows에서 직접 생성하려면 다음 PowerShell 스크립트를 사용합니다.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\platforms\windows\scripts\build-koda-vuln-data.ps1
# → dist\Windows\koda-vuln-data-<date>.zip
```

스크립트는 연도별 NVD 피드를 `.meta` SHA-256으로 검증하고, NVD
`recent`/`modified`와 CISA KEV를 새로 받아 동일한 `vuln-data\` 내부 구조로
압축합니다. 상세 옵션은 [Windows 설치](windows.md)와
[데이터 현행화 절차](vuln-data-refresh.md)를 참고하십시오.

```powershell
# 데이터 반입: 설치 폴더에 압축 해제
Expand-Archive koda-vuln-data-<date>.zip -DestinationPath $env:LOCALAPPDATA\KODA -Force
```

설치본의 런타임 훅이 시작 시 `vuln-data\`를 감지해 `KODA_NVD_DATA`·
`KODA_CISA_KEV`를 자동 설정합니다. 명령어는 다른 플랫폼과 동일합니다.

```bat
"%LOCALAPPDATA%\KODA\KODA-CLI.cmd" jar-scan --target D:\apps ^
  --output-dir reports --fail-on high --fail-on-kev
```

데이터 zip 갱신 절차: [vuln-data-refresh.md](vuln-data-refresh.md) · 설치본
상세: [windows.md](windows.md)

## GitLab 적재 (선택)

폐쇄망 내 다른 서버에 GitLab이 있으면 전달물을 적재할 수 있습니다.

* **Container Registry push (권장)** — `docker tag` + `docker push`로 이미지를
  올리고, 다른 서버에서 `docker pull` 후 `KODA_IMAGE` 또는 `image-ref.txt`만
  지정합니다.
* **Generic Package Registry** — tar.gz/zip 전달물을 `curl --upload-file`로
  API 업로드합니다.

git 저장소에 대용량 전달물을 직접 커밋하지 마십시오. 상세:
[platforms/linux/docker/README.md](../../platforms/linux/docker/README.md)

## 빌드 옵션 요약

| 명령 | 산출물 | 용도 |
| --- | --- | --- |
| `package-docker-offline.sh [--refresh]` | `dist/linux/koda-docker-offline-*.tar.gz` | Docker 전달물 |
| `package-offline.sh [--refresh]` | `dist/linux/koda-linux-x86_64-*.tar.gz` | Linux tarball |
| `package-offline.sh --vuln-data-only` | `dist/Windows/koda-vuln-data-<date>.zip` | Windows 데이터 |
| `build-koda-vuln-data.ps1` | `dist\Windows\koda-vuln-data-<date>.zip` | Windows에서 직접 생성하는 데이터 |
| `build-koda-windows-installer.ps1` | `dist/Windows/KODASetup.exe` | Windows 설치본 |

`--refresh`는 캐시된 연도별 NVD 피드를 `.meta`로 재검증하고 Grype DB 메타데이터를
다시 확인합니다. NVD recent/modified와 CISA KEV는 옵션과 무관하게 매 빌드
갱신됩니다. 연도 범위는 `KODA_NVD_START_YEAR`/`KODA_NVD_END_YEAR`로 조정합니다.
