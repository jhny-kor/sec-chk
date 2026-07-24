# Windows 취약점 데이터(zip) 현행화 절차

`koda-vuln-data-<date>.zip`은 Windows 설치본이 사용하는 NVD·CISA KEV 자료
묶음입니다. 설치본과 분리되어 있어, 데이터가 오래되면 **이 zip만 다시 만들어
반입**하면 됩니다. 설치본 재빌드·재설치는 필요 없습니다.

이 문서는 사람이 주기적으로 데이터를 최신화하는 표준 절차입니다.

## 언제 갱신하나

* CISA KEV는 거의 매일, NVD도 매일 바뀝니다.
* 운영 기준으로 **주 1회 또는 배포 심사 직전** 갱신을 권장합니다.
* 새 연도가 시작되면(예: 2027년 1월) 그해 NVD 피드가 자동 포함되도록 최소 한 번
  갱신해야 합니다.

현재 데이터의 기준일은 zip 안 `vuln-data/versions.txt`에서 확인합니다.

```powershell
# 이미 반입된 데이터의 기준일 확인
type %LOCALAPPDATA%\KODA\vuln-data\versions.txt
```

```text
cisa_kev_date_released=2026-07-16T17:00:15.6845Z   ← KEV 카탈로그 발행일
cisa_kev_catalog_version=2026.07.16
nvd_end_year=2026                                  ← 포함된 마지막 NVD 연도
```

## 준비물

* **인터넷에 연결된 빌드 PC** (Windows, macOS 또는 Linux). NVD·CISA에서 자료를
  내려받아야 하므로 폐쇄망 서버에서는 만들 수 없습니다.
* 이 저장소(sec-chk) 체크아웃.
* Windows: PowerShell 5.1 또는 PowerShell 7. Python, Docker, Inno Setup은
  필요하지 않습니다.
* macOS/Linux: Python 3, curl. (저장소 빌드 환경에 이미 있습니다.)

## 절차

### 1. 빌드 PC에서 새 데이터 zip 생성

#### Windows에서 생성

저장소 체크아웃 폴더에서 PowerShell 5.1 또는 PowerShell 7로 실행합니다.
Python, Docker, Inno Setup은 필요하지 않습니다.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\platforms\windows\scripts\build-koda-vuln-data.ps1
```

결과는 `dist\Windows\koda-vuln-data-<date>.zip`입니다. 연도별 NVD 피드는
`.build\koda-vuln-data-cache`에 캐시되며, 매 실행 시 `.meta`의 SHA-256으로
검증됩니다. `recent`, `modified`, CISA KEV는 매번 새로 내려받습니다.
처음부터 연도별 피드를 다시 받으려면 `-Refresh`를 추가하십시오.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\platforms\windows\scripts\build-koda-vuln-data.ps1 `
  -Refresh
```

#### macOS/Linux에서 생성

```bash
cd /path/to/sec-chk
bash platforms/linux/package-offline.sh --vuln-data-only
```

* 기본으로 NVD 2002년부터 현재 연도까지 + recent/modified + CISA KEV를 받습니다.
* 연도별 NVD는 캐시를 재사용하고, 변경분(recent/modified/KEV)만 새로 받습니다.
  캐시된 연도 피드까지 `.meta`로 다시 검증하려면 뒤에 `--refresh`를 붙입니다.
* 완료되면 경로와 SHA-256을 출력합니다.

```text
sha256=def5781460d0377066fb66d091cf978ea0a37fb49361478a568d694fb4e7f679
/path/to/sec-chk/dist/Windows/koda-vuln-data-2026-07-18.zip
```

파일명의 날짜는 빌드한 날(UTC)입니다. 출력된 **SHA-256을 따로 기록**해 두십시오
(2·4단계에서 사용).

> 연도 범위를 좁히려면: `KODA_NVD_START_YEAR=2025 KODA_NVD_END_YEAR=2026 bash
> platforms/linux/package-offline.sh --vuln-data-only`

### 2. 폐쇄망으로 반입

승인된 매체/경로로 zip을 서버 또는 대상 Windows PC로 옮깁니다. 옮긴 뒤 무결성을
확인합니다.

```powershell
Get-FileHash koda-vuln-data-2026-07-18.zip -Algorithm SHA256
# 출력 Hash가 1단계에서 기록한 sha256과 같은지 대조
```

값이 다르면 전송이 손상된 것이므로 다시 반입합니다.

### 3. 설치 폴더에 덮어쓰기

```powershell
Expand-Archive -Path koda-vuln-data-2026-07-18.zip `
  -DestinationPath $env:LOCALAPPDATA\KODA -Force
```

* `-Force`가 기존 `vuln-data\` 내용을 새 자료로 교체합니다.
* zip 내부 경로가 `vuln-data\...`이므로 정확히 `%LOCALAPPDATA%\KODA\vuln-data\`에
  풀립니다. 다른 폴더에 풀면 설치본이 인식하지 못합니다.
* 실행 중인 KODA가 있으면 닫았다가 다시 여십시오. 환경변수는 프로세스 시작
  시점에 잡힙니다.

### 4. 갱신 확인

```powershell
type %LOCALAPPDATA%\KODA\vuln-data\versions.txt
```

`cisa_kev_date_released`와 `nvd_end_year`가 기대한 최신 값인지 확인합니다.
이어서 실제 스캔으로 게이트가 동작하는지 확인합니다.

```bat
koda jar-scan --target D:\some\apps ^
  --output-dir %TEMP%\koda-check --fail-on-kev
echo exit=%ERRORLEVEL%
```

* `exit=0` 또는 `exit=1`: 데이터가 정상 인식됨(1은 악용 취약점 발견).
* `exit=2` + "requires CISA KEV data" 경고: **데이터가 인식되지 않음.** zip을
  `%LOCALAPPDATA%\KODA\`가 아닌 곳에 풀었을 가능성이 큽니다. 3단계 경로를
  확인하십시오.

## 되돌리기(롤백)

이전 zip 파일을 보관해 두었다면 그것을 다시 3단계 방식으로 풀면 됩니다. 데이터
교체는 파일 덮어쓰기일 뿐이므로 설치본에는 영향을 주지 않습니다. 직전 zip을
최소 1개 보관하는 것을 권장합니다.

## 참고

* 앱을 새 `KODASetup.exe`로 업그레이드해도 `vuln-data\`는 지워지지 않습니다.
  KODA를 제거하면 설치 폴더와 함께 데이터도 삭제됩니다.
* 데이터 없이도 `jar-scan`은 Grype만으로 동작하지만, CVSS·악용 여부 정보가 빠지고
  `--fail-on-kev`는 통과 대신 `exit=2`가 됩니다.
* Linux/Docker 배포에서는 데이터가 번들·이미지 안에 포함되므로 이 절차가 아니라
  전달물 자체를 새로 반입해 갱신합니다. → [offline-delivery.md](offline-delivery.md)
