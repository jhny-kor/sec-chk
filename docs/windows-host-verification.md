# Windows 호스트 점검 검증 필요 문서

> 목적: KODA `host-scan`의 **Windows 체크는 macOS 개발 환경에서 실행·검증이 불가**하다. 실제 Windows에서 확인해야 할 항목과 절차를 정리한다.
> 상태: 미검증(unverified) — 구조는 구현 완료, **실 Windows 실행 검증 대기**.
> 관련 코드: `security_scanner/checks/host/host_windows.py`
> 최종 갱신: 2026-06-07

---

## 1. 왜 별도 검증이 필요한가
- 개발/CI 머신이 macOS라 PowerShell 기반 Windows 체크의 실제 출력 형식을 확인할 수 없다.
- 각 cmdlet의 출력 문자열(대소문자, 줄바꿈, 로캘 영향)이 파서 가정과 다를 수 있다.
- 일부 cmdlet은 **관리자 권한** 또는 특정 Windows 버전/SKU가 필요하다.

## 2. 구현된 Windows 체크 (검증 대상)

| rule_id | cmdlet | 기대 출력 | 권한 | CIS 매핑 |
|---|---|---|---|---|
| `host.windows.bitlocker-on` / `-off` | `(Get-BitLockerVolume -MountPoint $env:SystemDrive).ProtectionStatus` | `On`/`Off`(또는 1/0) | 관리자 권장 | disk-encryption |
| `host.windows.defender-realtime-on` / `-off` | `(Get-MpComputerStatus).RealTimeProtectionEnabled` | `True`/`False` | 표준 | malware-defense |
| `host.windows.secure-boot-on` / `-off` / `-unsupported` | `Confirm-SecureBootUEFI` | `True`/`False`/예외 | 관리자 | boot-integrity |
| `host.windows.firewall-all-profiles-enabled` / `firewall-profile-disabled` | `Get-NetFirewallProfile … Where {-not $_.Enabled}` | 비활성 프로파일명 CSV | 표준 | network |

## 3. 검증 절차 (실 Windows에서)

### 3.1 단독 실행
```powershell
# 저장소 클론 후 PowerShell에서
python -m security_scanner host-scan --min-severity info
python -m security_scanner host-scan --format json --output host.json
```
- 6개(예상) 항목이 나오는지, 각 rule_id가 위 표와 일치하는지 확인.
- `warning:` 출력이 있으면 어떤 체크가 실패했는지 기록.

### 3.2 cmdlet 원시 출력 캡처 (파서 검증)
아래를 직접 실행해 **실제 출력 문자열**을 수집하고, 파서 가정(`host_windows.py`)과 비교한다.
```powershell
(Get-BitLockerVolume -MountPoint $env:SystemDrive).ProtectionStatus
(Get-MpComputerStatus).RealTimeProtectionEnabled
try { [string](Confirm-SecureBootUEFI) } catch { 'unsupported' }
(Get-NetFirewallProfile | Where-Object { -not $_.Enabled } | Select-Object -ExpandProperty Name) -join ','
```

### 3.3 권한 분기 확인
- 비관리자 PowerShell에서 BitLocker/Secure Boot가 어떤 결과(값/에러)를 주는지 확인.
- 에러 시 KODA는 해당 체크를 graceful skip(발견 없음)하도록 설계됨 → "조용히 누락"되는지, 경고로 표면화할지 정책 결정 필요.

## 4. 예상 이슈 / 확인 포인트
- [ ] `ProtectionStatus`가 enum(`On`/`Off`) vs 정수(`1`/`0`)로 나오는지 — 파서는 둘 다 처리하지만 실측 필요.
- [ ] `RealTimeProtectionEnabled`가 `True`(영문) 외 로캘 의존 출력이 있는지.
- [ ] `Confirm-SecureBootUEFI`가 레거시 BIOS에서 던지는 예외 메시지 — 현재 `'unsupported'`로 캐치.
- [ ] `Get-NetFirewallProfile`이 Home/Pro SKU·도메인 미가입 환경에서 정상 동작하는지.
- [ ] `powershell.exe` vs `pwsh.exe` 경로 — runner allowlist에 둘 다 포함되어 있음.
- [ ] WebView2 단일창 앱 런타임에서 subprocess(PowerShell) 호출이 정상인지(콘솔창 노출 여부 포함).
- [ ] 한글 Windows 로캘에서 출력 인코딩(cp949) 문제 — runner는 `text=True` 기본 디코딩 사용. 깨질 경우 인코딩 옵션 보강 필요.

## 5. 검증 후 할 일
- [ ] 실측 출력에 맞춰 `host_windows.py` 파서 보정.
- [ ] Windows 전용 단위 테스트 추가(실측 문자열을 fixture로 mock).
- [ ] 권한 부족/미지원 SKU의 graceful 처리 정책 확정 및 문서화.
- [ ] `docs/roadmap-endpoint-security.md` Phase 1 Windows 항목을 검증 완료로 갱신.
- [ ] 가능하면 GitHub Actions `windows-latest` 러너로 스모크 테스트(`host-scan` 실행) 추가.

## 5a. Phase 2 Windows 인벤토리/CVE 검증 (신규, 미검증)
`security_scanner/inventory.py`의 Windows 경로는 레지스트리 Uninstall 키를 PowerShell로 조회한다.

```powershell
# 인벤토리 원시 출력 확인
$paths=@('HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')
Get-ItemProperty $paths -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName } |
  Select-Object @{N='name';E={$_.DisplayName}}, @{N='version';E={$_.DisplayVersion}}, @{N='vendor';E={$_.Publisher}} |
  ConvertTo-Json -Compress

# KODA 경유
python -m security_scanner host-scan --inventory --eol --min-severity info
python -m security_scanner host-scan --check-cve --nvd-api-key-env NVD_API_KEY
```
확인 포인트:
- [ ] `ConvertTo-Json`이 단일 항목일 때 배열이 아닌 객체로 출력 → `inventory.py`는 dict→[dict] 처리하지만 실측 필요.
- [ ] 한글 로캘에서 DisplayName/Publisher 인코딩(cp949) 깨짐 여부.
- [ ] `OSVersion.Version.Build` 기반 Windows 10/11 cycle 판정(>=22000=11)이 endoflife.date `windows` 사이클과 맞는지.
- [ ] EOL 조회 시 endoflife.date `windows` product의 cycle 표기(예: "11", "10", "10-iot") 정합성.

## 6. Phase 1 이후 Windows 확장 후보 (미구현)
- TPM 2.0 상태(`Get-Tpm`), Credential/Device Guard, HVCI.
- Defender 시그니처 날짜(`(Get-MpComputerStatus).AntivirusSignatureLastUpdated`), Tamper Protection.
- 자동 업데이트 정책, RDP 활성 여부, 리스닝 포트(`Get-NetTCPConnection`).
- 로컬 관리자 계정 열거, 자동 로그인(`AutoAdminLogon` 레지스트리).
