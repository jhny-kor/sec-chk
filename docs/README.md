# KODA 문서

KODA 프로젝트 문서 모음입니다. 설치·운영 절차, 보안 연동 가이드, 리포트 계약,
로드맵을 카테고리별로 정리했습니다. 제품 개요와 CLI 사용법은 저장소 루트의
[README.md](../README.md)를 참고하세요.

## 설치와 배포 (`install/`)

| 문서 | 내용 |
| --- | --- |
| [offline-delivery.md](install/offline-delivery.md) | 폐쇄망 배포 개요 — Docker 전달물 / Linux tarball / Windows 설치본+데이터 zip 비교, 점검 파이프라인, 종료 코드, 빌드 옵션 |
| [macos.md](install/macos.md) | macOS 설치 (App Store 앱 및 스크립트 설치) |
| [linux.md](install/linux.md) | Linux 설치·운영 가이드 (호스트 설치, 대시보드, Docker 전달물) |
| [windows.md](install/windows.md) | Windows 설치본 빌드·설치 및 취약점 데이터 패키지 연결 |
| [vuln-data-refresh.md](install/vuln-data-refresh.md) | Windows 취약점 데이터(`koda-vuln-data-<date>.zip`) 현행화 절차 |
| [usage.md](usage.md) | 공통 Python CLI 사용법 — 설정, 보고서, CI, 자동 교정과 권한 있는 네트워크 점검 |

폐쇄망 Docker 래퍼의 운영 상세는
[platforms/linux/docker/README.md](../platforms/linux/docker/README.md),
Linux 오프라인 배포 계층 설명은
[platforms/linux/README-offline.md](../platforms/linux/README-offline.md)에 있습니다.

## 보안 점검·연동 (`security/`)

| 문서 | 내용 |
| --- | --- |
| [java-sbom-vulnerability-scan.md](security/java-sbom-vulnerability-scan.md) | 폐쇄망 Java(JAR/WAR/EAR) SBOM·취약점 점검 런북 |
| [PRE_COMMIT.md](security/PRE_COMMIT.md) | KODA pre-commit 보안 게이트 |
| [GITHUB_REPOSITORY_SECURITY.md](security/GITHUB_REPOSITORY_SECURITY.md) | GitHub 저장소 보안 설정 체크리스트 |
| [DEPENDENCY_TRACK.md](security/DEPENDENCY_TRACK.md) | Dependency-Track SBOM 업로드 연동 |
| [ZAP_BASELINE.md](security/ZAP_BASELINE.md) | OWASP ZAP baseline DAST 실행 |
| [VEX.md](security/VEX.md) | CycloneDX VEX 취약점 상태 추적 |
| [SLSA_SIGSTORE.md](security/SLSA_SIGSTORE.md) | SLSA·Sigstore 릴리스 출처 증명 |
| [NIST_SSDF_WORKFLOW.md](security/NIST_SSDF_WORKFLOW.md) | NIST SSDF 워크플로 증적 |
| [SECURE_BY_DESIGN.md](security/SECURE_BY_DESIGN.md) | CISA Secure by Design 예방 계획 |

## 기준 프로파일 (`standards/`)

| 문서 | 내용 |
| --- | --- |
| [sw-development-security-49.md](standards/sw-development-security-49.md) | 소프트웨어 개발보안 49개 항목 매핑 |

## 리포트·설계·로드맵

| 문서 | 내용 |
| --- | --- |
| [report-contract.md](report-contract.md) | KODA 리포트 계약 (출력 형식·필드 정의) |
| [security-dashboard-research.md](security-dashboard-research.md) | 대시보드 설계 근거와 구현 한계 |
| [spec-beyond-static-scanner.md](spec-beyond-static-scanner.md) | 정적 스캐너를 넘어서는 구현 명세 |
| [roadmap-ai-augmentation.md](roadmap-ai-augmentation.md) | AI 증강·자동 교정·CI/CD 로드맵 |
| [roadmap-endpoint-security.md](roadmap-endpoint-security.md) | 엔드포인트(호스트) 보안 점검 로드맵 |
