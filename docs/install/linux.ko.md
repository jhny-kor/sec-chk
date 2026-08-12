# KODA Linux 설치·운영

Linux는 `platforms/shared/python/`의 공통 엔진을 사용하며 사용자 소유 경로에
설치할 수 있습니다. 폐쇄망에서는 Syft·Grype·로컬 DB·NVD·CISA KEV 자료를
승인된 절차로 반입합니다.

```bash
export PYTHONPATH=/opt/koda/platforms/shared/python
python3 -m security_scanner jar-scan \
  --target /deploy/apps --target /deploy/worker-apps --output-dir reports/java-scan \
  --syft-bin /opt/koda/tools/syft --grype-bin /opt/koda/tools/grype \
  --nvd-data /opt/koda/vuln-data/nvd \
  --cisa-kev /opt/koda/vuln-data/known_exploited_vulnerabilities.json
```

JAR 보고서는 현재 HTML과 Markdown 모두 한국어로 생성되며 `--language`는
`ko`만 지원합니다.
`--target`은 반복 지정할 수 있으며, 여러 폴더의 결과를 하나의 라이브러리
메인/상세 리포트와 SBOM으로 통합합니다.

## 인증 Linux 포털

Linux 서버 화면은 KODA와 KODA SBOM Tracker를 묶은 폐쇄망 통합본으로 설치합니다.
동일한 HTTPS 오리진에서 Tracker가 계정과 세션을 관리하고 KODA는 별도의 프로젝트
역할·화면 권한을 적용합니다. 한쪽에서 로그아웃하면 중앙 세션이 폐기되어 두
사이트에서 모두 다시 로그인해야 합니다.

```text
https://<서버>/          # KODA SBOM Tracker
https://<서버>/koda/     # KODA
```

KODA의 보안·품질 점검 규칙은 시스템 관리자만 바꾸고, 일반 사용자는 프로젝트에서
검사 기준과 기준 범위만 선택합니다. 신규 Tracker 계정은 KODA에 처음 접근할 때
`pending`으로 등록되며 KODA 관리자의 승인과 프로젝트 역할 배정이 필요합니다.
로그인 화면의 LDAP 선택지는 현재 연결되지 않아 선택하면 `501`로 실패합니다.

통합 압축파일 생성·검증·설치와 최초 관리자 지정은
[KODA + KODA SBOM Tracker 폐쇄망 통합본](../../platforms/linux/suite/README.ko.md)을
따릅니다. KODA 컨테이너의 8765 포트는 직접 공개하지 않습니다.

- [한국어 문서 인덱스](../README.md)
