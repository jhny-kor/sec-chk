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

- [한국어 문서 인덱스](../README.md)
