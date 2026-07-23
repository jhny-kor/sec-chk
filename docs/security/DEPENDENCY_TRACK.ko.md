# Dependency-Track SBOM 업로드

KODA에서 CycloneDX SBOM을 만든 뒤 Dependency-Track 서버에 업로드합니다.

```bash
python -m security_scanner scan --target . --format cyclonedx --output reports/sbom.cdx.json
python -m security_scanner upload-sbom \
  --server-url https://dependency-track.example.com \
  --api-key-env DEPENDENCY_TRACK_API_KEY \
  --project-name security --project-version main \
  --sbom reports/sbom.cdx.json --auto-create
```

API 키는 명령행에 직접 입력하지 말고 환경변수로 전달하세요.

- [한국어 보안 문서 인덱스](../README.md#보안-점검연동-security)
- [English Dependency-Track guide](DEPENDENCY_TRACK.md)
