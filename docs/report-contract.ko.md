# KODA 리포트 계약

플랫폼별 스캐너가 달라도 리포트 소비자는 동일한 필드와 의미를 사용해야
합니다. Linux·Windows·CI·서버는 공통 Python 엔진을 사용하고, macOS 앱은
네이티브 Swift 스캐너를 사용합니다.

## 핵심 원칙

- `id`, `severity`, `category`, `title`, `description`, `recommendation`,
  `locations`는 모든 finding에 유지합니다.
- 심각도는 `critical`, `high`, `medium`, `low`, `info` 중 하나입니다.
- JSON·HTML·Markdown·SARIF·CycloneDX 변환은 원본 finding의 식별자와 경로를
  손실시키지 않아야 합니다.
- 빈 결과는 대상에 위험이 없다는 보장이 아닙니다.

Java 리포트는 라이브러리·설치 버전별로 취약점을 통합하고, `Fixed`와 동일한
Grype DB로 검증한 `Final` 후보를 별도 필드로 제공합니다.

- [한국어 문서 인덱스](README.md)
- [English report contract](report-contract.md)
