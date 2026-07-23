# KODA Linux 오프라인 배포

Linux x86_64 서버에서 인터넷 연결 없이 KODA를 설치하고 Java 아카이브를
점검하는 절차입니다. Docker 없이 사용자 소유 경로에 설치하는 tarball을
기준으로 하며, Python 3.10 이상이 필요합니다.

## 빌드와 설치

인터넷에 연결된 승인된 빌드 PC에서 패키지를 만든 뒤 결과물만 반입합니다.

```bash
bash platforms/linux/package-offline.sh --refresh
tar -xzf dist/linux/koda-linux-x86_64-<version>.tar.gz
cd koda-linux-x86_64-<version>
bash install.sh
```

설치 스크립트는 번들된 Syft, Grype, Grype DB, NVD/CISA 자료와 Chromium을
사용합니다. 실행 중 자동 다운로드나 외부 통신은 하지 않습니다.

## Java 아카이브 점검

```bash
/home/user0/koda/koda jar-scan \
  --target /deploy/apps \
  --output-dir reports/java-scan \
  --fail-on high --fail-on-kev
```

HTML은 `--language`를 생략하면 한국어로 열리고 `한국어`/`English` 전환
버튼을 표시합니다. `--language ko|en`을 지정하면 HTML과 Markdown이 해당
언어로 고정됩니다. `Final`은 현재 번들 Grype DB 기준으로 취약점이 없는
것을 확인한 최종 조치 후보입니다.

자세한 전달물 비교와 Windows 데이터 패키지는
[폐쇄망 배포 개요](../../docs/install/offline-delivery.md)를 참고하세요.

- [한국어 문서 인덱스](../../docs/README.md)
- [English Linux offline distribution](README-offline.md)
