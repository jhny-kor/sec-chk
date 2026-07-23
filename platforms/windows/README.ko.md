# KODA Windows EXE 설치본 빌드

이 폴더는 Windows 직접 배포용 Inno Setup 설치본을 만드는 경로입니다.
실제 `.exe`는 Windows PC에서 PyInstaller와 Inno Setup으로 빌드해야 합니다.

## 결과물과 요구사항

결과물은 `dist\\KODA\\KODA.exe`와 `dist\\Windows\\KODASetup.exe`입니다.
빌드 PC에는 Windows, Python 3.10 이상, Inno Setup 6이 필요합니다. 사용자는
저장소를 복제하지 않고 `KODASetup.exe`만 설치하면 됩니다.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\scripts\build-koda-windows-installer.ps1
```

버전은 `-Version 0.1.1`, Inno Setup 경로는
`-InnoCompilerPath "C:\\Path\\To\\ISCC.exe"`로 지정할 수 있습니다.

Microsoft Store 배포에는 Inno 설치본이 아니라 MSIX 또는 `.msixupload`를
사용해야 합니다.

- [한국어 문서 인덱스](../../docs/README.md)
- [English Windows installer guide](README.md)
