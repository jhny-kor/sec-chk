# Software Development Security 49 Profile

This profile maps the 49 implementation-stage software weaknesses from the
Korean Ministry of the Interior and Safety/KISA guide to KODA controls.

Official source: [MOIS Software Development Security Guide (revised 2021-11-30)](https://www.mois.go.kr/frt/bbs/type001/commonSelectBoardArticle.do?bbsId=BBSMSTR_000000000015&nttId=88956)

## Status meanings

| Status | Meaning |
| --- | --- |
| `PASS` | A fully automated mapped rule ran and found no matching pattern |
| `VULNERABLE` | A mapped rule detected a vulnerable pattern |
| `NEEDS_REVIEW` | Manual or partially automated evidence is still required |
| `UNSUPPORTED` | KODA cannot assess the criterion; use external SAST/evidence |
| `NOT_APPLICABLE` | The criterion does not apply to the target technology |
| `NOT_SCANNED` | The required scan category did not run |

Zero findings do not prove compliance. Keep the profile result with the scan
configuration, target scope, and manual evidence that supports each decision.

- [English documentation index](../README.en.md)
- [Korean SW development security 49 profile](sw-development-security-49.md)
