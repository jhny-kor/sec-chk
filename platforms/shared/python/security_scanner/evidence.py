from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


@dataclass(frozen=True)
class EvidenceItem:
    standard: str
    control: str
    question_ko: str
    question_en: str
    evidence_hint_ko: str
    evidence_hint_en: str


EVIDENCE_ITEMS = (
    EvidenceItem("OWASP ASVS", "V1 Architecture", "보안 아키텍처와 신뢰 경계가 문서화되어 있나요?", "Are security architecture and trust boundaries documented?", "아키텍처 다이어그램, 데이터 흐름도, 위협 모델", "Architecture diagrams, data-flow diagrams, threat models"),
    EvidenceItem("OWASP ASVS", "V2 Authentication", "인증 정책, MFA, 계정 복구 흐름을 검토했나요?", "Have authentication, MFA, and account recovery flows been reviewed?", "인증 설계 문서, 테스트 증적, 정책 화면", "Auth design notes, test evidence, policy screenshots"),
    EvidenceItem("OWASP WSTG", "Runtime Testing", "권한 있는 URL에 대해 동적 점검 또는 침투테스트를 수행했나요?", "Has dynamic testing or penetration testing been performed against an authorized URL?", "ZAP/Burp 리포트, 승인 기록, 점검 범위", "ZAP/Burp reports, authorization record, scope"),
    EvidenceItem("ISMS-P", "Policy & Operation", "개발보안 정책, 담당자, 예외 승인 절차가 운영 중인가요?", "Are secure-development policy, owners, and exception approval processes operating?", "정책 문서, R&R, 승인 티켓", "Policy docs, R&R, approval tickets"),
    EvidenceItem("NIST SSDF", "Prepare the Organization", "보안 요구사항과 개발자 보안 책임이 정의되어 있나요?", "Are security requirements and developer responsibilities defined?", "보안 요구사항 표준, 교육 기록, SDLC 절차", "Security requirements, training records, SDLC procedures"),
    EvidenceItem("NIST SSDF", "Protect Software", "소스/빌드/릴리스 산출물 보호 통제가 있나요?", "Are source, build, and release artifacts protected?", "브랜치 보호, 서명, provenance, 접근권한", "Branch protection, signing, provenance, access controls"),
    EvidenceItem("OWASP SAMM", "Governance", "보안 활동의 성숙도와 개선 계획을 추적하고 있나요?", "Is security maturity and improvement planning tracked?", "SAMM 평가표, 로드맵, 위험 수용 기록", "SAMM scorecards, roadmap, risk acceptance records"),
    EvidenceItem("SLSA/Sigstore", "Release Provenance", "릴리스 산출물에 서명과 출처 증명을 붙이나요?", "Are release artifacts signed and accompanied by provenance?", "cosign 서명, SLSA provenance, checksum", "cosign signatures, SLSA provenance, checksums"),
)


def render_evidence_checklist(*, project_name: str, language: str = "ko") -> str:
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    title = "KODA 수동 증적 체크리스트" if language == "ko" else "KODA Manual Evidence Checklist"
    lines = [
        f"# {title}",
        "",
        f"- Project: {project_name}",
        f"- Generated: {now}",
        "",
    ]
    for item in EVIDENCE_ITEMS:
        question = item.question_ko if language == "ko" else item.question_en
        hint = item.evidence_hint_ko if language == "ko" else item.evidence_hint_en
        lines.extend(
            [
                f"## {item.standard} - {item.control}",
                "",
                f"- [ ] {question}",
                f"- Evidence: {hint}",
                "- Owner:",
                "- Link/File:",
                "- Review date:",
                "- Notes:",
                "",
            ]
        )
    return "\n".join(lines)


def render_evidence_checklist_json(*, project_name: str) -> str:
    payload = {
        "project": project_name,
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "items": [item.__dict__ for item in EVIDENCE_ITEMS],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def write_evidence_checklist(path: Path, *, project_name: str, language: str = "ko", json_format: bool = False) -> None:
    content = render_evidence_checklist_json(project_name=project_name) if json_format else render_evidence_checklist(project_name=project_name, language=language)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
