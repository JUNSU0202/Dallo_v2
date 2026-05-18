"""Wave 5-J 리포트 Red/Blue 섹션 단위 테스트.

본 테스트는 ``reports/report_generator.py::ReportGenerator`` 의
``generate_html()`` / ``generate_markdown()`` 가 ``shared.red_blue
.build_red_blue_summary(..., include_attack_paths=True)`` 결과를
**additive only** 로 렌더링한다는 행동 계약을 검증한다.

검증 항목:
- vulnerabilities/patches 가 있을 때만 Red/Blue 섹션이 출력된다.
- HTML / Markdown 모두 red 메트릭, blue 메트릭, comparison/risk reduction,
  attack-path 행이 노출된다.
- vulnerabilities/patches 가 비어 있는 경우 기존 fallback 문구
  (탐지된 취약점이 없습니다 / 생성된 수정안이 없습니다) 가 유지되고,
  의미 없는 zero-only Red/Blue 표는 새로 추가되지 않는다.
- HTML 출력은 사용자 제어 가능 필드 (title / file_path / rule_id /
  explanation) 의 ``<script>`` 등 위험 토큰을 escape 한다.
- Markdown 출력은 사용자 제어 가능 필드 안의 triple backtick (```` ``` ````)
  이 새로운 코드 펜스를 만들지 않도록 안전 치환한다.
- ``shared/schemas.py`` 는 본 wave 에서 한 글자도 바뀌지 않는다.
"""

from __future__ import annotations

import pathlib
import subprocess

import pytest

from reports.report_generator import ReportGenerator


# ---------------------------------------------------------------------------
# fixture 빌더
# ---------------------------------------------------------------------------

def _make_data_with_vuln_and_patch() -> dict:
    """CWE-89 취약점 1건 + 검증 통과 patch 1건 데이터."""
    return {
        "session_id": "sess-w5j-001",
        "repo": "octo/sample",
        "summary": {
            "total": 1,
            "high": 1,
            "medium": 0,
            "low": 0,
            "patches_generated": 1,
            "patches_verified": 1,
        },
        "vulnerabilities": [
            {
                "id": "vuln_001",
                "tool": "bandit",
                "rule_id": "B608",
                "severity": "HIGH",
                "confidence": "HIGH",
                "title": "SQL injection via dynamic query",
                "description": "Concatenated SQL query.",
                "file_path": "app/db.py",
                "line_number": 42,
                "cwe_id": "CWE-89",
                "code_snippet": "query = 'SELECT * FROM users WHERE id=' + user_id",
            }
        ],
        "patches": [
            {
                "vulnerability_id": "vuln_001",
                "fix_type": "secure_refactor",
                "status": "verified",
                "fixed_code": "cursor.execute('SELECT * FROM users WHERE id=%s', (user_id,))",
                "explanation": "Use parameterized query to avoid SQL injection.",
                "security_revalidation": {
                    "passed": True,
                    "safe": True,
                    "removed_count": 1,
                    "introduced_count": 0,
                },
                "syntax_valid": True,
            }
        ],
    }


# ---------------------------------------------------------------------------
# 1. HTML 렌더: Red/Blue 섹션 + 메트릭 + attack-path 행
# ---------------------------------------------------------------------------

def test_html_renders_red_blue_section_heading_and_metrics():
    out = ReportGenerator().generate_html(_make_data_with_vuln_and_patch())

    # 섹션 헤딩 (한국어 라벨).
    assert "Red/Blue 보안 관점" in out
    # 하위 라벨이 존재한다.
    assert "Red Team" in out
    assert "Blue Team" in out
    assert "공격 경로" in out or "공격경로" in out

    # Red 메트릭 (total_findings=1, critical_or_high=1).
    assert "1" in out

    # comparison: risk_reduction_percent=100.0, fixed_count=1.
    assert "100.0" in out

    # attack-path 행: 취약점 정보가 그대로 노출된다.
    assert "vuln_001" in out
    assert "CWE-89" in out


def test_html_red_blue_section_includes_attack_path_row():
    out = ReportGenerator().generate_html(_make_data_with_vuln_and_patch())
    # build_attack_paths 의 status 는 patch defense_outcome 가
    # validated_defense 일 때 'BLOCKED' 를 emit 한다.
    assert "BLOCKED" in out
    # defense 텍스트 (CWE-89 템플릿) 의 핵심 키워드.
    assert "parameterized queries" in out.lower() or "parameterized" in out.lower()


# ---------------------------------------------------------------------------
# 2. Markdown 렌더: Red/Blue 섹션 + 메트릭 + attack-path 행
# ---------------------------------------------------------------------------

def test_markdown_renders_red_blue_section_heading_and_metrics():
    md = ReportGenerator().generate_markdown(_make_data_with_vuln_and_patch())

    assert "## Red/Blue 보안 관점" in md or "## Red/Blue" in md
    assert "Red Team" in md
    assert "Blue Team" in md
    # risk_reduction_percent
    assert "100.0" in md
    # attack-path
    assert "vuln_001" in md
    assert "CWE-89" in md
    assert "BLOCKED" in md


# ---------------------------------------------------------------------------
# 3. 빈/최소 입력 fallback 보존
# ---------------------------------------------------------------------------

def test_html_empty_data_keeps_existing_fallback_and_no_noisy_redblue_rows():
    out = ReportGenerator().generate_html({})
    # 기존 fallback 문구는 그대로 유지.
    assert "탐지된 취약점이 없습니다." in out
    assert "생성된 수정안이 없습니다." in out
    # vulnerabilities/patches 가 비어 있으면 Red/Blue 섹션을 추가하지 않는다
    # — "fake success" 처럼 보이는 zero-only 표는 만들지 않는다.
    assert "Red/Blue 보안 관점" not in out
    assert "BLOCKED" not in out


def test_markdown_empty_data_keeps_existing_fallback_and_no_redblue_section():
    md = ReportGenerator().generate_markdown({})
    assert "_탐지된 취약점이 없습니다._" in md
    assert "_생성된 수정안이 없습니다._" in md
    assert "Red/Blue 보안 관점" not in md
    assert "BLOCKED" not in md


# ---------------------------------------------------------------------------
# 4. HTML escaping for Red/Blue rows
# ---------------------------------------------------------------------------

def test_html_escapes_malicious_user_controlled_fields_in_red_blue_section():
    payload = {
        "summary": {"total": 1, "high": 1, "medium": 0, "low": 0,
                    "patches_generated": 1, "patches_verified": 0},
        "vulnerabilities": [
            {
                "id": "vuln_xss",
                "tool": "bandit",
                "rule_id": "<script>alert('rule')</script>",
                "severity": "HIGH",
                "confidence": "HIGH",
                "title": "<script>alert('title')</script>",
                "description": "x",
                "file_path": "<script>alert('path')</script>.py",
                "line_number": 1,
                "cwe_id": "CWE-89",
                "code_snippet": "x = 1",
            }
        ],
        "patches": [
            {
                "vulnerability_id": "vuln_xss",
                "fix_type": "secure_refactor",
                "status": "generated",
                "fixed_code": "y = 1",
                "explanation": "<script>alert('explain')</script>",
            }
        ],
    }
    out = ReportGenerator().generate_html(payload)

    # Raw <script> 가 그대로 노출되어선 안 된다.
    assert "<script>alert('title')</script>" not in out
    assert "<script>alert('path')</script>" not in out
    assert "<script>alert('rule')</script>" not in out
    # escape 된 형태는 등장해야 한다 (해당 데이터를 어딘가 출력하므로).
    assert "&lt;script&gt;" in out


# ---------------------------------------------------------------------------
# 5. Markdown fence safety
# ---------------------------------------------------------------------------

def test_markdown_red_blue_section_does_not_emit_user_supplied_triple_backticks():
    payload = {
        "summary": {"total": 1, "high": 1, "medium": 0, "low": 0,
                    "patches_generated": 1, "patches_verified": 0},
        "vulnerabilities": [
            {
                "id": "vuln_md",
                "tool": "bandit",
                "rule_id": "```evil",
                "severity": "HIGH",
                "confidence": "HIGH",
                "title": "Title with ``` backticks",
                "description": "desc",
                "file_path": "a/b.py",
                "line_number": 1,
                "cwe_id": "CWE-89",
                "code_snippet": "x = 1",
            }
        ],
        "patches": [
            {
                "vulnerability_id": "vuln_md",
                "fix_type": "secure_refactor",
                "status": "generated",
                "fixed_code": "y = 1",
                "explanation": "Use parameterized queries",
            }
        ],
    }
    md = ReportGenerator().generate_markdown(payload)

    # Red/Blue 섹션은 등장한다.
    redblue_idx = md.find("Red/Blue")
    assert redblue_idx >= 0
    # 섹션의 끝(다음 H2) 까지를 잘라 본다.
    next_section_idx = md.find("\n## ", redblue_idx + 1)
    if next_section_idx < 0:
        next_section_idx = len(md)
    section = md[redblue_idx:next_section_idx]

    # 본 섹션 내에서 사용자 제어 triple backtick 이 fence 형태로
    # 그대로 노출되어선 안 된다.
    assert "```evil" not in section
    assert "Title with ``` backticks" not in section


# ---------------------------------------------------------------------------
# 6. shared/schemas.py 무변경 검증
# ---------------------------------------------------------------------------

def test_shared_schemas_py_unchanged_in_this_wave():
    repo_root = pathlib.Path(__file__).resolve().parent.parent
    try:
        diff = subprocess.run(
            ["git", "diff", "main...HEAD", "--", "shared/schemas.py"],
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        pytest.skip("git unavailable in this environment")
    assert diff.returncode == 0, diff.stderr
    assert diff.stdout.strip() == "", (
        "shared/schemas.py must not change in Wave 5-J:\n" + diff.stdout
    )
