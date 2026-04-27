"""
PR 코멘트 포맷 골든/회귀 테스트 (tests/test_pr_formatter_golden.py)

GitHub 네트워크 호출 없이 결정론적인 샘플 데이터로 다음 두 코멘트
포매터의 출력 형식이 보존되는지 검증한다:

1. integrations/pr_commenter.PRCommenter — Bandit AnalysisResult 기반
2. scripts/post_pr_comment.format_comment — bandit_report.json + full_result.json

큰 리팩터링 전에 PR 코멘트 외관·구조의 회귀를 잡기 위한 안전망이다.
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyzer.bandit_runner import AnalysisResult, Vulnerability
from analyzer.context_extractor import CodeContext
from integrations.pr_commenter import PRCommenter
from scripts.post_pr_comment import format_comment


def _make_vuln(severity="HIGH", rule_id="B608", line=10, file_path="src/app.py", title=None, code="", cwe="CWE-89"):
    return Vulnerability(
        tool="bandit",
        rule_id=rule_id,
        severity=severity,
        confidence="HIGH",
        title=title or f"{rule_id} issue",
        description=f"{rule_id} 설명",
        file_path=file_path,
        line_number=line,
        code_snippet=code,
        cwe_id=cwe,
        more_info="https://bandit.readthedocs.io/en/latest/",
    )


def _make_result(vulns, error=None):
    high = sum(1 for v in vulns if v.severity == "HIGH")
    medium = sum(1 for v in vulns if v.severity == "MEDIUM")
    low = sum(1 for v in vulns if v.severity == "LOW")
    return AnalysisResult(
        tool="bandit",
        target_path="test_targets/sample.py",
        total_issues=len(vulns),
        high_count=high,
        medium_count=medium,
        low_count=low,
        vulnerabilities=vulns,
        error=error,
    )


# ============================================================
# integrations/pr_commenter.PRCommenter
# ============================================================


class TestPRCommenterSummary:
    def test_no_vulnerabilities_clean_message(self):
        result = _make_result([])
        out = PRCommenter().format_summary_comment(result)
        assert "## 🔍 Dallo 보안 분석 결과" in out
        assert "✅" in out and "취약점이 발견되지 않았습니다" in out
        # 깔끔한 케이스에서는 요약 테이블/취약점 섹션이 없어야 함
        assert "### 📊 요약" not in out
        assert "### 🛡️ 발견된 취약점" not in out

    def test_error_short_circuits(self):
        result = _make_result([_make_vuln()], error="bandit not installed")
        out = PRCommenter().format_summary_comment(result)
        assert "⚠️" in out
        assert "bandit not installed" in out
        # 에러 시에는 취약점 섹션을 그리지 않음
        assert "### 📊 요약" not in out

    def test_summary_table_counts_match_result(self):
        vulns = [
            _make_vuln(severity="HIGH", rule_id="B608", line=10),
            _make_vuln(severity="HIGH", rule_id="B602", line=20),
            _make_vuln(severity="MEDIUM", rule_id="B303", line=30),
            _make_vuln(severity="LOW", rule_id="B101", line=40),
        ]
        out = PRCommenter().format_summary_comment(_make_result(vulns))
        # 요약 테이블 헤더와 카운트
        assert "| 심각도 | 건수 |" in out
        assert "🔴 높음 (High) | **2**" in out
        assert "🟡 중간 (Medium) | **1**" in out
        assert "🔵 낮음 (Low) | **1**" in out
        assert "**전체** | **4**" in out

    def test_each_vulnerability_in_details_block(self):
        vulns = [
            _make_vuln(severity="HIGH", rule_id="B608", line=12, code="cursor.execute('SELECT ...')"),
            _make_vuln(severity="MEDIUM", rule_id="B303", line=42),
        ]
        out = PRCommenter().format_summary_comment(_make_result(vulns))
        # 각 취약점이 <details> 블록으로 감싸져 있어야 함
        assert out.count("<details>") == 2
        assert out.count("</details>") == 2
        # rule_id, file:line, CWE, 더 자세히 링크가 모두 포함되어야 함
        assert "[B608]" in out and "[B303]" in out
        assert "src/app.py:12" in out
        assert "src/app.py:42" in out
        assert "CWE-89" in out
        assert "https://bandit.readthedocs.io/en/latest/" in out
        # 코드 스니펫이 있으면 코드 블록으로 감싸야 함
        assert "```python" in out
        assert "cursor.execute('SELECT ...')" in out

    def test_unknown_severity_falls_back_to_default_emoji(self):
        # 매핑 테이블에 없는 심각도("CRITICAL")는 ⚪로 폴백
        vulns = [_make_vuln(severity="CRITICAL", rule_id="X999")]
        out = PRCommenter().format_summary_comment(_make_result(vulns))
        # 요약 테이블 카운트는 0/0/0이 되지만 상세 섹션에는 등장
        assert "⚪" in out
        assert "[X999]" in out

    def test_context_block_only_when_matching_key(self):
        v1 = _make_vuln(severity="HIGH", rule_id="B608", line=10, file_path="src/app.py")
        v2 = _make_vuln(severity="HIGH", rule_id="B602", line=20, file_path="src/app.py")
        result = _make_result([v1, v2])
        ctx = CodeContext(
            vulnerability=v1,
            full_function="def query():\n    cursor.execute('SELECT ...')\n",
            file_path="src/app.py",
            start_line=8,
            end_line=12,
        )
        out = PRCommenter(include_code_context=True).format_summary_comment(
            result, contexts=[ctx]
        )
        assert "**함수 전체:**" in out
        assert "def query():" in out
        # v2에 대한 함수 블록은 없어야 함 (context_map miss)
        assert out.count("**함수 전체:**") == 1

    def test_include_code_context_false_skips_function(self):
        v1 = _make_vuln(severity="HIGH", rule_id="B608", line=10)
        ctx = CodeContext(
            vulnerability=v1,
            full_function="def query():\n    pass\n",
            file_path="src/app.py",
        )
        out = PRCommenter(include_code_context=False).format_summary_comment(
            _make_result([v1]), contexts=[ctx]
        )
        assert "**함수 전체:**" not in out

    def test_llm_suggestion_rendered_with_explanation_and_code(self):
        v1 = _make_vuln(severity="HIGH", rule_id="B608", line=10)
        suggestions = [{
            "explanation": "쿼리에 파라미터 바인딩을 사용하세요.",
            "fixed_code": "cursor.execute('SELECT * FROM t WHERE id=%s', (uid,))",
        }]
        out = PRCommenter().format_summary_comment(
            _make_result([v1]), llm_suggestions=suggestions
        )
        assert "🤖 AI 수정 제안" in out
        assert "쿼리에 파라미터 바인딩을 사용하세요." in out
        assert "cursor.execute('SELECT * FROM t WHERE id=%s'," in out

    def test_inline_comment_format(self):
        v1 = _make_vuln(severity="HIGH", rule_id="B608", line=10)
        out = PRCommenter().format_inline_comment(v1)
        assert "🔴" in out
        assert "[B608]" in out
        assert "심각도: 높음" in out
        assert "CWE-89" in out
        assert "상세 정보" in out


# ============================================================
# scripts/post_pr_comment.format_comment
# ============================================================


class TestPostPRCommentBanditOnly:
    def test_clean_run_uses_clean_template(self):
        bandit = {"results": [], "metrics": {"_totals": {}}}
        out = format_comment(bandit, {})
        assert "## 🔍 Dallo 보안 분석 결과" in out
        assert "✅" in out and "취약점이 발견되지 않았습니다" in out
        assert "Bandit 정적 분석" in out
        # 깨끗하면 요약 테이블 없이 끝나야 함
        assert "### 📊 요약" not in out

    def test_bandit_table_uses_severity_totals(self):
        bandit = {
            "results": [
                {"issue_severity": "HIGH", "test_id": "B608", "test_name": "sql",
                 "filename": "a.py", "line_number": 1, "issue_text": "x", "code": "q='..'"},
                {"issue_severity": "LOW", "test_id": "B101", "test_name": "assert",
                 "filename": "b.py", "line_number": 2, "issue_text": "y", "code": ""},
            ],
            "metrics": {"_totals": {
                "SEVERITY.HIGH": 1, "SEVERITY.MEDIUM": 0, "SEVERITY.LOW": 1
            }},
        }
        out = format_comment(bandit, {})
        assert "| 🔴 HIGH | **1** |" in out
        assert "| 🟡 MEDIUM | **0** |" in out
        assert "| 🔵 LOW | **1** |" in out
        # bandit 모드 표식
        assert "Bandit 정적 분석" in out

    def test_bandit_results_sorted_by_severity_high_first(self):
        # LOW가 먼저 와도 출력에선 HIGH가 먼저 와야 함
        bandit = {
            "results": [
                {"issue_severity": "LOW", "test_id": "B101", "test_name": "assert",
                 "filename": "b.py", "line_number": 2, "issue_text": "low",
                 "code": "", "issue_cwe": {"id": "703"}},
                {"issue_severity": "HIGH", "test_id": "B608", "test_name": "sql",
                 "filename": "a.py", "line_number": 1, "issue_text": "high",
                 "code": "q='..'", "issue_cwe": {"id": "89"}},
            ],
            "metrics": {"_totals": {"SEVERITY.HIGH": 1, "SEVERITY.MEDIUM": 0, "SEVERITY.LOW": 1}},
        }
        out = format_comment(bandit, {})
        idx_high = out.index("[B608]")
        idx_low = out.index("[B101]")
        assert idx_high < idx_low
        # CWE는 "CWE-{id}" 형태로 변환되어 노출
        assert "CWE-89" in out
        assert "CWE-703" in out

    def test_bandit_unknown_severity_uses_white_emoji(self):
        bandit = {
            "results": [
                {"issue_severity": "WEIRD", "test_id": "BX", "test_name": "n",
                 "filename": "a.py", "line_number": 3, "issue_text": "z", "code": ""},
            ],
            "metrics": {"_totals": {}},
        }
        out = format_comment(bandit, {})
        assert "⚪" in out
        assert "[BX]" in out


class TestPostPRCommentFullResult:
    def _full(self, vulns=None, patches=None, summary=None, duration=1.5):
        return {
            "summary": summary or {},
            "vulnerabilities": vulns or [],
            "patches": patches or [],
            "duration_seconds": duration,
        }

    def test_full_result_takes_precedence_over_bandit(self):
        # full_result.vulnerabilities가 있으면 bandit 결과는 무시
        bandit = {"results": [{"issue_severity": "HIGH", "test_id": "B999",
                                "test_name": "x", "filename": "z.py",
                                "line_number": 1, "issue_text": "ignored", "code": ""}]}
        full = self._full(
            vulns=[{
                "severity": "HIGH", "rule_id": "B608", "title": "SQL",
                "file_path": "src/app.py", "line_number": 12,
                "description": "desc", "cwe_id": "CWE-89", "id": "v1",
                "code_snippet": "x = 1",
            }],
            summary={"total": 1, "high": 1, "medium": 0, "low": 0,
                     "patches_generated": 0, "patches_verified": 0},
        )
        out = format_comment(bandit, full)
        assert "[B608]" in out
        assert "[B999]" not in out
        assert "Bandit + Gemini AI 분석" in out

    def test_full_result_table_includes_patch_metrics_and_duration(self):
        full = self._full(
            vulns=[{"severity": "HIGH", "rule_id": "B608", "title": "SQL",
                    "file_path": "a.py", "line_number": 1, "description": "d",
                    "id": "v1", "code_snippet": ""}],
            summary={"total": 1, "high": 1, "medium": 0, "low": 0,
                     "patches_generated": 1, "patches_verified": 1},
            duration=12.34,
        )
        out = format_comment({}, full)
        assert "🤖 AI 수정안 생성 | **1**" in out
        assert "✅ 검증 통과 | **1**" in out
        assert "12.3초" in out

    def test_full_result_zero_total_clean_short_circuit(self):
        full = self._full(
            vulns=[],
            summary={"total": 0, "high": 0, "medium": 0, "low": 0,
                     "patches_generated": 0, "patches_verified": 0},
        )
        out = format_comment({}, full)
        assert "✅" in out and "취약점이 발견되지 않았습니다" in out
        assert "### 📊 요약" not in out

    def test_full_result_vulns_sorted_high_medium_low(self):
        full = self._full(
            vulns=[
                {"severity": "LOW", "rule_id": "B-LOW", "title": "L",
                 "file_path": "a.py", "line_number": 1, "description": "d",
                 "id": "vL", "code_snippet": ""},
                {"severity": "HIGH", "rule_id": "B-HIGH", "title": "H",
                 "file_path": "a.py", "line_number": 2, "description": "d",
                 "id": "vH", "code_snippet": ""},
                {"severity": "MEDIUM", "rule_id": "B-MED", "title": "M",
                 "file_path": "a.py", "line_number": 3, "description": "d",
                 "id": "vM", "code_snippet": ""},
            ],
            summary={"total": 3, "high": 1, "medium": 1, "low": 1,
                     "patches_generated": 0, "patches_verified": 0},
        )
        out = format_comment({}, full)
        idx_h = out.index("[B-HIGH]")
        idx_m = out.index("[B-MED]")
        idx_l = out.index("[B-LOW]")
        assert idx_h < idx_m < idx_l

    def test_full_result_verified_patch_shows_verified_badge(self):
        full = self._full(
            vulns=[{"severity": "HIGH", "rule_id": "B608", "title": "SQL",
                    "file_path": "a.py", "line_number": 1, "description": "d",
                    "id": "v1", "code_snippet": ""}],
            patches=[{
                "vulnerability_id": "v1",
                "fixed_code": "safe = True",
                "explanation": "패치 설명",
                "status": "PatchStatus.VERIFIED",
            }],
            summary={"total": 1, "high": 1, "medium": 0, "low": 0,
                     "patches_generated": 1, "patches_verified": 1},
        )
        out = format_comment({}, full)
        assert "✅ 검증 통과 — AI 수정 제안" in out
        assert "패치 설명" in out
        assert "safe = True" in out

    def test_full_result_unverified_patch_shows_generated_badge(self):
        full = self._full(
            vulns=[{"severity": "HIGH", "rule_id": "B608", "title": "SQL",
                    "file_path": "a.py", "line_number": 1, "description": "d",
                    "id": "v1", "code_snippet": ""}],
            patches=[{
                "vulnerability_id": "v1",
                "fixed_code": "tweak()",
                "explanation": "검증되지 않음",
                "status": "PatchStatus.GENERATED",
            }],
            summary={"total": 1, "high": 1, "medium": 0, "low": 0,
                     "patches_generated": 1, "patches_verified": 0},
        )
        out = format_comment({}, full)
        assert "🤖 AI 생성 — AI 수정 제안" in out

    def test_full_result_failed_patch_shows_failure_block(self):
        # patch는 있지만 fixed_code가 없는 경우 → 실패 메시지
        full = self._full(
            vulns=[{"severity": "HIGH", "rule_id": "B608", "title": "SQL",
                    "file_path": "a.py", "line_number": 1, "description": "d",
                    "id": "v1", "code_snippet": ""}],
            patches=[{"vulnerability_id": "v1", "fixed_code": "",
                      "status": "PatchStatus.FAILED"}],
            summary={"total": 1, "high": 1, "medium": 0, "low": 0,
                     "patches_generated": 0, "patches_verified": 0},
        )
        out = format_comment({}, full)
        assert "❌ AI 수정안 생성 실패" in out

    def test_full_result_long_explanation_truncated_to_300(self):
        long_text = "가" * 500
        full = self._full(
            vulns=[{"severity": "HIGH", "rule_id": "B608", "title": "SQL",
                    "file_path": "a.py", "line_number": 1, "description": "d",
                    "id": "v1", "code_snippet": ""}],
            patches=[{"vulnerability_id": "v1", "fixed_code": "x=1",
                      "explanation": long_text,
                      "status": "PatchStatus.VERIFIED"}],
            summary={"total": 1, "high": 1, "medium": 0, "low": 0,
                     "patches_generated": 1, "patches_verified": 1},
        )
        out = format_comment({}, full)
        # 잘려서 300자만 들어가야 함 ("가" * 500 → "가" * 300 등장, 그 이상은 X)
        assert "가" * 300 in out
        assert "가" * 301 not in out
