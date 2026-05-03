#!/usr/bin/env python3
"""
GitHub Actions에서 실행되는 PR 코멘트 게시 스크립트

전체 파이프라인 결과(full_result.json)가 있으면 LLM 패치까지 포함,
없으면 Bandit 결과만 코멘트로 게시합니다.

환경 변수:
  GITHUB_TOKEN: GitHub 토큰 (자동 제공)
  PR_NUMBER: PR 번호
  REPO: owner/repo 형식
"""

import os
import sys
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from integrations.github_pr_comment_adapter import post_or_update_pr_comment


def load_json(path: str) -> dict:
    if not os.path.exists(path):
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def format_comment(bandit_report: dict, full_result: dict) -> str:
    """분석 결과를 마크다운 PR 코멘트로 변환"""
    lines = []
    lines.append("## 🔍 Dallo 보안 분석 결과")
    lines.append("")

    # full_result가 있으면 사용, 없으면 bandit만
    if full_result and full_result.get("vulnerabilities"):
        return _format_full_comment(full_result)

    # bandit only
    results = bandit_report.get("results", [])
    totals = bandit_report.get("metrics", {}).get("_totals", {})

    if not results:
        lines.append("> ✅ **보안 취약점이 발견되지 않았습니다.** 깔끔한 코드입니다!")
        lines.append("")
        lines.append("---")
        lines.append("*🤖 Dallo DevSecOps — Bandit 정적 분석*")
        return "\n".join(lines)

    high = totals.get("SEVERITY.HIGH", 0)
    medium = totals.get("SEVERITY.MEDIUM", 0)
    low = totals.get("SEVERITY.LOW", 0)

    lines.append(_summary_table(len(results), high, medium, low))
    lines.append(_bandit_details(results))
    lines.append("---")
    lines.append("*🤖 Dallo DevSecOps — Bandit 정적 분석*")

    return "\n".join(lines)


def _format_full_comment(full: dict) -> str:
    """전체 파이프라인 결과 (LLM 패치 포함) 코멘트"""
    lines = []
    lines.append("## 🔍 Dallo 보안 분석 결과")
    lines.append("")

    summary = full.get("summary", {})
    vulns = full.get("vulnerabilities", [])
    patches = full.get("patches", [])
    duration = full.get("duration_seconds", 0)

    total = summary.get("total", len(vulns))
    high = summary.get("high", 0)
    medium = summary.get("medium", 0)
    low = summary.get("low", 0)
    generated = summary.get("patches_generated", 0)
    verified = summary.get("patches_verified", 0)

    if total == 0:
        lines.append("> ✅ **보안 취약점이 발견되지 않았습니다.**")
        lines.append("")
        lines.append("---")
        lines.append("*🤖 Dallo DevSecOps*")
        return "\n".join(lines)

    # 요약 테이블
    lines.append("### 📊 요약")
    lines.append("")
    lines.append("| 항목 | 결과 |")
    lines.append("|------|------|")
    lines.append(f"| 🔴 HIGH | **{high}** |")
    lines.append(f"| 🟡 MEDIUM | **{medium}** |")
    lines.append(f"| 🔵 LOW | **{low}** |")
    lines.append(f"| **전체 취약점** | **{total}** |")
    lines.append(f"| 🤖 AI 수정안 생성 | **{generated}** |")
    lines.append(f"| ✅ 검증 통과 | **{verified}** |")
    if duration:
        lines.append(f"| ⏱️ 분석 시간 | **{duration:.1f}초** |")
    lines.append("")

    # 패치 매핑
    patch_map = {}
    for p in patches:
        patch_map[p.get("vulnerability_id", "")] = p

    # 취약점 상세
    emoji_map = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🔵"}
    severity_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    sorted_vulns = sorted(vulns, key=lambda v: severity_order.get(v.get("severity", ""), 99))

    lines.append("### 🛡️ 발견된 취약점")
    lines.append("")

    for v in sorted_vulns:
        severity = v.get("severity", "")
        emoji = emoji_map.get(severity, "⚪")
        rule_id = v.get("rule_id", "")
        title = v.get("title", "")
        file_path = v.get("file_path", "")
        line_num = v.get("line_number", 0)
        desc = v.get("description", "")
        cwe = v.get("cwe_id", "")
        code = v.get("code_snippet", "")
        vuln_id = v.get("id", "")

        lines.append("<details>")
        lines.append(f"<summary>{emoji} <b>[{rule_id}] {title}</b> — {file_path}:{line_num}</summary>")
        lines.append("")
        lines.append(f"**설명:** {desc}")
        if cwe:
            lines.append(f"**CWE:** {cwe}")
        lines.append("")

        if code:
            lines.append("**취약 코드:**")
            lines.append("```python")
            lines.append(code.strip())
            lines.append("```")
            lines.append("")

        # AI 수정안
        patch = patch_map.get(vuln_id)
        if patch and patch.get("fixed_code"):
            status = patch.get("status", "")
            is_verified = "VERIFIED" in status.upper() if status else False
            badge = "✅ 검증 통과" if is_verified else "🤖 AI 생성"

            lines.append(f"**{badge} — AI 수정 제안:**")
            if patch.get("explanation"):
                # 설명에서 첫 200자만
                exp = patch["explanation"][:300]
                lines.append(f"> {exp}")
                lines.append("")
            lines.append("```python")
            lines.append(patch["fixed_code"])
            lines.append("```")
            lines.append("")
        elif patch:
            lines.append(f"**❌ AI 수정안 생성 실패**")
            lines.append("")

        lines.append("</details>")
        lines.append("")

    lines.append("---")
    lines.append("*🤖 Dallo DevSecOps — Bandit + Gemini AI 분석*")

    return "\n".join(lines)


def _summary_table(total, high, medium, low):
    return f"""### 📊 요약

| 심각도 | 건수 |
|--------|------|
| 🔴 HIGH | **{high}** |
| 🟡 MEDIUM | **{medium}** |
| 🔵 LOW | **{low}** |
| **전체** | **{total}** |
"""


def _bandit_details(results):
    emoji_map = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🔵"}
    severity_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    sorted_results = sorted(results, key=lambda x: severity_order.get(x.get("issue_severity", ""), 99))

    lines = ["### 🛡️ 발견된 취약점", ""]
    for item in sorted_results:
        severity = item.get("issue_severity", "")
        emoji = emoji_map.get(severity, "⚪")
        test_id = item.get("test_id", "")
        test_name = item.get("test_name", "")
        filename = item.get("filename", "")
        line_num = item.get("line_number", 0)
        issue_text = item.get("issue_text", "")
        code = item.get("code", "").strip()

        cwe = item.get("issue_cwe", {})
        cwe_str = f"CWE-{cwe['id']}" if isinstance(cwe, dict) and cwe.get("id") else ""

        lines.append("<details>")
        lines.append(f"<summary>{emoji} <b>[{test_id}] {test_name}</b> — {filename}:{line_num}</summary>")
        lines.append("")
        lines.append(f"**설명:** {issue_text}")
        if cwe_str:
            lines.append(f"**CWE:** {cwe_str}")
        lines.append("")
        if code:
            lines.append("```python")
            lines.append(code)
            lines.append("```")
            lines.append("")
        lines.append("</details>")
        lines.append("")

    return "\n".join(lines)


def post_comment(token: str, repo: str, pr_number: int, body: str) -> bool:
    """GitHub API로 PR 코멘트 게시 (기존 Dallo 코멘트는 업데이트).

    HTTP 호출 책임은 ``integrations.github_pr_comment_adapter`` 어댑터가
    담당한다. 본 함수는 어댑터 결과를 한국어 stdout / bool 로 변환한다.
    """
    result = post_or_update_pr_comment(
        token=token,
        repo=repo,
        pr_number=pr_number,
        body=body,
    )
    print(result["message"])
    return result["status"] != "failed"


def main():
    token = os.environ.get("GITHUB_TOKEN", "")
    pr_number = os.environ.get("PR_NUMBER", "")
    repo = os.environ.get("REPO", "")

    if not all([token, pr_number, repo]):
        print("[!] 환경 변수가 설정되지 않았습니다 (GITHUB_TOKEN, PR_NUMBER, REPO)")
        sys.exit(1)

    pr_number = int(pr_number)

    # 전체 파이프라인 결과 > bandit 결과 순으로 시도
    full_result = load_json("reports/full_result.json")
    bandit_report = load_json("reports/bandit_report.json")

    comment_body = format_comment(bandit_report, full_result)
    success = post_comment(token, repo, pr_number, comment_body)

    if not success:
        sys.exit(1)

    total = len(full_result.get("vulnerabilities", [])) or len(bandit_report.get("results", []))
    print(f"[*] 총 {total}건의 취약점이 PR #{pr_number}에 보고되었습니다.")


if __name__ == "__main__":
    main()
