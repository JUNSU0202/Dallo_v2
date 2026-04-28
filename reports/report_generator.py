"""분석 리포트 생성기 (reports/report_generator.py).

정적 분석 결과 dict (shared.schemas.AnalysisSession.to_dict() 셰이프)를
HTML / Markdown 으로 렌더링한다. 외부 네트워크/LLM 호출 없이 순수
Python + 표준 라이브러리만 사용한다.

api/routers/report.py 와 api/server.py 가 lazy import 로 사용한다.

지원 입력
---------
data: dict — 최상위 키는 일부만 있어도 동작한다 (방어적 .get).
    - session_id, repo, pr_number, commit_sha, branch
    - summary: {total, high, medium, low, patches_generated, patches_verified}
    - vulnerabilities: list[VulnerabilityReport.to_dict()]
    - patches: list[PatchSuggestion.to_dict()]
    - started_at, completed_at, duration_seconds
deps_data: Optional[dict] — DependencyScanner 결과({"results": [...]}).

공개 API
--------
- ReportGenerator().generate_html(data, deps_data) -> str
- ReportGenerator().generate_markdown(data, deps_data) -> str
- ReportGenerator().save_report(data, output_dir, fmt, include_deps)
    fmt ∈ {"html", "md", "both"}; 반환: {"html": path, "md": path} (선택된 키만).
"""

from __future__ import annotations

import html
import os
from datetime import datetime
from typing import Any, Optional


def _g(d: Optional[dict], key: str, default: Any = "") -> Any:
    """None-safe .get."""
    if not isinstance(d, dict):
        return default
    val = d.get(key, default)
    return default if val is None else val


def _summary(data: dict) -> dict:
    s = _g(data, "summary", {}) or {}
    return {
        "total": int(_g(s, "total", 0) or 0),
        "high": int(_g(s, "high", 0) or 0),
        "medium": int(_g(s, "medium", 0) or 0),
        "low": int(_g(s, "low", 0) or 0),
        "patches_generated": int(_g(s, "patches_generated", 0) or 0),
        "patches_verified": int(_g(s, "patches_verified", 0) or 0),
    }


def _cwe_link(cwe_id: Optional[str]) -> str:
    """CWE-89 -> https://cwe.mitre.org/data/definitions/89.html"""
    if not cwe_id:
        return ""
    raw = str(cwe_id).upper().replace("CWE-", "").strip()
    if not raw.isdigit():
        return ""
    return f"https://cwe.mitre.org/data/definitions/{raw}.html"


class ReportGenerator:
    """정적 분석 결과 → HTML/Markdown 리포트.

    구현 메모:
      - 입력 dict 가 비어 있어도 예외를 던지지 않는다.
      - HTML 출력은 사용자 입력(코드/설명/파일명)을 모두 escape 한다.
      - Markdown 출력은 코드 블록 안에 그대로 노출하되,
        백틱(`) 만 안전 치환한다 (블록이 깨지지 않도록).
    """

    # ------------------------------------------------------------
    # 공개 API
    # ------------------------------------------------------------

    def generate_html(self, data: dict, deps_data: Optional[dict] = None) -> str:
        data = data or {}
        s = _summary(data)
        title = "Dallo 보안 분석 리포트"
        session_id = html.escape(str(_g(data, "session_id", "(미상)")))
        repo = html.escape(str(_g(data, "repo", "")))
        pr_number = _g(data, "pr_number", "")
        commit_sha = html.escape(str(_g(data, "commit_sha", "")))
        branch = html.escape(str(_g(data, "branch", "")))
        generated_at = datetime.now().isoformat(timespec="seconds")

        vuln_rows = "".join(
            self._html_vuln_row(v) for v in (_g(data, "vulnerabilities", []) or [])
        )
        patch_rows = "".join(
            self._html_patch_row(p) for p in (_g(data, "patches", []) or [])
        )
        deps_block = self._html_deps_block(deps_data)

        return f"""<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="utf-8">
<title>{html.escape(title)}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
         max-width: 960px; margin: 24px auto; padding: 0 16px; color: #222; }}
  h1, h2 {{ border-bottom: 1px solid #eee; padding-bottom: 4px; }}
  table {{ border-collapse: collapse; width: 100%; margin: 12px 0; }}
  th, td {{ border: 1px solid #ddd; padding: 6px 8px; text-align: left;
           vertical-align: top; font-size: 14px; }}
  th {{ background: #f6f8fa; }}
  .sev-HIGH {{ color: #b00020; font-weight: 600; }}
  .sev-MEDIUM {{ color: #b56a00; font-weight: 600; }}
  .sev-LOW {{ color: #3a7a3a; font-weight: 600; }}
  pre {{ background: #f6f8fa; padding: 8px; border-radius: 4px; overflow-x: auto;
        white-space: pre-wrap; word-break: break-word; font-size: 13px; }}
  .muted {{ color: #666; font-size: 12px; }}
  .summary-grid {{ display: grid; grid-template-columns: repeat(6, 1fr);
                   gap: 8px; margin: 12px 0; }}
  .summary-grid div {{ background: #f6f8fa; padding: 8px; border-radius: 4px;
                       text-align: center; }}
  .summary-grid strong {{ display: block; font-size: 18px; }}
</style>
</head>
<body>
<h1>{html.escape(title)}</h1>
<p class="muted">
  세션: <code>{session_id}</code>
  · 레포: <code>{repo or "-"}</code>
  · PR: <code>{html.escape(str(pr_number)) if pr_number != "" else "-"}</code>
  · 브랜치: <code>{branch or "-"}</code>
  · 커밋: <code>{commit_sha or "-"}</code>
  · 생성: <code>{html.escape(generated_at)}</code>
</p>

<h2>요약</h2>
<div class="summary-grid">
  <div><strong>{s["total"]}</strong>전체</div>
  <div><strong>{s["high"]}</strong>HIGH</div>
  <div><strong>{s["medium"]}</strong>MEDIUM</div>
  <div><strong>{s["low"]}</strong>LOW</div>
  <div><strong>{s["patches_generated"]}</strong>수정안 생성</div>
  <div><strong>{s["patches_verified"]}</strong>수정안 검증</div>
</div>

<h2>취약점 ({s["total"]}건)</h2>
{('<table><thead><tr><th>ID</th><th>심각도</th><th>도구/규칙</th><th>제목</th>'
  '<th>위치</th><th>CWE</th></tr></thead><tbody>' + vuln_rows + '</tbody></table>')
 if vuln_rows else '<p class="muted">탐지된 취약점이 없습니다.</p>'}

<h2>LLM 수정안 ({s["patches_generated"]}건)</h2>
{('<table><thead><tr><th>대상 취약점</th><th>유형</th><th>상태</th>'
  '<th>설명</th></tr></thead><tbody>' + patch_rows + '</tbody></table>')
 if patch_rows else '<p class="muted">생성된 수정안이 없습니다.</p>'}

{deps_block}
</body>
</html>
"""

    def generate_markdown(self, data: dict, deps_data: Optional[dict] = None) -> str:
        data = data or {}
        s = _summary(data)
        lines: list[str] = []
        lines.append("# Dallo 보안 분석 리포트")
        lines.append("")
        lines.append(f"- 세션: `{_g(data, 'session_id', '(미상)')}`")
        if _g(data, "repo"):
            lines.append(f"- 레포: `{_g(data, 'repo')}`")
        if _g(data, "pr_number") not in ("", None):
            lines.append(f"- PR: `{_g(data, 'pr_number')}`")
        if _g(data, "branch"):
            lines.append(f"- 브랜치: `{_g(data, 'branch')}`")
        if _g(data, "commit_sha"):
            lines.append(f"- 커밋: `{_g(data, 'commit_sha')}`")
        lines.append(f"- 생성: `{datetime.now().isoformat(timespec='seconds')}`")
        lines.append("")
        lines.append("## 요약")
        lines.append("")
        lines.append(f"- 전체: **{s['total']}**")
        lines.append(f"- HIGH: **{s['high']}**, MEDIUM: **{s['medium']}**, LOW: **{s['low']}**")
        lines.append(
            f"- 수정안 생성: **{s['patches_generated']}**, "
            f"검증 통과: **{s['patches_verified']}**"
        )
        lines.append("")

        vulns = _g(data, "vulnerabilities", []) or []
        lines.append(f"## 취약점 ({s['total']}건)")
        lines.append("")
        if not vulns:
            lines.append("_탐지된 취약점이 없습니다._")
        else:
            for v in vulns:
                lines.extend(self._md_vuln_block(v))
        lines.append("")

        patches = _g(data, "patches", []) or []
        lines.append(f"## LLM 수정안 ({s['patches_generated']}건)")
        lines.append("")
        if not patches:
            lines.append("_생성된 수정안이 없습니다._")
        else:
            for p in patches:
                lines.extend(self._md_patch_block(p))
        lines.append("")

        if deps_data:
            lines.extend(self._md_deps_block(deps_data))

        return "\n".join(lines).rstrip() + "\n"

    def save_report(
        self,
        data: dict,
        output_dir: str,
        fmt: str = "html",
        include_deps: Optional[dict] = None,
    ) -> dict[str, str]:
        """리포트 파일을 디스크에 저장. 선택된 포맷의 경로 dict 반환.

        fmt: "html" | "md" | "both"
        include_deps: 의존성 스캔 결과 dict (선택).
        """
        os.makedirs(output_dir, exist_ok=True)
        session_id = str(_g(data, "session_id", "report") or "report")
        # 파일명에 안전한 문자만 남긴다.
        safe_session = "".join(
            c if c.isalnum() or c in ("_", "-") else "_" for c in session_id
        )[:64] or "report"
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        base = f"report_{safe_session}_{ts}"

        files: dict[str, str] = {}
        if fmt in ("html", "both"):
            html_path = os.path.join(output_dir, f"{base}.html")
            with open(html_path, "w", encoding="utf-8") as f:
                f.write(self.generate_html(data, include_deps))
            files["html"] = html_path
        if fmt in ("md", "both"):
            md_path = os.path.join(output_dir, f"{base}.md")
            with open(md_path, "w", encoding="utf-8") as f:
                f.write(self.generate_markdown(data, include_deps))
            files["md"] = md_path
        return files

    # ------------------------------------------------------------
    # HTML 헬퍼
    # ------------------------------------------------------------

    def _html_vuln_row(self, v: dict) -> str:
        v = v or {}
        sev = str(_g(v, "severity", "")).upper()
        cwe = _g(v, "cwe_id", "")
        cwe_url = _cwe_link(cwe)
        cwe_html = (
            f'<a href="{html.escape(cwe_url)}" target="_blank" rel="noopener">'
            f"{html.escape(str(cwe))}</a>"
            if cwe and cwe_url
            else html.escape(str(cwe or "-"))
        )
        snippet = str(_g(v, "code_snippet", ""))
        return (
            "<tr>"
            f"<td><code>{html.escape(str(_g(v, 'id', '')))}</code></td>"
            f'<td class="sev-{html.escape(sev)}">{html.escape(sev or "-")}</td>'
            f"<td>{html.escape(str(_g(v, 'tool', '')))}/"
            f"<code>{html.escape(str(_g(v, 'rule_id', '')))}</code></td>"
            f"<td>{html.escape(str(_g(v, 'title', '')))}"
            f'<div class="muted">{html.escape(str(_g(v, "description", "")))}</div>'
            f"<pre>{html.escape(snippet)}</pre></td>"
            f"<td><code>{html.escape(str(_g(v, 'file_path', '')))}:"
            f"{html.escape(str(_g(v, 'line_number', '')))}</code></td>"
            f"<td>{cwe_html}</td>"
            "</tr>"
        )

    def _html_patch_row(self, p: dict) -> str:
        p = p or {}
        sec = _g(p, "security_revalidation", None)
        sec_text = ""
        if isinstance(sec, dict):
            ok = sec.get("safe", sec.get("passed"))
            sec_text = f' · 보안재검증: {"통과" if ok else "실패"}'
        return (
            "<tr>"
            f"<td><code>{html.escape(str(_g(p, 'vulnerability_id', '')))}</code></td>"
            f"<td>{html.escape(str(_g(p, 'fix_type', '')))}</td>"
            f"<td>{html.escape(str(_g(p, 'status', '')))}{html.escape(sec_text)}</td>"
            f"<td>{html.escape(str(_g(p, 'explanation', '')))}"
            f"<pre>{html.escape(str(_g(p, 'fixed_code', '')))}</pre></td>"
            "</tr>"
        )

    def _html_deps_block(self, deps_data: Optional[dict]) -> str:
        if not isinstance(deps_data, dict):
            return ""
        results = deps_data.get("results") or []
        if not results:
            return ""
        rows: list[str] = []
        for r in results:
            r = r or {}
            tool = html.escape(str(r.get("tool", "")))
            for vuln in r.get("vulnerabilities", []) or []:
                vuln = vuln or {}
                rows.append(
                    "<tr>"
                    f"<td>{tool}</td>"
                    f"<td><code>{html.escape(str(vuln.get('package', '')))}</code></td>"
                    f"<td><code>{html.escape(str(vuln.get('installed_version', '')))}</code></td>"
                    f"<td><code>{html.escape(str(vuln.get('fixed_version', '')))}</code></td>"
                    f"<td>{html.escape(str(vuln.get('severity', '')))}</td>"
                    f"<td>{html.escape(str(vuln.get('vulnerability_id', '')))}</td>"
                    "</tr>"
                )
        if not rows:
            return ""
        return (
            "<h2>의존성 취약점</h2>"
            "<table><thead><tr><th>도구</th><th>패키지</th><th>설치</th>"
            "<th>수정</th><th>심각도</th><th>ID</th></tr></thead>"
            "<tbody>" + "".join(rows) + "</tbody></table>"
        )

    # ------------------------------------------------------------
    # Markdown 헬퍼
    # ------------------------------------------------------------

    def _md_vuln_block(self, v: dict) -> list[str]:
        v = v or {}
        cwe = _g(v, "cwe_id", "")
        cwe_link = _cwe_link(cwe)
        sev = str(_g(v, "severity", "")).upper() or "-"
        out = [
            f"### `{_g(v, 'id', '')}` — {_g(v, 'title', '')}",
            "",
            f"- 심각도: **{sev}**",
            f"- 도구/규칙: `{_g(v, 'tool', '')}` / `{_g(v, 'rule_id', '')}`",
            f"- 위치: `{_g(v, 'file_path', '')}:{_g(v, 'line_number', '')}`",
        ]
        if cwe:
            out.append(f"- CWE: [{cwe}]({cwe_link})" if cwe_link else f"- CWE: {cwe}")
        desc = str(_g(v, "description", "")).strip()
        if desc:
            out.append(f"- 설명: {desc}")
        snippet = str(_g(v, "code_snippet", ""))
        if snippet:
            out.append("")
            out.append("```")
            out.append(self._md_safe_code(snippet))
            out.append("```")
        out.append("")
        return out

    def _md_patch_block(self, p: dict) -> list[str]:
        p = p or {}
        out = [
            f"### 수정안 → `{_g(p, 'vulnerability_id', '')}`",
            "",
            f"- 유형: `{_g(p, 'fix_type', '')}`",
            f"- 상태: `{_g(p, 'status', '')}`",
        ]
        sec = _g(p, "security_revalidation", None)
        if isinstance(sec, dict):
            ok = sec.get("safe", sec.get("passed"))
            out.append(f"- 보안 재검증: {'통과' if ok else '실패'}")
        explanation = str(_g(p, "explanation", "")).strip()
        if explanation:
            out.append(f"- 설명: {explanation}")
        fixed_code = str(_g(p, "fixed_code", ""))
        if fixed_code:
            out.append("")
            out.append("```")
            out.append(self._md_safe_code(fixed_code))
            out.append("```")
        out.append("")
        return out

    def _md_deps_block(self, deps_data: dict) -> list[str]:
        results = deps_data.get("results") or []
        if not results:
            return []
        out = ["## 의존성 취약점", ""]
        any_vuln = False
        for r in results:
            r = r or {}
            for vuln in r.get("vulnerabilities", []) or []:
                any_vuln = True
                vuln = vuln or {}
                out.append(
                    f"- `{vuln.get('package', '')}` "
                    f"({vuln.get('installed_version', '')} → "
                    f"{vuln.get('fixed_version', '')}) "
                    f"— {vuln.get('severity', '')} "
                    f"`{vuln.get('vulnerability_id', '')}`"
                )
        if not any_vuln:
            out.append("_탐지된 의존성 취약점이 없습니다._")
        out.append("")
        return out

    @staticmethod
    def _md_safe_code(text: str) -> str:
        """코드 블록 안에서 ``` 가 충돌하지 않도록 백틱 3연속을 치환."""
        return text.replace("```", "''`")
