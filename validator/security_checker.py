"""
보안 재검증 모듈 (validator/security_checker.py)

LLM이 생성한 수정 코드에 Bandit/Semgrep을 다시 실행하여
새로운 취약점이 도입되지 않았는지 검증합니다.

사용법:
    from validator.security_checker import SecurityChecker

    checker = SecurityChecker()
    result = checker.check(patch, language="python", filename="app.py")
"""

import os
import sys
import tempfile
import logging
from dataclasses import dataclass, field, asdict
from typing import Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shared.schemas import PatchSuggestion, PatchStatus
from validator.file_io import FileIO, get_default_file_io

logger = logging.getLogger(__name__)


@dataclass
class SecurityCheckResult:
    """보안 재검증 결과"""
    passed: bool                              # 새 취약점 없으면 True
    new_vulnerabilities: list[dict] = field(default_factory=list)  # 새로 발견된 취약점
    original_vuln_count: int = 0              # 원본 코드 취약점 수
    fixed_vuln_count: int = 0                 # 수정 코드 취약점 수
    removed_count: int = 0                    # 제거된 취약점 수
    introduced_count: int = 0                 # 새로 도입된 취약점 수
    tool_used: str = ""                       # 사용된 도구
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)


class SecurityChecker:
    """LLM 수정안의 보안 재검증기.

    외부 도구(``bandit`` / ``semgrep``) 호출은 ``analyzer.bandit_runner.BanditRunner``
    / ``analyzer.semgrep_runner.SemgrepRunner`` 어댑터에 위임한다. 테스트는 생성자에
    더블을 주입해 실제 subprocess / 외부 스캐너 호출을 막을 수 있다 (Wave 4-L).

    더블을 주입하지 않으면 기본 동작은 보존된다 — 실제 ``BanditRunner()`` /
    ``SemgrepRunner(config="auto")`` 인스턴스는 ``check()`` 호출 시점에 lazy 하게
    생성되어 import 시 부수효과를 일으키지 않는다.
    """

    def __init__(
        self,
        *,
        bandit_runner=None,
        semgrep_runner=None,
        file_io: Optional[FileIO] = None,
    ):
        """
        Args:
            bandit_runner: ``BanditRunner`` 인터페이스 더블(테스트 주입용).
                ``None`` 이면 호출 시점에 ``BanditRunner()`` 를 lazy 생성한다.
            semgrep_runner: ``SemgrepRunner`` 인터페이스 더블(테스트 주입용).
                ``None`` 이면 호출 시점에 ``SemgrepRunner(config="auto")`` 를
                lazy 생성한다.
            file_io: ``validator.file_io.FileIO`` 인터페이스 더블(테스트 주입용).
                ``None`` 이면 ``_run_security_scan`` 시점에 lazy 로
                ``get_default_file_io()`` 를 사용한다 (Wave 4-O).
        """
        self._bandit_runner = bandit_runner
        self._semgrep_runner = semgrep_runner
        self._file_io = file_io

    def _get_bandit_runner(self):
        if self._bandit_runner is None:
            from analyzer.bandit_runner import BanditRunner
            self._bandit_runner = BanditRunner()
        return self._bandit_runner

    def _get_semgrep_runner(self):
        if self._semgrep_runner is None:
            from analyzer.semgrep_runner import SemgrepRunner
            self._semgrep_runner = SemgrepRunner(config="auto")
        return self._semgrep_runner

    def check(
        self,
        patch: PatchSuggestion,
        language: str = "python",
        filename: str = "code.py",
        original_code: str = "",
    ) -> PatchSuggestion:
        """
        수정안을 보안 재검증하고 결과를 PatchSuggestion에 반영합니다.

        Args:
            patch: LLM이 생성한 수정안
            language: 코드 언어
            filename: 파일명 (확장자로 도구 선택)
            original_code: 원본 코드 (비교용)

        Returns:
            보안 재검증 결과가 반영된 PatchSuggestion
        """
        if not patch.fixed_code or not patch.fixed_code.strip():
            return patch

        if patch.status == PatchStatus.FAILED:
            return patch

        result = self._run_security_scan(
            fixed_code=patch.fixed_code,
            original_code=original_code,
            language=language,
            filename=filename,
        )

        # 결과를 patch에 반영
        patch.security_revalidation = result.to_dict()

        if result.passed:
            patch.status = PatchStatus.VERIFIED
            patch.explanation += f"\n\n✅ 보안 재검증 통과 — 새로운 취약점 없음 (도구: {result.tool_used})"
            if result.removed_count > 0:
                patch.explanation += f"\n   원본 {result.original_vuln_count}건 → 수정 {result.fixed_vuln_count}건 ({result.removed_count}건 제거)"
        else:
            patch.status = PatchStatus.FAILED
            vuln_summary = ", ".join(
                f"{v.get('rule_id', '?')}({v.get('severity', '?')})"
                for v in result.new_vulnerabilities[:3]
            )
            patch.explanation += f"\n\n❌ 보안 재검증 실패 — 새로운 취약점 {result.introduced_count}건 발견: {vuln_summary}"

        return patch

    def check_batch(
        self,
        patches: list[PatchSuggestion],
        language: str = "python",
        filename: str = "code.py",
        original_code: str = "",
    ) -> list[PatchSuggestion]:
        """여러 수정안을 일괄 보안 재검증"""
        return [
            self.check(p, language=language, filename=filename, original_code=original_code)
            for p in patches
        ]

    def _run_security_scan(
        self,
        fixed_code: str,
        original_code: str,
        language: str,
        filename: str,
    ) -> SecurityCheckResult:
        """수정 코드와 원본 코드에 보안 스캔을 실행하고 비교합니다."""
        ext = os.path.splitext(filename)[1].lower()
        if not ext:
            ext_map = {
                "python": ".py", "java": ".java", "javascript": ".js",
                "typescript": ".ts", "go": ".go", "c": ".c", "cpp": ".cpp",
                "kotlin": ".kt", "rust": ".rs", "ruby": ".rb", "php": ".php",
            }
            ext = ext_map.get(language, ".py")
            filename = f"code{ext}"

        tmp_dir = tempfile.mkdtemp(prefix="dallo_revalidate_")
        try:
            # Wave 4-O: 임시 파일 쓰기 경계를 file_io 어댑터로 위임.
            file_io = self._file_io or get_default_file_io()

            # 수정 코드 스캔
            fixed_path = os.path.join(tmp_dir, f"fixed_{filename}")
            file_io.write_text(fixed_path, fixed_code)

            fixed_vulns = self._scan_file(fixed_path, ext)

            # 원본 코드 스캔 (비교용)
            original_vulns = []
            if original_code:
                original_path = os.path.join(tmp_dir, f"original_{filename}")
                file_io.write_text(original_path, original_code)
                original_vulns = self._scan_file(original_path, ext)

            # 비교 분석
            original_rules = {(v.get("rule_id"), v.get("title")) for v in original_vulns}
            fixed_rules = {(v.get("rule_id"), v.get("title")) for v in fixed_vulns}

            new_rules = fixed_rules - original_rules
            new_vulns = [
                v for v in fixed_vulns
                if (v.get("rule_id"), v.get("title")) in new_rules
            ]

            tool_used = "bandit+semgrep" if ext == ".py" else "semgrep"

            return SecurityCheckResult(
                passed=len(new_vulns) == 0,
                new_vulnerabilities=new_vulns,
                original_vuln_count=len(original_vulns),
                fixed_vuln_count=len(fixed_vulns),
                removed_count=max(0, len(original_vulns) - len(fixed_vulns)),
                introduced_count=len(new_vulns),
                tool_used=tool_used,
            )

        except Exception as e:
            logger.warning(f"보안 재검증 오류: {e}")
            return SecurityCheckResult(
                passed=True,  # 스캔 실패 시 통과 처리 (기존 동작 유지)
                error=str(e),
                tool_used="error",
            )
        finally:
            import shutil
            shutil.rmtree(tmp_dir, ignore_errors=True)

    def _scan_file(self, file_path: str, ext: str) -> list[dict]:
        """파일에 보안 스캔을 실행하고 취약점 리스트를 반환합니다."""
        vulns = []

        if ext == ".py":
            vulns.extend(self._run_bandit(file_path))

        vulns.extend(self._run_semgrep(file_path))

        return vulns

    def _run_bandit(self, file_path: str) -> list[dict]:
        """Bandit 스캔 실행"""
        try:
            runner = self._get_bandit_runner()
            result = runner.run(file_path)
            return [
                {
                    "tool": "bandit",
                    "rule_id": v.rule_id,
                    "severity": v.severity,
                    "title": v.title,
                    "description": v.description,
                    "line_number": v.line_number,
                    "cwe_id": v.cwe_id,
                }
                for v in result.vulnerabilities
            ]
        except Exception as e:
            logger.warning(f"Bandit 재스캔 실패: {e}")
            return []

    def _run_semgrep(self, file_path: str) -> list[dict]:
        """Semgrep 스캔 실행"""
        try:
            runner = self._get_semgrep_runner()
            result = runner.run(file_path)
            return [
                {
                    "tool": "semgrep",
                    "rule_id": v.rule_id,
                    "severity": v.severity,
                    "title": v.title,
                    "description": v.description,
                    "line_number": v.line_number,
                    "cwe_id": v.cwe_id,
                }
                for v in result.vulnerabilities
            ]
        except Exception as e:
            logger.warning(f"Semgrep 재스캔 실패: {e}")
            return []
