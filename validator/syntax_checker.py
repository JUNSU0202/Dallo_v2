"""
문법 검증 모듈 (validator/syntax_checker.py)

LLM이 생성한 수정 코드가 문법적으로 올바른지 검증합니다.

사용법:
    from validator.syntax_checker import SyntaxChecker

    checker = SyntaxChecker()
    result = checker.check(patch)
    # result.syntax_valid = True/False
"""

import ast
import sys
import os
import tempfile
from dataclasses import dataclass
from typing import Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shared.schemas import PatchSuggestion, PatchStatus
from analyzer.command_env import build_child_env
from validator.validator_command_runner import ValidatorCommandRunner


@dataclass
class CheckResult:
    """문법 검사 결과"""
    valid: bool
    error_message: Optional[str] = None
    error_line: Optional[int] = None


class SyntaxChecker:
    """LLM 생성 코드의 문법 검증기.

    외부 도구(``flake8``) 호출은 ``ValidatorCommandRunner`` 어댑터에
    위임한다. 테스트는 생성자에 더블을 주입해 실제 subprocess 호출을 막을
    수 있다 (Wave 4-A).
    """

    def __init__(self, runner: Optional[ValidatorCommandRunner] = None):
        self._runner = runner or ValidatorCommandRunner()

    def check(self, patch: PatchSuggestion, language: str = "python") -> PatchSuggestion:
        """
        PatchSuggestion의 fixed_code 문법을 검증하고 결과를 업데이트합니다.

        Args:
            patch: LLM이 생성한 수정안
            language: 코드 언어 (python, java, javascript, go 등)

        Returns:
            문법 검증 결과가 반영된 PatchSuggestion
        """
        if not patch.fixed_code or not patch.fixed_code.strip():
            patch.syntax_valid = False
            patch.status = PatchStatus.FAILED
            return patch

        result = self._check_syntax(patch.fixed_code, language)
        patch.syntax_valid = result.valid

        if not result.valid:
            patch.status = PatchStatus.FAILED
            patch.explanation += f"\n\n⚠️ 문법 오류: {result.error_message} (라인 {result.error_line})"

        return patch

    def check_batch(self, patches: list[PatchSuggestion]) -> list[PatchSuggestion]:
        """여러 수정안을 일괄 검증"""
        return [self.check(p) for p in patches]

    def _check_syntax(self, code: str, language: str = "python") -> CheckResult:
        """코드의 문법을 검증합니다. Python은 AST, 기타 언어는 기본 구조 검사."""
        if language == "python":
            return self._check_python(code)
        elif language in ("java", "javascript", "typescript", "go", "c", "cpp"):
            return self._check_brackets(code, language)
        else:
            return self._check_brackets(code, language)

    def _check_python(self, code: str) -> CheckResult:
        """Python AST 파싱으로 문법 검증"""
        try:
            ast.parse(code)
            return CheckResult(valid=True)
        except SyntaxError as e:
            return CheckResult(
                valid=False,
                error_message=str(e.msg),
                error_line=e.lineno,
            )

    def _check_brackets(self, code: str, language: str) -> CheckResult:
        """중괄호/괄호 매칭으로 기본 구조 검증 (Java, JS, Go, C 등)"""
        stack = []
        pairs = {')': '(', ']': '[', '}': '{'}
        in_string = False
        string_char = None
        prev_char = None

        for i, ch in enumerate(code):
            # 문자열 내부 스킵
            if in_string:
                if ch == string_char and prev_char != '\\':
                    in_string = False
                prev_char = ch
                continue

            if ch in ('"', "'", '`'):
                in_string = True
                string_char = ch
                prev_char = ch
                continue

            if ch in '([{':
                stack.append((ch, i))
            elif ch in ')]}':
                if not stack:
                    line = code[:i].count('\n') + 1
                    return CheckResult(valid=False, error_message=f"Unmatched '{ch}'", error_line=line)
                top, _ = stack.pop()
                if top != pairs[ch]:
                    line = code[:i].count('\n') + 1
                    return CheckResult(valid=False, error_message=f"Mismatched '{top}' and '{ch}'", error_line=line)

            prev_char = ch

        if stack:
            ch, pos = stack[-1]
            line = code[:pos].count('\n') + 1
            return CheckResult(valid=False, error_message=f"Unclosed '{ch}'", error_line=line)

        return CheckResult(valid=True)

    def check_with_flake8(self, code: str) -> CheckResult:
        """flake8로 코드 스타일까지 검사합니다 (선택적)."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False
        ) as f:
            f.write(code)
            f.flush()
            tmp_path = f.name

        try:
            result = self._runner.run(
                ["flake8", "--select=E9,F63,F7,F82", tmp_path],
                timeout=10,
                env=build_child_env(),
            )
            if result.returncode == 0:
                return CheckResult(valid=True)
            else:
                return CheckResult(
                    valid=False,
                    error_message=result.stdout.strip(),
                )
        except FileNotFoundError:
            # flake8 미설치 시 기본 문법 검사로 폴백
            return self._check_syntax(code)
        finally:
            os.unlink(tmp_path)
