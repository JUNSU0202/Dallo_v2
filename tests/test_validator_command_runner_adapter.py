"""검증기 외부 명령 어댑터 단위 테스트.

Wave 4-A: ``validator/validator_command_runner.py`` 와 ``SyntaxChecker`` /
``TestRunner`` 의 어댑터 분리 동작을 검증한다.

- 어댑터(Runner)는 list-argv 만 사용하고 ``shell=True`` 를 절대 쓰지 않는다.
- ``SyntaxChecker.check_with_flake8()`` 는 ``runner`` 더블을 주입받으면
  실제 ``flake8`` subprocess 를 호출하지 않는다.
- ``TestRunner._run_in_sandbox()`` 는 ``runner`` 더블을 주입받으면 실제
  ``pytest`` subprocess 를 호출하지 않는다.
- flake8 / pytest argv·cwd·timeout 형태가 그대로 보존된다.
- flake8 의 ``FileNotFoundError`` 폴백, pytest 의 ``TimeoutExpired`` 한국어
  메시지 분기가 그대로 유지된다.
- 어댑터/runner 어디에도 ``shell=True`` 또는 문자열 명령 실행이 등장하지
  않는다.
"""

from __future__ import annotations

import ast
import inspect
import os
import subprocess
import sys
from typing import Any, Optional

import pytest

from validator.validator_command_runner import (
    CommandResult,
    ValidatorCommandRunner,
)
from validator.syntax_checker import SyntaxChecker
from validator.test_runner import TestRunner as ValidatorTestRunner


# ============================================================
# 어댑터 모듈 surface — shell 금지, subprocess 단일 호출
# ============================================================

def _calls_with_shell_true(tree: ast.AST) -> list[ast.Call]:
    """AST 상에서 ``shell=True`` 키워드를 실제로 사용한 함수 호출만 찾는다."""
    out: list[ast.Call] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            for kw in node.keywords:
                if (
                    kw.arg == "shell"
                    and isinstance(kw.value, ast.Constant)
                    and kw.value.value is True
                ):
                    out.append(node)
    return out


def _direct_subprocess_run_calls(tree: ast.AST) -> list[int]:
    """``subprocess.run(...)`` 직접 호출의 라인 번호를 반환."""
    lines: list[int] = []
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "run"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "subprocess"
        ):
            lines.append(node.lineno)
    return lines


class TestRunnerModuleSurface:
    def test_runner_module_does_not_use_shell_true(self):
        """어댑터에서 실제 ``shell=True`` 호출(AST 기준) 금지."""
        from validator import validator_command_runner as mod

        tree = ast.parse(inspect.getsource(mod))
        assert _calls_with_shell_true(tree) == [], "shell=True 호출 금지"

    def test_runner_module_does_not_use_os_system_or_eval(self):
        from validator import validator_command_runner as mod

        src = inspect.getsource(mod)
        assert "os.system" not in src
        assert "os.popen" not in src
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                assert node.func.id not in {"eval", "exec"}

    def test_adapter_module_owns_single_subprocess_run(self):
        """어댑터 모듈에는 정확히 한 곳에서만 ``subprocess.run`` 을 호출해야 한다."""
        from validator import validator_command_runner as mod

        tree = ast.parse(inspect.getsource(mod))
        assert len(_direct_subprocess_run_calls(tree)) == 1

    def test_syntax_checker_module_no_longer_uses_subprocess_run_directly(self):
        """``syntax_checker.py`` 본문에 ``subprocess.run(...)`` 직접 호출이 없어야 한다."""
        from validator import syntax_checker as mod

        tree = ast.parse(inspect.getsource(mod))
        assert _direct_subprocess_run_calls(tree) == [], (
            "subprocess.run 호출은 ValidatorCommandRunner 어댑터로 이동되어야 함"
        )

    def test_test_runner_module_no_longer_uses_subprocess_run_directly(self):
        """``test_runner.py`` 본문에 ``subprocess.run(...)`` 직접 호출이 없어야 한다.

        ``subprocess`` 모듈 자체는 ``TimeoutExpired`` 사용을 위해 import 가
        남을 수 있다.
        """
        from validator import test_runner as mod

        tree = ast.parse(inspect.getsource(mod))
        assert _direct_subprocess_run_calls(tree) == [], (
            "subprocess.run 호출은 ValidatorCommandRunner 어댑터로 이동되어야 함"
        )

    def test_syntax_checker_module_no_shell_true(self):
        from validator import syntax_checker as mod

        tree = ast.parse(inspect.getsource(mod))
        assert _calls_with_shell_true(tree) == []

    def test_test_runner_module_no_shell_true(self):
        from validator import test_runner as mod

        tree = ast.parse(inspect.getsource(mod))
        assert _calls_with_shell_true(tree) == []


# ============================================================
# CommandResult / 기본 Runner 동작
# ============================================================

class TestCommandResultDataclass:
    def test_command_result_holds_streams_and_returncode(self):
        cr = CommandResult(stdout="ok", stderr="", returncode=0)
        assert cr.stdout == "ok"
        assert cr.stderr == ""
        assert cr.returncode == 0

    def test_command_result_is_immutable(self):
        cr = CommandResult(stdout="x", stderr="", returncode=0)
        with pytest.raises(Exception):
            cr.stdout = "y"  # frozen


class TestValidatorCommandRunnerCallShape:
    def test_runner_invokes_subprocess_with_list_argv_no_shell(self, monkeypatch):
        """기본 Runner 는 list argv 와 ``shell=False`` 의미로 ``subprocess.run`` 을 호출한다."""
        captured: dict = {}

        class _FakeProc:
            def __init__(self):
                self.stdout = "ok"
                self.stderr = ""
                self.returncode = 0

        def _fake_run(argv, **kwargs):
            captured["argv"] = argv
            captured["kwargs"] = kwargs
            return _FakeProc()

        monkeypatch.setattr(
            "validator.validator_command_runner.subprocess.run", _fake_run
        )

        runner = ValidatorCommandRunner()
        out = runner.run(
            ["flake8", "/tmp/x.py"], cwd="/tmp/work", timeout=10
        )

        assert isinstance(out, CommandResult)
        assert out.stdout == "ok"
        assert out.returncode == 0
        assert captured["argv"] == ["flake8", "/tmp/x.py"]
        kwargs = captured["kwargs"]
        # shell 키워드는 절대 True 가 아니어야 함 (없거나 False)
        assert kwargs.get("shell", False) is False
        assert kwargs.get("capture_output") is True
        assert kwargs.get("text") is True
        assert kwargs.get("timeout") == 10
        assert kwargs.get("cwd") == "/tmp/work"

    def test_runner_rejects_non_list_argv(self):
        runner = ValidatorCommandRunner()
        with pytest.raises(ValueError):
            runner.run("flake8 /tmp/x.py")  # type: ignore[arg-type]
        with pytest.raises(ValueError):
            runner.run([])

    def test_runner_propagates_timeout(self, monkeypatch):
        def _raise_timeout(argv, **kwargs):
            raise subprocess.TimeoutExpired(cmd=argv, timeout=kwargs.get("timeout", 0))

        monkeypatch.setattr(
            "validator.validator_command_runner.subprocess.run", _raise_timeout
        )
        runner = ValidatorCommandRunner()
        with pytest.raises(subprocess.TimeoutExpired):
            runner.run(["flake8"], timeout=1)

    def test_runner_propagates_filenotfound(self, monkeypatch):
        def _raise_fnf(argv, **kwargs):
            raise FileNotFoundError(argv[0])

        monkeypatch.setattr(
            "validator.validator_command_runner.subprocess.run", _raise_fnf
        )
        runner = ValidatorCommandRunner()
        with pytest.raises(FileNotFoundError):
            runner.run(["flake8"])

    def test_runner_normalizes_none_streams_to_empty_strings(self, monkeypatch):
        class _FakeProc:
            stdout = None
            stderr = None
            returncode = 0

        monkeypatch.setattr(
            "validator.validator_command_runner.subprocess.run",
            lambda argv, **kw: _FakeProc(),
        )
        runner = ValidatorCommandRunner()
        out = runner.run(["flake8"])
        assert out.stdout == ""
        assert out.stderr == ""


# ============================================================
# 더블 Runner — 호출 기록을 보관
# ============================================================

class _RecordingRunner:
    """argv / cwd / timeout 호출 이력을 보관하고, 사전 등록된 응답을 돌려준다."""

    def __init__(self):
        self.calls: list[dict] = []
        self.responses: list[Any] = []

    def queue(self, *, stdout: str = "", stderr: str = "", returncode: int = 0):
        self.responses.append(
            CommandResult(stdout=stdout, stderr=stderr, returncode=returncode)
        )

    def queue_exc(self, exc: BaseException):
        self.responses.append(exc)

    def run(
        self,
        argv: list[str],
        *,
        cwd: Optional[str] = None,
        timeout: Optional[float] = None,
    ) -> CommandResult:
        self.calls.append({"argv": list(argv), "cwd": cwd, "timeout": timeout})
        if self.responses:
            item = self.responses.pop(0)
            if isinstance(item, BaseException):
                raise item
            return item
        return CommandResult(stdout="", stderr="", returncode=0)


# ============================================================
# SyntaxChecker.check_with_flake8: 실제 subprocess 미사용 + argv 형태 보존
# ============================================================

class TestSyntaxCheckerWithFakeRunner:
    def test_check_with_flake8_uses_injected_runner(self, monkeypatch):
        """fake runner 가 주입되면 실제 ``subprocess.run`` 은 호출되지 않는다."""
        def _boom(*a, **kw):
            raise AssertionError("실제 subprocess.run 이 호출되면 안 됩니다")

        monkeypatch.setattr(
            "validator.validator_command_runner.subprocess.run", _boom
        )

        runner = _RecordingRunner()
        runner.queue(stdout="", stderr="", returncode=0)
        checker = SyntaxChecker(runner=runner)

        result = checker.check_with_flake8("x = 1\n")
        assert result.valid is True
        assert len(runner.calls) == 1

    def test_flake8_argv_and_timeout_preserved(self):
        runner = _RecordingRunner()
        runner.queue(stdout="", stderr="", returncode=0)
        checker = SyntaxChecker(runner=runner)

        checker.check_with_flake8("x = 1\n")

        assert len(runner.calls) == 1
        call = runner.calls[0]
        argv = call["argv"]
        assert argv[0] == "flake8"
        assert argv[1] == "--select=E9,F63,F7,F82"
        # 마지막 인자는 임시 파일 경로 (.py 확장자)
        assert argv[2].endswith(".py")
        # 호출 후 임시 파일은 삭제되어 있어야 함
        assert not os.path.exists(argv[2])
        assert call["timeout"] == 10
        # cwd 는 명시적으로 지정하지 않음
        assert call["cwd"] is None

    def test_flake8_nonzero_returncode_yields_invalid_result(self):
        runner = _RecordingRunner()
        runner.queue(
            stdout="x.py:1:1: E999 invalid syntax",
            stderr="",
            returncode=1,
        )
        checker = SyntaxChecker(runner=runner)

        result = checker.check_with_flake8("def broken(\n")
        assert result.valid is False
        assert "E999" in (result.error_message or "")

    def test_flake8_filenotfound_falls_back_to_ast_check(self):
        """flake8 미설치(``FileNotFoundError``) 시 ``_check_syntax`` 폴백이 보존된다."""
        runner = _RecordingRunner()
        runner.queue_exc(FileNotFoundError("flake8"))
        checker = SyntaxChecker(runner=runner)

        # 유효한 코드 → AST 폴백이 valid 를 돌려줘야 함
        result = checker.check_with_flake8("x = 1\n")
        assert result.valid is True

        runner2 = _RecordingRunner()
        runner2.queue_exc(FileNotFoundError("flake8"))
        checker2 = SyntaxChecker(runner=runner2)
        # 잘못된 코드 → AST 폴백이 invalid 를 돌려줘야 함
        bad = checker2.check_with_flake8("def broken(\n")
        assert bad.valid is False


# ============================================================
# TestRunner._run_in_sandbox: 실제 subprocess 미사용 + argv 형태 보존
# ============================================================

def _make_minimal_project(tmp_path) -> str:
    """pytest sandbox copy 가 동작할 수 있는 최소 프로젝트 디렉토리를 만든다."""
    proj = tmp_path / "proj"
    proj.mkdir()
    # 대상 파일
    (proj / "target.py").write_text("x = 1\n", encoding="utf-8")
    # tests 디렉토리는 비어있지 않아야 _run_in_sandbox 가 pytest 까지 진입
    tests = proj / "tests"
    tests.mkdir()
    (tests / "test_dummy.py").write_text("def test_ok():\n    assert True\n", encoding="utf-8")
    return str(proj)


class TestTestRunnerWithFakeRunner:
    def test_run_in_sandbox_uses_injected_runner(self, monkeypatch, tmp_path):
        """fake runner 가 주입되면 실제 ``subprocess.run`` 은 호출되지 않는다."""
        def _boom(*a, **kw):
            raise AssertionError("실제 subprocess.run 이 호출되면 안 됩니다")

        monkeypatch.setattr(
            "validator.validator_command_runner.subprocess.run", _boom
        )

        proj_root = _make_minimal_project(tmp_path)
        runner = _RecordingRunner()
        runner.queue(stdout="1 passed", stderr="", returncode=0)

        tr = ValidatorTestRunner(project_root=proj_root, runner=runner)
        result = tr._run_in_sandbox(
            fixed_code="x = 2\n",
            original_file_path="target.py",
        )
        assert result.passed is True
        assert "1 passed" in result.output
        assert len(runner.calls) == 1

    def test_pytest_argv_cwd_and_timeout_preserved(self, tmp_path):
        proj_root = _make_minimal_project(tmp_path)
        runner = _RecordingRunner()
        runner.queue(stdout="", stderr="", returncode=0)

        tr = ValidatorTestRunner(project_root=proj_root, runner=runner)
        tr._run_in_sandbox(
            fixed_code="x = 2\n",
            original_file_path="target.py",
        )

        assert len(runner.calls) == 1
        call = runner.calls[0]
        argv = call["argv"]
        # [sys.executable, "-m", "pytest", test_path, "-v", "--tb=short"]
        assert argv[0] == sys.executable
        assert argv[1] == "-m"
        assert argv[2] == "pytest"
        # test_path 는 sandbox tmp dir 안의 tests 디렉토리
        assert argv[3].endswith(os.sep + "tests")
        assert argv[4] == "-v"
        assert argv[5] == "--tb=short"
        # cwd 는 sandbox 임시 디렉토리이며 test_path 의 부모와 일치해야 함
        assert call["cwd"] is not None
        assert os.path.dirname(argv[3]) == call["cwd"]
        assert call["timeout"] == 60

    def test_pytest_nonzero_returncode_marks_failed(self, tmp_path):
        proj_root = _make_minimal_project(tmp_path)
        runner = _RecordingRunner()
        runner.queue(stdout="1 failed", stderr="boom", returncode=1)

        tr = ValidatorTestRunner(project_root=proj_root, runner=runner)
        result = tr._run_in_sandbox(
            fixed_code="x = 2\n",
            original_file_path="target.py",
        )
        assert result.passed is False
        assert result.output == "1 failed"
        assert result.error == "boom"

    def test_pytest_timeout_preserves_korean_message(self, tmp_path):
        proj_root = _make_minimal_project(tmp_path)
        runner = _RecordingRunner()
        runner.queue_exc(
            subprocess.TimeoutExpired(cmd=["pytest"], timeout=60)
        )

        tr = ValidatorTestRunner(project_root=proj_root, runner=runner)
        result = tr._run_in_sandbox(
            fixed_code="x = 2\n",
            original_file_path="target.py",
        )
        assert result.passed is False
        assert result.error == "테스트 실행 시간 초과 (60초)"


# ============================================================
# 하위 호환: 인자 없는 / 기존 시그니처 생성자 동작
# ============================================================

class TestBackwardCompatibility:
    def test_syntax_checker_default_constructor_still_works(self):
        checker = SyntaxChecker()
        assert hasattr(checker, "_runner")
        assert isinstance(checker._runner, ValidatorCommandRunner)

    def test_test_runner_default_constructor_still_works(self):
        tr = ValidatorTestRunner()
        assert hasattr(tr, "_runner")
        assert isinstance(tr._runner, ValidatorCommandRunner)
        assert tr.project_root  # 기본 project_root 설정 보존

    def test_test_runner_positional_project_root_still_works(self, tmp_path):
        # 기존: TestRunner(project_root=...) 형태로 호출하던 코드 보존.
        tr = ValidatorTestRunner(project_root=str(tmp_path))
        assert tr.project_root == str(tmp_path)
        assert isinstance(tr._runner, ValidatorCommandRunner)


__all__: list[str] = []
