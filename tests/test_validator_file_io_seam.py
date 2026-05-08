"""Validator file I/O seam test (Wave 4-O).

``TestRunner`` / ``SecurityChecker`` / ``SyntaxChecker`` 가 sandbox 또는
임시 파일에 직접 ``open(..., 'w').write(...)`` 호출로 쓰던 파일 I/O 책임을
keyword-only ``file_io`` 어댑터(``validator/file_io.py`` 의 ``FileIO``)로
fakeable 화한 동작을 회귀 검증한다.

- ``validator/file_io.py`` 모듈에는 최소한 ``write_text(path, content)``
  와 ``write_named_temp(content, suffix='')`` 두 메서드를 갖는 ``FileIO``
  와 lazy ``get_default_file_io()`` 가 존재해야 한다. 기본 어댑터는 UTF-8
  텍스트 인코딩을 보존한다.
- 세 validator 모듈은 keyword-only ``file_io`` 매개변수를 수용하며 기본값
  ``None`` 은 lazy 로 ``get_default_file_io()`` 를 사용한다 — 기본 생성자
  호환성이 유지되어야 한다.
- 더블이 주입되면 sandbox 타깃 쓰기 / 보안 재검증 임시 쓰기 / flake8 임시
  파일 쓰기 모두 어댑터를 통과한다. 실제 디스크에는 그 *내용* 이 직접
  쓰이지 않는다.
- 세 validator 모듈 본문에 직접 ``open(..., 'w'/'a'/'x')`` / ``.write(...)``
  / ``tempfile.NamedTemporaryFile`` 호출이 잔존하지 않아야 한다 — 그
  책임은 ``validator/file_io.py`` 어댑터로만 이동했다.
- 본 테스트는 실제 ``pytest`` / ``flake8`` / ``bandit`` / ``semgrep``
  호출을 절대 일으키지 않는다. 모든 외부 도구 경계는 fake 어댑터로
  격리된다.
"""

from __future__ import annotations

import ast
import inspect
import os
import sys
import tempfile
from types import SimpleNamespace
from typing import Optional

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from validator.test_runner import TestRunner as ValidatorTestRunner
from validator.security_checker import SecurityChecker
from validator.syntax_checker import SyntaxChecker
from validator.validator_command_runner import CommandResult
from shared.schemas import PatchStatus, PatchSuggestion


# ============================================================
# 더블 — FileIO / CommandRunner / Bandit/Semgrep
# ============================================================


class _FakeFileIO:
    """``validator.file_io.FileIO`` 동등 인터페이스 더블 — 실제 디스크 쓰기 없음.

    ``write_text(path, content)`` 은 호출만 기록한다. 디스크에는 아무 것도
    쓰지 않는다.

    ``write_named_temp(content, suffix='')`` 는 호출을 기록한 뒤, 호출자
    (특히 ``SyntaxChecker.check_with_flake8`` 의 ``finally: os.unlink(...)``)
    의 cleanup 계약을 만족시키기 위해 *빈* 임시 파일만 생성해 그 경로를
    돌려준다 — 실제 *content* 는 디스크에 닿지 않는다.
    """

    def __init__(self) -> None:
        self.write_text_calls: list[tuple[str, str]] = []
        self.write_named_temp_calls: list[tuple[str, str]] = []
        self._created_paths: list[str] = []

    def write_text(self, path: str, content: str) -> None:
        self.write_text_calls.append((path, content))

    def write_named_temp(self, content: str, suffix: str = "") -> str:
        self.write_named_temp_calls.append((suffix, content))
        fd, path = tempfile.mkstemp(suffix=suffix)
        os.close(fd)
        self._created_paths.append(path)
        return path


class _FakeCommandRunner:
    """``ValidatorCommandRunner`` 동등 인터페이스 더블."""

    def __init__(
        self,
        *,
        returncode: int = 0,
        stdout: str = "",
        stderr: str = "",
    ) -> None:
        self.calls: list[dict] = []
        self._returncode = returncode
        self._stdout = stdout
        self._stderr = stderr

    def run(self, argv, *, cwd=None, timeout=None, env=None):
        self.calls.append(
            {
                "argv": list(argv),
                "cwd": cwd,
                "timeout": timeout,
                "env": env,
            }
        )
        return CommandResult(
            stdout=self._stdout, stderr=self._stderr, returncode=self._returncode
        )


class _FakeAnalysisRunner:
    """``BanditRunner`` / ``SemgrepRunner`` 동등 인터페이스 더블."""

    def __init__(self, vulns: Optional[list] = None) -> None:
        self.calls: list[str] = []
        self._vulns = list(vulns or [])

    def run(self, file_path: str):
        self.calls.append(file_path)
        return SimpleNamespace(vulnerabilities=list(self._vulns))


def _make_minimal_project(tmp_path) -> str:
    """``_run_in_sandbox`` 가 진입할 수 있는 최소 프로젝트 디렉토리."""
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "target.py").write_text("x = 1\n", encoding="utf-8")
    tests = proj / "tests"
    tests.mkdir()
    (tests / "test_dummy.py").write_text(
        "def test_ok():\n    assert True\n", encoding="utf-8"
    )
    return str(proj)


def _make_patch(
    fixed_code: str = "x = 1\n",
    status: str = PatchStatus.GENERATED,
) -> PatchSuggestion:
    return PatchSuggestion(
        vulnerability_id="v1",
        fixed_code=fixed_code,
        explanation="원본",
        status=status,
    )


# ============================================================
# 1. 어댑터 모듈 표면
# ============================================================


class TestFileIOModuleSurface:
    def test_file_io_module_importable(self):
        import validator.file_io  # noqa: F401

    def test_file_io_class_has_write_text(self):
        from validator.file_io import FileIO

        adapter = FileIO()
        assert callable(getattr(adapter, "write_text", None))

    def test_file_io_class_has_write_named_temp(self):
        from validator.file_io import FileIO

        adapter = FileIO()
        assert callable(getattr(adapter, "write_named_temp", None))

    def test_default_file_io_provider_returns_adapter(self):
        from validator.file_io import FileIO, get_default_file_io

        assert isinstance(get_default_file_io(), FileIO)

    def test_default_write_text_writes_utf8_to_disk(self, tmp_path):
        from validator.file_io import FileIO

        target = str(tmp_path / "out.py")
        FileIO().write_text(target, "한글 = 1\n")
        with open(target, "rb") as f:
            assert f.read().decode("utf-8") == "한글 = 1\n"

    def test_default_write_named_temp_creates_real_file_with_content(self, tmp_path):
        from validator.file_io import FileIO

        path = FileIO().write_named_temp("y = 2\n", suffix=".py")
        try:
            assert os.path.exists(path)
            assert path.endswith(".py")
            with open(path, "rb") as f:
                assert f.read().decode("utf-8") == "y = 2\n"
        finally:
            if os.path.exists(path):
                os.unlink(path)


# ============================================================
# 2. 생성자 시그니처 — keyword-only file_io
# ============================================================


class TestConstructorSignatures:
    def test_test_runner_file_io_param_is_keyword_only_optional(self):
        sig = inspect.signature(ValidatorTestRunner.__init__)
        assert "file_io" in sig.parameters
        param = sig.parameters["file_io"]
        assert param.kind == inspect.Parameter.KEYWORD_ONLY
        assert param.default is None

    def test_security_checker_file_io_param_is_keyword_only_optional(self):
        sig = inspect.signature(SecurityChecker.__init__)
        assert "file_io" in sig.parameters
        param = sig.parameters["file_io"]
        assert param.kind == inspect.Parameter.KEYWORD_ONLY
        assert param.default is None

    def test_syntax_checker_file_io_param_is_keyword_only_optional(self):
        sig = inspect.signature(SyntaxChecker.__init__)
        assert "file_io" in sig.parameters
        param = sig.parameters["file_io"]
        assert param.kind == inspect.Parameter.KEYWORD_ONLY
        assert param.default is None

    def test_test_runner_existing_constructor_still_works(self, tmp_path):
        tr = ValidatorTestRunner(
            project_root=str(tmp_path), runner=_FakeCommandRunner()
        )
        assert tr.project_root == str(tmp_path)

    def test_test_runner_default_constructor_still_works(self):
        tr = ValidatorTestRunner()
        assert tr is not None
        assert tr.project_root  # 기본 project_root 보존

    def test_security_checker_existing_constructor_still_works(self):
        SecurityChecker()
        SecurityChecker(
            bandit_runner=_FakeAnalysisRunner(),
            semgrep_runner=_FakeAnalysisRunner(),
        )

    def test_syntax_checker_existing_constructor_still_works(self):
        SyntaxChecker()
        SyntaxChecker(runner=_FakeCommandRunner())

    def test_test_runner_file_io_rejects_positional(self):
        # ``file_io`` 는 keyword-only — positional 3번째로 전달 시 TypeError.
        with pytest.raises(TypeError):
            ValidatorTestRunner("/tmp", _FakeCommandRunner(), _FakeFileIO())

    def test_syntax_checker_file_io_rejects_positional(self):
        with pytest.raises(TypeError):
            SyntaxChecker(_FakeCommandRunner(), _FakeFileIO())


# ============================================================
# 3. TestRunner — sandbox 타깃 쓰기에 file_io 사용
# ============================================================


class TestTestRunnerSandboxWriteSeam:
    def test_injected_file_io_used_for_sandbox_target_write(self, tmp_path):
        proj_root = _make_minimal_project(tmp_path)
        cmd_runner = _FakeCommandRunner(returncode=0, stdout="1 passed")
        fake_io = _FakeFileIO()
        tr = ValidatorTestRunner(
            project_root=proj_root, runner=cmd_runner, file_io=fake_io
        )

        result = tr._run_in_sandbox(
            fixed_code="x = 99\n",
            original_file_path="target.py",
        )

        assert result.passed is True
        assert "1 passed" in result.output
        # 가짜 file_io 가 sandbox target.py 쓰기에 사용되어야 한다
        assert len(fake_io.write_text_calls) == 1
        path, content = fake_io.write_text_calls[0]
        assert path.endswith(os.sep + "target.py")
        # sandbox 임시 디렉토리 안의 경로여야 한다 (project_root 바깥 아님)
        assert os.path.basename(os.path.dirname(path)).startswith("dallo_test_")
        assert content == "x = 99\n"
        # 호출 후 sandbox 디렉토리는 정리되었으므로 path 는 더 이상 존재 X.
        # 핵심 회귀: 외부 파일 / 원본 project_root 의 target.py 는 변경 없음.
        with open(os.path.join(proj_root, "target.py"), "r", encoding="utf-8") as f:
            assert f.read() == "x = 1\n"
        # 실 subprocess 호출 0건 (fake runner)
        assert len(cmd_runner.calls) == 1

    def test_default_file_io_lazy_runs_real_sandbox_write(self, tmp_path):
        """``file_io=None`` 기본 경로에서도 ``_run_in_sandbox`` 가 정상 동작한다.

        sandbox 임시 디렉토리는 finally 에서 정리되므로 디스크 검증은
        외부에서 직접 할 수 없지만, fake command runner 가 정상 호출되고
        결과가 ``passed=True`` 로 반환되어야 한다.
        """
        proj_root = _make_minimal_project(tmp_path)
        cmd_runner = _FakeCommandRunner(returncode=0, stdout="1 passed")
        tr = ValidatorTestRunner(project_root=proj_root, runner=cmd_runner)

        result = tr._run_in_sandbox(
            fixed_code="x = 2\n",
            original_file_path="target.py",
        )
        assert result.passed is True
        assert len(cmd_runner.calls) == 1


# ============================================================
# 4. SecurityChecker — fixed/original 임시 쓰기에 file_io 사용
# ============================================================


class TestSecurityCheckerFileIOSeam:
    def test_fake_used_for_fixed_only_when_no_original(self):
        bandit = _FakeAnalysisRunner()
        semgrep = _FakeAnalysisRunner()
        fake_io = _FakeFileIO()
        checker = SecurityChecker(
            bandit_runner=bandit, semgrep_runner=semgrep, file_io=fake_io
        )

        out = checker.check(
            _make_patch(fixed_code="fix = 1\n"),
            language="python",
            filename="app.py",
            original_code="",
        )

        assert len(fake_io.write_text_calls) == 1
        path, content = fake_io.write_text_calls[0]
        assert os.path.basename(path) == "fixed_app.py"
        assert content == "fix = 1\n"
        # bandit/semgrep 가 그 경로로 호출되었어야 한다
        assert bandit.calls == [path]
        assert semgrep.calls == [path]
        assert out.status == PatchStatus.VERIFIED

    def test_fake_used_for_both_fixed_and_original(self):
        bandit = _FakeAnalysisRunner()
        semgrep = _FakeAnalysisRunner()
        fake_io = _FakeFileIO()
        checker = SecurityChecker(
            bandit_runner=bandit, semgrep_runner=semgrep, file_io=fake_io
        )

        checker.check(
            _make_patch(fixed_code="fix = 1\n"),
            language="python",
            filename="app.py",
            original_code="orig = 1\n",
        )

        # fixed 1 + original 1 = 총 2회 write_text 호출
        assert len(fake_io.write_text_calls) == 2
        names = sorted(
            (os.path.basename(p), c) for p, c in fake_io.write_text_calls
        )
        assert names == [
            ("fixed_app.py", "fix = 1\n"),
            ("original_app.py", "orig = 1\n"),
        ]

    def test_default_file_io_lazy_when_none(self):
        """``file_io=None`` 기본 경로에서도 ``check()`` 가 정상 종료해야 한다.

        실 디스크 쓰기 + fake bandit/semgrep 결과 비교 → ``VERIFIED`` 분기.
        """
        bandit = _FakeAnalysisRunner()
        semgrep = _FakeAnalysisRunner()
        checker = SecurityChecker(
            bandit_runner=bandit, semgrep_runner=semgrep
        )

        out = checker.check(
            _make_patch(),
            language="python",
            filename="app.py",
            original_code="",
        )
        assert out.status == PatchStatus.VERIFIED
        # 실제 임시 파일 경로로 호출되었어야 한다
        assert len(bandit.calls) == 1
        assert len(semgrep.calls) == 1


# ============================================================
# 5. SyntaxChecker — flake8 임시 쓰기에 file_io 사용
# ============================================================


class TestSyntaxCheckerFileIOSeam:
    def test_fake_used_for_temp_file_write(self):
        cmd_runner = _FakeCommandRunner(returncode=0, stdout="")
        fake_io = _FakeFileIO()
        checker = SyntaxChecker(runner=cmd_runner, file_io=fake_io)

        result = checker.check_with_flake8("x = 1\n")
        assert result.valid is True

        assert len(fake_io.write_named_temp_calls) == 1
        suffix, content = fake_io.write_named_temp_calls[0]
        assert suffix == ".py"
        assert content == "x = 1\n"

        # flake8 argv 의 마지막 인자는 fake 가 돌려준 임시 경로여야 한다
        assert len(cmd_runner.calls) == 1
        argv = cmd_runner.calls[0]["argv"]
        assert argv[0] == "flake8"
        assert argv[-1].endswith(".py")
        # 호출 종료 후 임시 파일은 정리되어야 한다 (cleanup 계약 보존)
        assert not os.path.exists(argv[-1])

    def test_default_file_io_lazy_with_fake_runner(self, monkeypatch):
        """``file_io=None`` 기본 경로 + fake runner — 실 flake8 호출 없음."""
        cmd_runner = _FakeCommandRunner(returncode=0, stdout="")
        checker = SyntaxChecker(runner=cmd_runner)

        result = checker.check_with_flake8("x = 1\n")
        assert result.valid is True
        # 임시 .py 파일이 생성되어 argv 마지막 인자에 들어가고, 호출 후 삭제됨
        assert len(cmd_runner.calls) == 1
        tmp = cmd_runner.calls[0]["argv"][-1]
        assert tmp.endswith(".py")
        assert not os.path.exists(tmp)

    def test_filenotfound_falls_back_to_ast_with_fake_io(self):
        """``flake8`` 미설치 (FileNotFoundError) 폴백이 file_io 도입 후에도 보존."""

        class _FNFRunner:
            def __init__(self):
                self.calls: list[dict] = []

            def run(self, argv, *, cwd=None, timeout=None, env=None):
                self.calls.append({"argv": list(argv)})
                raise FileNotFoundError("flake8")

        fake_io = _FakeFileIO()
        checker = SyntaxChecker(runner=_FNFRunner(), file_io=fake_io)

        ok = checker.check_with_flake8("x = 1\n")
        assert ok.valid is True
        # 임시 파일 쓰기는 발생했지만 fake 였으므로 콜 기록만 남음
        assert len(fake_io.write_named_temp_calls) == 1


# ============================================================
# 6. AST 정적 가드 — 세 모듈 본문에 직접 file write 잔존 없음
# ============================================================


def _open_with_write_mode_calls(tree: ast.AST) -> list[int]:
    """``open(path, mode)`` 형태에서 mode 가 쓰기/추가/배타 모드인 호출의 라인."""
    lines: list[int] = []
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "open"
        ):
            mode_value = None
            if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant):
                mode_value = node.args[1].value
            for kw in node.keywords:
                if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
                    mode_value = kw.value.value
            if isinstance(mode_value, str) and any(c in mode_value for c in "wax+"):
                lines.append(node.lineno)
    return lines


def _write_attr_calls(tree: ast.AST) -> list[int]:
    """``.write(...)`` / ``.writelines(...)`` 속성 호출의 라인."""
    lines: list[int] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr in {"write", "writelines"}:
                lines.append(node.lineno)
    return lines


def _named_temp_file_refs(src: str) -> bool:
    return "NamedTemporaryFile" in src


class TestNoDirectFileWriteRemains:
    def _module_tree(self, mod):
        return ast.parse(inspect.getsource(mod))

    def test_test_runner_no_direct_open_write(self):
        from validator import test_runner as mod

        tree = self._module_tree(mod)
        assert _open_with_write_mode_calls(tree) == [], (
            "test_runner.py 본문에 ``open(..., 'w')`` 직접 호출 잔존 — "
            "validator/file_io.py 어댑터로 위임해야 함"
        )
        assert _write_attr_calls(tree) == [], (
            "test_runner.py 본문에 ``.write(...)`` 직접 호출 잔존 — "
            "validator/file_io.py 어댑터로 위임해야 함"
        )

    def test_security_checker_no_direct_open_write(self):
        from validator import security_checker as mod

        tree = self._module_tree(mod)
        assert _open_with_write_mode_calls(tree) == [], (
            "security_checker.py 본문에 ``open(..., 'w')`` 직접 호출 잔존"
        )
        assert _write_attr_calls(tree) == [], (
            "security_checker.py 본문에 ``.write(...)`` 직접 호출 잔존"
        )

    def test_syntax_checker_no_direct_open_write(self):
        from validator import syntax_checker as mod

        tree = self._module_tree(mod)
        src = inspect.getsource(mod)
        assert _open_with_write_mode_calls(tree) == [], (
            "syntax_checker.py 본문에 ``open(..., 'w')`` 직접 호출 잔존"
        )
        assert _write_attr_calls(tree) == [], (
            "syntax_checker.py 본문에 ``.write(...)`` 직접 호출 잔존"
        )
        assert not _named_temp_file_refs(src), (
            "syntax_checker.py 본문에 ``tempfile.NamedTemporaryFile`` 잔존 — "
            "validator/file_io.py 어댑터의 ``write_named_temp`` 로 위임해야 함"
        )

    def test_validator_file_io_module_owns_the_write_boundary(self):
        """``validator/file_io.py`` 본문에는 어댑터 구현으로 ``open`` /
        ``.write`` 가 등장해야 한다 — 이 모듈이 유일한 파일 쓰기 경계다."""
        from validator import file_io as mod

        tree = self._module_tree(mod)
        assert _open_with_write_mode_calls(tree) != [], (
            "file_io.py 어댑터 본문에 ``open(..., 'w')`` 가 있어야 한다"
        )
        assert _write_attr_calls(tree) != [], (
            "file_io.py 어댑터 본문에 ``.write(...)`` 가 있어야 한다"
        )


# ============================================================
# 7. lazy 동작 — 기본 생성자에서 디스크 쓰기 0건
# ============================================================


class TestDefaultConstructionDoesNotTouchDisk:
    def test_test_runner_default_construct_does_not_write(self, tmp_path, monkeypatch):
        """``ValidatorTestRunner()`` 인스턴스화만으로 file_io 호출이 일어나선 안 된다."""
        write_calls: list[tuple] = []

        def _spy_write(path, content):
            write_calls.append((path, content))

        from validator import file_io as mod

        monkeypatch.setattr(mod.FileIO, "write_text", _spy_write)
        ValidatorTestRunner(project_root=str(tmp_path))
        assert write_calls == []

    def test_security_checker_default_construct_does_not_write(self, monkeypatch):
        write_calls: list[tuple] = []

        def _spy_write(self, path, content):
            write_calls.append((path, content))

        from validator import file_io as mod

        monkeypatch.setattr(mod.FileIO, "write_text", _spy_write)
        SecurityChecker()
        assert write_calls == []

    def test_syntax_checker_default_construct_does_not_write(self, monkeypatch):
        write_calls: list[tuple] = []

        def _spy_named_temp(self, content, suffix=""):
            write_calls.append((suffix, content))
            return "/tmp/should_not_be_used.py"

        from validator import file_io as mod

        monkeypatch.setattr(mod.FileIO, "write_named_temp", _spy_named_temp)
        SyntaxChecker()
        assert write_calls == []


__all__: list[str] = []
