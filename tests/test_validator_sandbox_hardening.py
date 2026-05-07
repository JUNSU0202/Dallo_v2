"""Wave 4-K validator sandbox 하드닝 회귀 테스트.

검증하는 속성:

- ``original_file_path`` 가 sandbox 바깥을 가리키면 (상대 traversal /
  절대 경로 / 중첩 traversal) 외부 파일을 덮어쓰지 않고 실패 결과를
  반환한다.
- 정상 상대 경로 (예: ``target.py``) 는 기존과 동일하게 fake runner 를
  sandbox cwd / 보존된 pytest argv 로 호출한다.
- 성공 / 실패 / 경로 거부 어느 경로에서든 임시 sandbox 디렉토리는
  남지 않는다.
- 프로젝트 root 에 외부를 가리키는 symlink 가 있어도 sandbox 안에 일반
  파일로 그 내용이 복사되지 않는다 (외부 데이터 누출 방지).
- ``validator/test_runner.py`` 본문에 ``shell=True``, ``os.system``,
  ``eval``, ``exec`` 가 도입되지 않았다.

본 테스트는 실제 ``pytest`` subprocess 를 절대로 호출하지 않으며 fake
runner 와 stdlib 임시 디렉토리만 사용한다.
"""

from __future__ import annotations

import ast
import inspect
import os
import sys
import tempfile

import pytest

from validator.test_runner import TestRunner as ValidatorTestRunner
from validator.validator_command_runner import CommandResult


# ============================================================
# 헬퍼 — 최소 프로젝트 / fake runner
# ============================================================


def _make_minimal_project(tmp_path) -> str:
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "target.py").write_text("x = 1\n", encoding="utf-8")
    tests = proj / "tests"
    tests.mkdir()
    (tests / "test_dummy.py").write_text(
        "def test_ok():\n    assert True\n", encoding="utf-8"
    )
    return str(proj)


class _RecordingRunner:
    """argv / cwd / timeout / env 와 호출 시점의 cwd 존재 여부를 기록."""

    def __init__(self, *, returncode: int = 0, stdout: str = "1 passed", stderr: str = ""):
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
                "cwd_existed_during_call": (
                    cwd is not None and os.path.isdir(cwd)
                ),
            }
        )
        return CommandResult(
            stdout=self._stdout, stderr=self._stderr, returncode=self._returncode
        )


# ============================================================
# 1. 경로 traversal / 절대경로 거부
# ============================================================


class TestSandboxPathTraversalRejected:
    """sandbox 바깥을 가리키는 ``original_file_path`` 는 외부 파일을
    덮어쓰지 않고 실패 결과를 반환해야 한다."""

    def test_relative_traversal_does_not_overwrite_outside_file(self, tmp_path):
        proj_root = _make_minimal_project(tmp_path)
        outside = tmp_path / "outside.py"
        outside.write_text("ORIGINAL\n", encoding="utf-8")

        runner = _RecordingRunner()
        tr = ValidatorTestRunner(project_root=proj_root, runner=runner)

        result = tr._run_in_sandbox(
            fixed_code="HACKED\n",
            original_file_path="../outside.py",
        )

        assert result.passed is False
        assert outside.read_text(encoding="utf-8") == "ORIGINAL\n", (
            "sandbox 바깥의 파일이 fixed_code 로 덮어써짐 — traversal 미차단"
        )
        # 경로 거부 시점에 외부 도구는 호출되어선 안 된다.
        assert runner.calls == []

    def test_absolute_outside_path_does_not_overwrite_outside_file(self, tmp_path):
        proj_root = _make_minimal_project(tmp_path)
        outside = tmp_path / "abs_outside.py"
        outside.write_text("ORIGINAL\n", encoding="utf-8")

        runner = _RecordingRunner()
        tr = ValidatorTestRunner(project_root=proj_root, runner=runner)

        result = tr._run_in_sandbox(
            fixed_code="HACKED\n",
            original_file_path=str(outside),
        )

        assert result.passed is False
        assert outside.read_text(encoding="utf-8") == "ORIGINAL\n", (
            "절대 경로로 sandbox 바깥의 파일이 덮어써짐"
        )
        assert runner.calls == []

    def test_nested_traversal_rejected(self, tmp_path):
        """``safe/../../outside.py`` 처럼 중첩된 traversal 도 거부되어야 한다."""
        proj_root = _make_minimal_project(tmp_path)
        outside = tmp_path / "nested_outside.py"
        outside.write_text("ORIGINAL\n", encoding="utf-8")

        # sandbox 안에 진짜 존재하는 디렉토리
        os.makedirs(os.path.join(proj_root, "safe"), exist_ok=True)
        with open(os.path.join(proj_root, "safe", "inner.py"), "w", encoding="utf-8") as f:
            f.write("y = 1\n")

        runner = _RecordingRunner()
        tr = ValidatorTestRunner(project_root=proj_root, runner=runner)

        result = tr._run_in_sandbox(
            fixed_code="HACKED\n",
            original_file_path="safe/../../nested_outside.py",
        )

        assert result.passed is False
        assert outside.read_text(encoding="utf-8") == "ORIGINAL\n"
        assert runner.calls == []


# ============================================================
# 2. 정상 상대경로는 그대로 동작
# ============================================================


class TestSandboxNormalRelativeTargetStillWorks:
    """traversal 차단 도입 후에도 평범한 상대 경로 (예: ``target.py``,
    ``pkg/module.py``) 는 그대로 동작해야 한다."""

    def test_top_level_relative_target_still_runs_pytest(self, tmp_path):
        proj_root = _make_minimal_project(tmp_path)
        runner = _RecordingRunner()
        tr = ValidatorTestRunner(project_root=proj_root, runner=runner)

        result = tr._run_in_sandbox(
            fixed_code="x = 2\n",
            original_file_path="target.py",
        )

        assert result.passed is True
        assert len(runner.calls) == 1
        call = runner.calls[0]
        argv = call["argv"]
        assert argv[0] == sys.executable
        assert argv[1] == "-m"
        assert argv[2] == "pytest"
        assert argv[3].endswith(os.sep + "tests")
        assert argv[4] == "-v"
        assert argv[5] == "--tb=short"
        assert call["timeout"] == 60
        assert call["cwd"] is not None
        assert call["cwd_existed_during_call"] is True

    def test_nested_relative_target_inside_sandbox_works(self, tmp_path):
        proj_root = _make_minimal_project(tmp_path)
        os.makedirs(os.path.join(proj_root, "pkg"), exist_ok=True)
        with open(os.path.join(proj_root, "pkg", "module.py"), "w", encoding="utf-8") as f:
            f.write("z = 1\n")

        runner = _RecordingRunner()
        tr = ValidatorTestRunner(project_root=proj_root, runner=runner)

        result = tr._run_in_sandbox(
            fixed_code="z = 2\n",
            original_file_path="pkg/module.py",
        )

        assert result.passed is True
        assert len(runner.calls) == 1


# ============================================================
# 3. cleanup — 성공 / 실패 / 경로 거부 모두에서 sandbox 디렉토리 제거
# ============================================================


class TestSandboxCleanup:
    def test_sandbox_dir_removed_after_success(self, tmp_path):
        proj_root = _make_minimal_project(tmp_path)
        runner = _RecordingRunner(returncode=0, stdout="1 passed")

        tr = ValidatorTestRunner(project_root=proj_root, runner=runner)
        result = tr._run_in_sandbox(
            fixed_code="x = 2\n",
            original_file_path="target.py",
        )

        assert result.passed is True
        sandbox_cwd = runner.calls[0]["cwd"]
        assert sandbox_cwd is not None
        assert runner.calls[0]["cwd_existed_during_call"] is True
        assert not os.path.exists(sandbox_cwd), (
            f"성공 후 sandbox 임시 디렉토리가 남음: {sandbox_cwd}"
        )

    def test_sandbox_dir_removed_after_failure(self, tmp_path):
        proj_root = _make_minimal_project(tmp_path)
        runner = _RecordingRunner(returncode=1, stdout="1 failed", stderr="boom")

        tr = ValidatorTestRunner(project_root=proj_root, runner=runner)
        result = tr._run_in_sandbox(
            fixed_code="x = 2\n",
            original_file_path="target.py",
        )

        assert result.passed is False
        sandbox_cwd = runner.calls[0]["cwd"]
        assert sandbox_cwd is not None
        assert not os.path.exists(sandbox_cwd), (
            f"실패 후 sandbox 임시 디렉토리가 남음: {sandbox_cwd}"
        )

    def test_sandbox_dir_removed_after_path_rejection(self, tmp_path, monkeypatch):
        """경로 거부 경로에서도 임시 sandbox 디렉토리가 잔존하지 않아야 한다."""
        proj_root = _make_minimal_project(tmp_path)
        outside = tmp_path / "leak.py"
        outside.write_text("X\n", encoding="utf-8")

        created: list[str] = []
        original_mkdtemp = tempfile.mkdtemp

        def _tracking_mkdtemp(*args, **kwargs):
            d = original_mkdtemp(*args, **kwargs)
            created.append(d)
            return d

        monkeypatch.setattr(tempfile, "mkdtemp", _tracking_mkdtemp)

        runner = _RecordingRunner()
        tr = ValidatorTestRunner(project_root=proj_root, runner=runner)
        result = tr._run_in_sandbox(
            fixed_code="X\n",
            original_file_path="../leak.py",
        )

        assert result.passed is False
        assert runner.calls == []
        # mkdtemp 가 호출되었다면 (경로 검증을 sandbox 생성 후에 수행한 경우)
        # 만들어진 모든 디렉토리는 finally 에서 정리되어야 한다.
        for d in created:
            assert not os.path.exists(d), f"경로 거부 후 sandbox dir 잔존: {d}"


# ============================================================
# 4. symlink 정책 — 외부를 가리키는 symlink 의 내용이 sandbox 로 복사되지 않음
# ============================================================


def _can_symlink(tmp_path) -> bool:
    src = tmp_path / "_probe_src"
    dst = tmp_path / "_probe_dst"
    src.write_text("x", encoding="utf-8")
    try:
        os.symlink(str(src), str(dst))
    except (OSError, NotImplementedError):
        return False
    return os.path.islink(str(dst))


class TestSandboxSymlinkPolicy:
    def test_outside_symlink_in_project_root_does_not_leak_target_content(
        self, tmp_path
    ):
        """프로젝트 root 에 외부 파일을 가리키는 symlink 가 있어도 그 내용이
        sandbox 안에 일반 파일로 복사되어선 안 된다."""
        if not _can_symlink(tmp_path):
            pytest.skip("symlink 생성 불가 환경 — 건너뜀")

        proj_root = _make_minimal_project(tmp_path)
        secret = tmp_path / "secret.txt"
        secret.write_text("TOPSECRET\n", encoding="utf-8")
        link_path = os.path.join(proj_root, "secret_link.txt")
        os.symlink(str(secret), link_path)

        captured: dict = {}

        class _InspectingRunner:
            def run(self, argv, *, cwd=None, timeout=None, env=None):
                captured["cwd"] = cwd
                link_in_sandbox = os.path.join(cwd, "secret_link.txt")
                captured["link_in_sandbox_exists"] = os.path.exists(link_in_sandbox)
                if captured["link_in_sandbox_exists"]:
                    with open(link_in_sandbox, "rb") as f:
                        captured["link_in_sandbox_content"] = f.read()
                return CommandResult(stdout="1 passed", stderr="", returncode=0)

        tr = ValidatorTestRunner(project_root=proj_root, runner=_InspectingRunner())
        result = tr._run_in_sandbox(
            fixed_code="x = 2\n",
            original_file_path="target.py",
        )

        # sandbox 진행 자체는 깨져선 안 된다.
        assert result.passed is True
        assert captured.get("cwd") is not None
        # 외부 symlink 가 일반 파일로 sandbox 에 복사되지 않아야 한다.
        assert captured.get("link_in_sandbox_exists") is False, (
            "프로젝트 root 의 외부 symlink 가 sandbox 에 일반 파일로 복사됨 — "
            "외부 데이터가 sandbox 로 노출됨"
        )

    def test_dangling_symlink_in_subdir_does_not_break_copy(self, tmp_path):
        """서브 디렉토리의 dangling symlink 가 있어도 sandbox 복사가 깨져선 안 된다.

        ``shutil.copytree(symlinks=False)`` 의 기본 동작은 dangling 시 에러를
        내므로, ``ignore_dangling_symlinks=True`` 가 적용되어 있는지 확인한다.
        """
        if not _can_symlink(tmp_path):
            pytest.skip("symlink 생성 불가 환경 — 건너뜀")

        proj_root = _make_minimal_project(tmp_path)
        sub = os.path.join(proj_root, "subpkg")
        os.makedirs(sub, exist_ok=True)
        with open(os.path.join(sub, "__init__.py"), "w", encoding="utf-8") as f:
            f.write("")
        # 존재하지 않는 대상을 가리키는 symlink
        os.symlink(
            os.path.join(tmp_path, "does_not_exist.txt"),
            os.path.join(sub, "dangling.txt"),
        )

        runner = _RecordingRunner()
        tr = ValidatorTestRunner(project_root=proj_root, runner=runner)
        result = tr._run_in_sandbox(
            fixed_code="x = 2\n",
            original_file_path="target.py",
        )

        assert result.passed is True
        assert len(runner.calls) == 1


# ============================================================
# 5. AST/static 가드 — shell=True / os.system / eval / exec 미도입
# ============================================================


class TestTestRunnerSourceStaticGuards:
    @staticmethod
    def _src() -> str:
        from validator import test_runner as mod

        return inspect.getsource(mod)

    def test_no_shell_true(self):
        tree = ast.parse(self._src())
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                for kw in node.keywords:
                    if (
                        kw.arg == "shell"
                        and isinstance(kw.value, ast.Constant)
                        and kw.value.value is True
                    ):
                        pytest.fail("shell=True 가 validator/test_runner.py 에 도입됨")

    def test_no_os_system_or_popen(self):
        src = self._src()
        assert "os.system" not in src
        assert "os.popen" not in src

    def test_no_eval_or_exec_calls(self):
        tree = ast.parse(self._src())
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                assert node.func.id not in {"eval", "exec"}, (
                    f"validator/test_runner.py 에 {node.func.id} 호출이 도입됨"
                )


__all__: list[str] = []
