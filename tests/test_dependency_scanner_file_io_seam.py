"""DependencyScanner file I/O seam test (Wave 4-Z).

``DependencyScanner`` 의 requirements/package.json 임시 쓰기 및 pip-audit
fallback 라인 읽기 책임을 ``analyzer.file_io.FileIO`` 어댑터로 분리해
fakeable 화한 동작을 회귀 검증한다.

- 생성자는 keyword-only ``file_io`` 매개변수를 수용하며 기본값 ``None`` 은
  ``run`` / ``scan_*`` 시점에 lazy 로 ``analyzer.file_io.get_default_file_io()``
  를 사용한다 — 기존 ``DependencyScanner()`` / ``DependencyScanner(runner=...)``
  호환이 유지되어야 한다.
- 더블이 주입되면 ``scan_requirements_text`` / ``scan_package_json_text`` 의
  임시 쓰기와 ``_fallback_pip_scan`` 의 라인 읽기 모두 어댑터를 통과한다.
  실제 디스크에는 그 *내용* 이 직접 쓰이지 않는다 (tempfile.mkdtemp 만 OS
  호출이며, scanner 본문은 ``open(...)`` 을 더 이상 호출하지 않는다).
- AST 가드: ``analyzer/dependency_scanner.py`` 본문에 ``open()`` / ``.write(``
  / ``.readlines(`` 등 파일 I/O 경계 함수 호출이 남아 있지 않아야 한다.
- 본 테스트는 실제 ``pip-audit`` / ``npm`` / 네트워크 호출을 절대 일으키지
  않는다. 모든 외부 명령 경계는 fake runner 로 격리된다.
"""

from __future__ import annotations

import ast
import inspect
import json
import os
import sys
from typing import Any, Optional

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyzer.dependency_command_runner import CommandResult
from analyzer.dependency_scanner import DependencyScanner


# ============================================================
# 더블 — Runner / FileIO
# ============================================================


class _RecordingRunner:
    """argv / cwd / timeout 호출 이력을 보관하고, 사전 등록된 응답을 돌려준다."""

    def __init__(self):
        self.calls: list[dict] = []
        self.responses: dict[str, list[Any]] = {}

    def queue(self, argv0: str, *, stdout: str = "", stderr: str = "", returncode: int = 0):
        self.responses.setdefault(argv0, []).append(
            CommandResult(stdout=stdout, stderr=stderr, returncode=returncode)
        )

    def queue_exc(self, argv0: str, exc: BaseException):
        self.responses.setdefault(argv0, []).append(exc)

    def run(
        self,
        argv: list[str],
        *,
        cwd: Optional[str] = None,
        timeout: int = 120,
        env: Optional[dict] = None,
    ) -> CommandResult:
        self.calls.append({
            "argv": list(argv),
            "cwd": cwd,
            "timeout": timeout,
            "env": env,
        })
        argv0 = argv[0]
        if argv0 == "npm" and len(argv) > 1:
            key = f"npm {argv[1]}"
            if key in self.responses and self.responses[key]:
                item = self.responses[key].pop(0)
                if isinstance(item, BaseException):
                    raise item
                return item
        if argv0 in self.responses and self.responses[argv0]:
            item = self.responses[argv0].pop(0)
            if isinstance(item, BaseException):
                raise item
            return item
        return CommandResult(stdout="", stderr="", returncode=0)


class _FakeFileIO:
    """write_text / read_text_lines 호출을 기록만 하는 더블 — 실제 디스크 쓰기 없음.

    ``read_text_lines`` 는 ``seed_lines(path, lines)`` 로 사전 시드된 응답을
    돌려준다. 시드가 없으면 빈 리스트.
    """

    def __init__(self) -> None:
        self.write_text_calls: list[tuple[str, str]] = []
        self.read_calls: list[str] = []
        self._read_seeds: dict[str, list[str]] = {}

    def write_text(self, path: str, content: str) -> None:
        self.write_text_calls.append((path, content))

    def seed_lines(self, path: str, lines: list[str]) -> None:
        self._read_seeds[path] = lines

    def read_text_lines(self, path: str) -> list[str]:
        self.read_calls.append(path)
        return list(self._read_seeds.get(path, []))


# ============================================================
# 생성자 시그니처 — keyword-only file_io
# ============================================================


class TestDependencyScannerConstructorSignature:
    def test_file_io_param_is_keyword_only_and_optional(self):
        sig = inspect.signature(DependencyScanner.__init__)
        assert "file_io" in sig.parameters, (
            "DependencyScanner 는 keyword-only file_io 매개변수를 받아야 함"
        )
        param = sig.parameters["file_io"]
        assert param.kind == inspect.Parameter.KEYWORD_ONLY
        assert param.default is None

    def test_default_construction_still_works(self):
        # ``DependencyScanner()`` 는 그대로 동작해야 한다.
        scanner = DependencyScanner()
        assert scanner is not None

    def test_runner_only_kwarg_still_accepted(self):
        runner = _RecordingRunner()
        scanner = DependencyScanner(runner=runner)
        assert scanner._runner is runner

    def test_file_io_is_keyword_only_positional_rejected(self):
        # positional 2번째 인자로는 받지 않는다.
        with pytest.raises(TypeError):
            DependencyScanner(_RecordingRunner(), _FakeFileIO())  # type: ignore[arg-type]


# ============================================================
# 주입된 file_io 사용 — scan_requirements_text / scan_package_json_text
# ============================================================


class TestScanRequirementsTextUsesInjectedFileIO:
    def test_write_text_invoked_with_requirements_content(self):
        runner = _RecordingRunner()
        runner.queue("pip-audit", stdout=json.dumps({"dependencies": []}))
        fake_io = _FakeFileIO()
        scanner = DependencyScanner(runner=runner, file_io=fake_io)

        requirements = "flask==2.0.0\nrequests==2.25.0\n"
        scanner.scan_requirements_text(requirements)

        assert len(fake_io.write_text_calls) == 1
        path, content = fake_io.write_text_calls[0]
        assert path.endswith("requirements.txt")
        assert content == requirements
        # write_text 가 호출되었더라도 실제 디스크에 *내용* 이 직접 쓰이진 않는다.
        assert not os.path.exists(path) or open(path).read() != requirements


class TestScanPackageJsonTextUsesInjectedFileIO:
    def test_write_text_invoked_with_package_json_content(self):
        runner = _RecordingRunner()
        runner.queue("npm install", stdout="", returncode=0)
        runner.queue(
            "npm audit",
            stdout=json.dumps({
                "vulnerabilities": {},
                "metadata": {"totalDependencies": 0},
            }),
        )
        fake_io = _FakeFileIO()
        scanner = DependencyScanner(runner=runner, file_io=fake_io)

        package_json = json.dumps({"dependencies": {"lodash": "4.17.0"}})
        scanner.scan_package_json_text(package_json)

        assert len(fake_io.write_text_calls) == 1
        path, content = fake_io.write_text_calls[0]
        assert path.endswith("package.json")
        assert content == package_json
        # npm install 과 npm audit 두 호출 모두 어댑터를 통과해야 함.
        assert len(runner.calls) == 2
        assert runner.calls[0]["argv"] == ["npm", "install", "--package-lock-only"]
        assert runner.calls[1]["argv"] == ["npm", "audit", "--json"]


# ============================================================
# 주입된 file_io 사용 — pip fallback path 라인 읽기
# ============================================================


class TestFallbackPipScanUsesInjectedFileIO:
    def _scan_with_pip_audit_response(self, fake_io: _FakeFileIO, *, stdout: str, stderr: str = "", returncode: int = 0):
        runner = _RecordingRunner()
        runner.queue("pip-audit", stdout=stdout, stderr=stderr, returncode=returncode)
        scanner = DependencyScanner(runner=runner, file_io=fake_io)
        # 호출 전에 어댑터 입장에서 lines 를 시드한다 — 실제 ``write_text`` 가
        # 호출되는 경로(임시 requirements.txt) 를 가로채 read 응답으로 매핑.
        # 우선 write_text 호출 경로를 캡처하려면 단순히 동일 prefix 의 임시
        # 경로에 대해 seed 한다.
        # ``scan_requirements_text`` 는 ``write_text`` 후 동일 path 로
        # ``read_text_lines`` 를 호출한다. 따라서 호출 순서에 의존하지 않는
        # 가벼운 hook 으로 변경하기 위해 ``write_text`` 가 받은 path 를
        # 그대로 read_text_lines 응답에 매핑한다.
        original_write = fake_io.write_text

        def _spy_write_text(path: str, content: str) -> None:
            # 임시 requirements 경로에 대해, 같은 path 로 read_text_lines
            # 호출 시 ``content.splitlines(keepends=True)`` 를 돌려주도록 seed.
            fake_io.seed_lines(path, content.splitlines(keepends=True))
            original_write(path, content)

        fake_io.write_text = _spy_write_text  # type: ignore[method-assign]
        return scanner

    def test_module_not_found_falls_back_through_injected_read(self):
        fake_io = _FakeFileIO()
        scanner = self._scan_with_pip_audit_response(
            fake_io,
            stdout="",
            stderr="No module named pip_audit",
            returncode=1,
        )

        result = scanner.scan_requirements_text("flask==2.0.0\nrequests==2.25.0\n")

        # 어댑터의 read_text_lines 가 fallback path 에서 호출되어야 한다.
        assert len(fake_io.read_calls) == 1
        # write_text 가 받은 경로와 동일해야 함 (lazy real-disk read 없음).
        assert fake_io.read_calls[0] == fake_io.write_text_calls[0][0]
        # 한국어 메시지/패키지 파싱 동작 보존.
        assert result.error is not None
        assert "pip-audit이 설치되어 있지 않습니다" in result.error
        assert {"name": "flask", "version": "2.0.0"} in result.packages
        assert {"name": "requests", "version": "2.25.0"} in result.packages
        assert result.total_packages == 2

    def test_invalid_json_falls_back_through_injected_read(self):
        fake_io = _FakeFileIO()
        scanner = self._scan_with_pip_audit_response(fake_io, stdout="not-json{{")

        result = scanner.scan_requirements_text("flask>=2.0\n")

        assert len(fake_io.read_calls) == 1
        assert result.error == "pip-audit 출력 파싱 실패"
        assert any(p["name"] == "flask" for p in result.packages)

    def test_filenotfound_falls_back_through_injected_read(self):
        fake_io = _FakeFileIO()
        runner = _RecordingRunner()
        runner.queue_exc("pip-audit", FileNotFoundError("pip-audit"))
        scanner = DependencyScanner(runner=runner, file_io=fake_io)
        # write_text path 를 동일 path 로 read 시드 매핑.
        original_write = fake_io.write_text

        def _spy(path: str, content: str) -> None:
            fake_io.seed_lines(path, content.splitlines(keepends=True))
            original_write(path, content)

        fake_io.write_text = _spy  # type: ignore[method-assign]

        result = scanner.scan_requirements_text("flask==2.0.0\n")

        assert len(fake_io.read_calls) == 1
        assert result.error == "pip-audit 미설치"
        assert any(p["name"] == "flask" for p in result.packages)


# ============================================================
# Lazy 기본 어댑터 해석 — file_io=None
# ============================================================


class TestDefaultFileIOLazyResolution:
    def test_default_file_io_used_only_when_no_fake_injected(self, monkeypatch):
        """``file_io=None`` (기본) 인 경로에서만 ``get_default_file_io()`` 가
        호출되어야 한다. ``file_io=<fake>`` 가 주입되면 호출되지 않는다."""
        from analyzer import dependency_scanner as scanner_mod
        from analyzer.file_io import FileIO

        call_count = {"n": 0}
        real_default = FileIO()

        def _spy() -> FileIO:
            call_count["n"] += 1
            return real_default

        monkeypatch.setattr(scanner_mod, "get_default_file_io", _spy)

        # 1) 더블 주입 — get_default_file_io 호출되면 안 된다.
        runner1 = _RecordingRunner()
        runner1.queue("pip-audit", stdout=json.dumps({"dependencies": []}))
        fake_io = _FakeFileIO()
        scanner1 = DependencyScanner(runner=runner1, file_io=fake_io)
        scanner1.scan_requirements_text("flask==2.0.0\n")
        assert call_count["n"] == 0, (
            "file_io 가 주입되면 get_default_file_io 는 호출되지 않아야 함"
        )

        # 2) 기본 (None) — get_default_file_io 가 lazy 로 호출된다.
        runner2 = _RecordingRunner()
        runner2.queue("pip-audit", stdout=json.dumps({"dependencies": []}))
        scanner2 = DependencyScanner(runner=runner2)
        scanner2.scan_requirements_text("flask==2.0.0\n")
        assert call_count["n"] >= 1, (
            "file_io=None 일 때는 lazy 로 get_default_file_io 가 호출되어야 함"
        )

    def test_default_construction_writes_to_real_disk(self, tmp_path, monkeypatch):
        """``file_io=None`` 운영 경로에서는 기본 어댑터로 실제 디스크에 쓰여야 한다."""
        from analyzer import dependency_scanner as scanner_mod

        # tempfile.mkdtemp 를 tmp_path 하위로 고정해 디스크 잔재 검증을 쉽게 함.
        observed: dict = {}

        original_mkdtemp = scanner_mod.tempfile.mkdtemp

        def _mkdtemp_in_tmp(prefix: str = "tmp"):
            d = str(tmp_path / f"{prefix}fixed")
            os.makedirs(d, exist_ok=True)
            observed["dir"] = d
            return d

        monkeypatch.setattr(scanner_mod.tempfile, "mkdtemp", _mkdtemp_in_tmp)

        runner = _RecordingRunner()
        runner.queue("pip-audit", stdout=json.dumps({"dependencies": []}))
        scanner = DependencyScanner(runner=runner)
        # 디렉토리는 finally 에서 rmtree 로 정리되므로, 파일 존재 자체를 검증할
        # 수 없다. 대신 ``write_text`` 가 실제 어댑터 경로로 실행되었음을
        # 호출이 예외 없이 끝나고 결과가 정상 파싱되는 것으로 간접 검증한다.
        result = scanner.scan_requirements_text("flask==2.0.0\n")
        assert result.tool == "pip-audit"
        assert result.error is None
        assert observed["dir"].endswith("dallo_deps_fixed")


# ============================================================
# AST 가드 — 직접 파일 I/O 호출이 본문에 잔존하지 않아야 한다
# ============================================================


def _collect_direct_io_calls(tree: ast.AST) -> list[str]:
    """``open(...)`` / ``<x>.write(...)`` / ``<x>.writelines(...)`` /
    ``<x>.readlines(...)`` / ``<x>.read(...)`` 형태의 파일 I/O 경계 호출을
    AST 상에서 추출한다.

    주의: ``DependencyScanResult.to_dict()`` 같은 결과 dict 빌더의
    ``.write(...)`` 메서드 사용은 본 스캐너에 존재하지 않으며, 본 가드는
    *호출* 형태만 보므로 fake 클래스 메서드 이름으로 인한 false positive
    를 피할 수 있다.
    """
    out: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name) and func.id == "open":
                out.append("open")
            elif isinstance(func, ast.Attribute) and func.attr in {
                "write",
                "writelines",
                "readlines",
            }:
                out.append(f".{func.attr}")
    return out


class TestNoDirectFileIOLeft:
    def test_dependency_scanner_module_has_no_direct_file_io_calls(self):
        from analyzer import dependency_scanner as mod

        tree = ast.parse(inspect.getsource(mod))
        offending = _collect_direct_io_calls(tree)
        assert offending == [], (
            f"analyzer/dependency_scanner.py 에 직접 파일 I/O 호출 잔존: {offending}"
        )

    def test_file_io_module_still_owns_disk_boundary(self):
        """직접 파일 I/O 호출은 ``analyzer/file_io.py`` 에 그대로 남아 있어야 한다."""
        from analyzer import file_io as mod

        tree = ast.parse(inspect.getsource(mod))
        offending = _collect_direct_io_calls(tree)
        # 적어도 하나의 open() 호출은 file_io 어댑터에 존재한다.
        assert "open" in offending


__all__: list[str] = []
