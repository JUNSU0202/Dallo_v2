"""의존성 스캐너 외부 명령 어댑터 단위 테스트.

Wave 3-F: ``analyzer/dependency_command_runner.py`` 와 ``DependencyScanner``
의 어댑터 분리 동작을 검증한다.

- 어댑터(Runner)는 list-argv 만 사용하고 ``shell=True`` 를 절대 쓰지 않는다.
- ``DependencyScanner`` 는 ``runner`` 더블을 주입받으면 실제 ``subprocess``
  호출 없이 동작해야 한다.
- pip-audit / npm install / npm audit argv 가 기존 형태(commands, flags)를
  유지해야 한다.
- pip-audit 미설치 / 출력 없음 / JSON 파싱 실패 / FileNotFoundError /
  TimeoutExpired 등 기존 에러 메시지(한국어) 분기가 그대로 보존되어야 한다.
- 어댑터/스캐너 어디에도 ``shell=True`` 또는 문자열 명령 실행이 등장하지
  않아야 한다.
"""

from __future__ import annotations

import ast
import inspect
import json
import os
import subprocess
from typing import Any, Optional

import pytest

from analyzer.dependency_command_runner import (
    CommandResult,
    DependencyCommandRunner,
)
from analyzer.dependency_scanner import DependencyScanner


# ============================================================
# 어댑터 모듈 surface — shell 금지, subprocess 사용 형태
# ============================================================

def _calls_with_shell_true(tree: ast.AST) -> list[ast.Call]:
    """AST 상에서 ``shell=True`` 키워드를 실제로 사용한 함수 호출만 찾는다.

    docstring 안의 'shell=True' 문자열(정적 분석 가이드용)은 건너뛴다.
    """
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


class TestRunnerModuleSurface:
    def test_runner_module_does_not_use_shell_true(self):
        """어댑터에서 실제 ``shell=True`` 호출(AST 기준) 금지."""
        from analyzer import dependency_command_runner as mod

        tree = ast.parse(inspect.getsource(mod))
        assert _calls_with_shell_true(tree) == [], "shell=True 호출 금지"

    def test_runner_module_does_not_use_os_system_or_eval(self):
        from analyzer import dependency_command_runner as mod

        src = inspect.getsource(mod)
        assert "os.system" not in src
        assert "os.popen" not in src
        # eval/exec 토큰이 함수 호출로 등장하지 않아야 함
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                assert node.func.id not in {"eval", "exec"}

    def test_scanner_module_no_longer_uses_subprocess_run_directly(self):
        """``DependencyScanner`` 본문에 ``subprocess.run(...)`` 직접 호출이 없어야 한다.

        ``subprocess`` 모듈 자체는 ``TimeoutExpired`` 사용을 위해 import 가
        남을 수 있다.
        """
        from analyzer import dependency_scanner as mod

        tree = ast.parse(inspect.getsource(mod))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "run"
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "subprocess"
            ):
                raise AssertionError(
                    "subprocess.run 호출은 DependencyCommandRunner 어댑터로 이동되어야 함"
                )

    def test_scanner_module_no_shell_true(self):
        from analyzer import dependency_scanner as mod

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


class TestDependencyCommandRunnerCallShape:
    def test_runner_invokes_subprocess_with_list_argv_no_shell(self, monkeypatch):
        """기본 Runner 는 list argv 와 ``shell=False`` 의미로 ``subprocess.run`` 을 호출한다."""
        captured: dict = {}

        class _FakeProc:
            def __init__(self):
                self.stdout = "{}"
                self.stderr = ""
                self.returncode = 0

        def _fake_run(argv, **kwargs):
            captured["argv"] = argv
            captured["kwargs"] = kwargs
            return _FakeProc()

        monkeypatch.setattr(
            "analyzer.dependency_command_runner.subprocess.run", _fake_run
        )

        runner = DependencyCommandRunner()
        out = runner.run(["pip-audit", "-r", "/tmp/req.txt"], timeout=42)

        assert isinstance(out, CommandResult)
        assert out.stdout == "{}"
        assert out.returncode == 0
        # argv 는 그대로 list 로 전달되어야 함
        assert captured["argv"] == ["pip-audit", "-r", "/tmp/req.txt"]
        kwargs = captured["kwargs"]
        # shell 키워드는 절대 True 가 아니어야 함 (없거나 False)
        assert kwargs.get("shell", False) is False
        # capture_output / text=True 로 stdout 을 텍스트로 가져옴
        assert kwargs.get("capture_output") is True
        assert kwargs.get("text") is True
        assert kwargs.get("timeout") == 42

    def test_runner_rejects_non_list_argv(self):
        runner = DependencyCommandRunner()
        with pytest.raises(ValueError):
            runner.run("pip-audit -r /tmp/x")  # type: ignore[arg-type]
        with pytest.raises(ValueError):
            runner.run([])

    def test_runner_propagates_timeout(self, monkeypatch):
        def _raise_timeout(argv, **kwargs):
            raise subprocess.TimeoutExpired(cmd=argv, timeout=kwargs.get("timeout", 0))

        monkeypatch.setattr(
            "analyzer.dependency_command_runner.subprocess.run", _raise_timeout
        )
        runner = DependencyCommandRunner()
        with pytest.raises(subprocess.TimeoutExpired):
            runner.run(["pip-audit"], timeout=1)

    def test_runner_propagates_filenotfound(self, monkeypatch):
        def _raise_fnf(argv, **kwargs):
            raise FileNotFoundError(argv[0])

        monkeypatch.setattr(
            "analyzer.dependency_command_runner.subprocess.run", _raise_fnf
        )
        runner = DependencyCommandRunner()
        with pytest.raises(FileNotFoundError):
            runner.run(["pip-audit"])


# ============================================================
# 더블 Runner — 호출 기록을 보관
# ============================================================

class _RecordingRunner:
    """argv / cwd / timeout 호출 이력을 보관하고, 사전 등록된 응답을 돌려준다."""

    def __init__(self):
        self.calls: list[dict] = []
        # key: argv[0] (e.g. "pip-audit", "npm")
        self.responses: dict[str, Any] = {}

    def queue(self, argv0: str, *, stdout: str = "", stderr: str = "", returncode: int = 0):
        self.responses.setdefault(argv0, []).append(
            CommandResult(stdout=stdout, stderr=stderr, returncode=returncode)
        )

    def queue_exc(self, argv0: str, exc: BaseException):
        self.responses.setdefault(argv0, []).append(exc)

    def run(self, argv: list[str], *, cwd: Optional[str] = None, timeout: int = 120) -> CommandResult:
        self.calls.append({"argv": list(argv), "cwd": cwd, "timeout": timeout})
        argv0 = argv[0]
        # argv 가 npm 으로 시작하지만 'npm install' 과 'npm audit' 을 구분해야 함
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
        # 기본값: 빈 stdout, returncode 0
        return CommandResult(stdout="", stderr="", returncode=0)


# ============================================================
# DependencyScanner: 실제 subprocess 미사용 + argv 형태 보존
# ============================================================

class TestScannerDoesNotCallRealSubprocess:
    def test_scanner_with_fake_runner_never_touches_subprocess(self, monkeypatch):
        """fake runner 가 주입되면 실제 ``subprocess.run`` 은 호출되지 않는다."""
        # 실제 subprocess.run 가 호출되면 즉시 실패하도록 가드
        def _boom(*a, **kw):
            raise AssertionError("실제 subprocess.run 이 호출되면 안 됩니다")

        monkeypatch.setattr(
            "analyzer.dependency_command_runner.subprocess.run", _boom
        )

        runner = _RecordingRunner()
        runner.queue("pip-audit", stdout=json.dumps({"dependencies": []}))
        scanner = DependencyScanner(runner=runner)

        result = scanner.scan_requirements_text("flask==2.0.0\n")
        assert result.tool == "pip-audit"
        assert result.error is None
        assert len(runner.calls) == 1


class TestScanRequirementsTextArgv:
    def test_pip_audit_argv_contains_required_flags(self, tmp_path):
        runner = _RecordingRunner()
        runner.queue("pip-audit", stdout=json.dumps({"dependencies": []}))
        scanner = DependencyScanner(runner=runner)

        scanner.scan_requirements_text("flask==2.0.0\n")

        assert len(runner.calls) == 1
        argv = runner.calls[0]["argv"]
        assert argv[0] == "pip-audit"
        assert "-r" in argv
        # -r 다음 인자가 임시 requirements.txt 경로여야 함
        idx = argv.index("-r")
        req_path = argv[idx + 1]
        assert req_path.endswith("requirements.txt")
        # JSON 출력 플래그
        assert "--format" in argv
        assert "json" in argv
        assert "--output" in argv
        # timeout 값 보존
        assert runner.calls[0]["timeout"] == 120


class TestScanPackageJsonTextArgv:
    def test_npm_install_then_npm_audit_in_temp_dir(self):
        """npm install --package-lock-only → npm audit --json 시퀀스가 보존된다."""
        runner = _RecordingRunner()
        # npm install 응답 (stdout 사용 안 함)
        runner.queue("npm install", stdout="", returncode=0)
        # npm audit 응답
        runner.queue(
            "npm audit",
            stdout=json.dumps({
                "vulnerabilities": {},
                "metadata": {"totalDependencies": 1},
            }),
        )
        scanner = DependencyScanner(runner=runner)

        scanner.scan_package_json_text(
            json.dumps({"dependencies": {"lodash": "4.17.0"}})
        )

        assert len(runner.calls) == 2
        first, second = runner.calls

        # 첫 호출: npm install --package-lock-only, cwd=tmp dir
        assert first["argv"] == ["npm", "install", "--package-lock-only"]
        assert first["cwd"] is not None
        assert os.path.basename(first["cwd"]).startswith("dallo_deps_") or \
            "dallo_deps_" in first["cwd"]
        assert first["timeout"] == 60

        # 두 번째 호출: npm audit --json, 같은 디렉토리
        assert second["argv"] == ["npm", "audit", "--json"]
        assert second["cwd"] == first["cwd"]
        assert second["timeout"] == 120


# ============================================================
# pip-audit JSON 파싱 (정상 / fallback / 에러)
# ============================================================

class TestPipAuditParsing:
    def _payload(self):
        return {
            "dependencies": [
                {
                    "name": "flask",
                    "version": "2.0.0",
                    "vulns": [
                        {
                            "id": "PYSEC-2023-1",
                            "fix_versions": ["2.2.5"],
                            "description": "XSS issue",
                        }
                    ],
                },
                {
                    "name": "requests",
                    "version": "2.25.0",
                    "vulns": [],
                },
            ]
        }

    def test_valid_json_parses_to_expected_shape(self):
        runner = _RecordingRunner()
        runner.queue("pip-audit", stdout=json.dumps(self._payload()))
        scanner = DependencyScanner(runner=runner)

        result = scanner.scan_requirements_text("flask==2.0.0\nrequests==2.25.0\n")
        d = result.to_dict()

        assert d["tool"] == "pip-audit"
        assert d["summary"]["total_packages"] == 2
        assert d["summary"]["total_vulnerabilities"] == 1
        # fix_versions 가 있으므로 HIGH 로 정규화
        assert d["summary"]["high"] == 1
        assert d["vulnerabilities"][0]["package"] == "flask"
        assert d["vulnerabilities"][0]["vulnerability_id"] == "PYSEC-2023-1"
        assert d["packages"] == [
            {"name": "flask", "version": "2.0.0"},
            {"name": "requests", "version": "2.25.0"},
        ]

    def test_no_stdout_with_module_not_found_falls_back(self):
        """pip-audit 미설치 (stderr 'No module named') 분기 — 한국어 에러 메시지 보존."""
        runner = _RecordingRunner()
        runner.queue(
            "pip-audit",
            stdout="",
            stderr="No module named pip_audit",
            returncode=1,
        )
        scanner = DependencyScanner(runner=runner)

        result = scanner.scan_requirements_text("flask==2.0.0\n")
        assert result.error is not None
        assert "pip-audit이 설치되어 있지 않습니다" in result.error
        # fallback 으로 패키지 목록은 채워져야 함
        assert {"name": "flask", "version": "2.0.0"} in result.packages
        assert result.total_packages == 1

    def test_no_stdout_returncode_127_falls_back(self):
        runner = _RecordingRunner()
        runner.queue("pip-audit", stdout="", stderr="", returncode=127)
        scanner = DependencyScanner(runner=runner)

        result = scanner.scan_requirements_text("requests==2.25.0\n")
        assert "pip-audit이 설치되어 있지 않습니다" in (result.error or "")
        assert {"name": "requests", "version": "2.25.0"} in result.packages

    def test_filenotfound_runner_exception_falls_back(self):
        runner = _RecordingRunner()
        runner.queue_exc("pip-audit", FileNotFoundError("pip-audit"))
        scanner = DependencyScanner(runner=runner)

        result = scanner.scan_requirements_text("flask>=2.0\n")
        assert result.error == "pip-audit 미설치"
        # fallback 이 동작해 패키지가 채워짐
        assert any(p["name"] == "flask" for p in result.packages)

    def test_timeout_exception_preserves_korean_message(self):
        runner = _RecordingRunner()
        runner.queue_exc(
            "pip-audit",
            subprocess.TimeoutExpired(cmd=["pip-audit"], timeout=120),
        )
        scanner = DependencyScanner(runner=runner)

        result = scanner.scan_requirements_text("flask==2.0.0\n")
        assert result.error == "pip-audit 시간 초과 (120초)"

    def test_invalid_json_falls_back(self):
        runner = _RecordingRunner()
        runner.queue("pip-audit", stdout="not-json{{")
        scanner = DependencyScanner(runner=runner)

        result = scanner.scan_requirements_text("flask==2.0.0\n")
        assert result.error == "pip-audit 출력 파싱 실패"
        assert any(p["name"] == "flask" for p in result.packages)


# ============================================================
# npm audit 파싱
# ============================================================

class TestNpmAuditParsing:
    def _payload(self):
        return {
            "vulnerabilities": {
                "lodash": {
                    "severity": "high",
                    "range": "<4.17.21",
                    "via": [
                        {
                            "source": 1234,
                            "title": "Prototype Pollution",
                            "url": "https://example.test/advisory/1234",
                        }
                    ],
                },
                "minimist": {
                    "severity": "moderate",
                    "range": "<1.2.6",
                    "via": [
                        {
                            "source": 5678,
                            "title": "Prototype Pollution",
                            "url": "https://example.test/advisory/5678",
                        }
                    ],
                },
            },
            "metadata": {"totalDependencies": 42},
        }

    def test_valid_json_counts_severities(self):
        runner = _RecordingRunner()
        runner.queue("npm install", stdout="", returncode=0)
        runner.queue("npm audit", stdout=json.dumps(self._payload()))
        scanner = DependencyScanner(runner=runner)

        result = scanner.scan_package_json_text(
            json.dumps({"dependencies": {"lodash": "4.17.0"}})
        )
        d = result.to_dict()

        assert d["tool"] == "npm-audit"
        assert d["summary"]["total_packages"] == 42
        assert d["summary"]["total_vulnerabilities"] == 2
        assert d["summary"]["high"] == 1
        # moderate → MEDIUM 으로 정규화
        assert d["summary"]["medium"] == 1
        ids = sorted(v["package"] for v in d["vulnerabilities"])
        assert ids == ["lodash", "minimist"]

    def test_npm_missing_yields_korean_error(self):
        runner = _RecordingRunner()
        runner.queue("npm install", stdout="", returncode=0)
        runner.queue_exc("npm audit", FileNotFoundError("npm"))
        scanner = DependencyScanner(runner=runner)

        result = scanner.scan_package_json_text(
            json.dumps({"dependencies": {}})
        )
        assert result.error == "npm이 설치되어 있지 않습니다"

    def test_npm_audit_timeout_yields_korean_error(self):
        runner = _RecordingRunner()
        runner.queue("npm install", stdout="", returncode=0)
        runner.queue_exc(
            "npm audit",
            subprocess.TimeoutExpired(cmd=["npm", "audit"], timeout=120),
        )
        scanner = DependencyScanner(runner=runner)

        result = scanner.scan_package_json_text(json.dumps({"dependencies": {}}))
        assert result.error == "npm audit 시간 초과 (120초)"


# ============================================================
# 하위 호환: 인자 없는 생성자 동작
# ============================================================

class TestBackwardCompatibility:
    def test_default_constructor_still_works(self):
        # 기본 생성자는 실제 어댑터를 자동 생성한다 (호출하기 전이라 안전).
        scanner = DependencyScanner()
        assert hasattr(scanner, "_runner")
        assert isinstance(scanner._runner, DependencyCommandRunner)


__all__: list[str] = []
