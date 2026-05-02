"""SonarQube scanner subprocess 어댑터 단위 테스트.

Wave 3-H: ``analyzer/sonar_runner.py`` 의 ``run_scan()`` 이 직접 호출하던
``subprocess.run([...])`` 외부 도구 실행 책임을 ``StaticToolCommandRunner``
어댑터로 분리한 동작을 검증한다.

- ``SonarRunner`` 는 생성자에 더블(``scanner_runner``)을 주입받으면 실제
  ``subprocess`` 호출 없이 동작해야 한다.
- ``run_scan()`` 의 argv 형태(project key, host url, project base dir)는
  유지되어야 하고, timeout 은 300초 이다.
- ``returncode == 0`` 은 True, 그 외는 False 를 반환한다.
- ``FileNotFoundError`` 는 기존 동작대로 False 반환 + 한국어 안내 출력으로
  보존된다.
- HTTP API(``is_available`` / ``get_issues`` / ``wait_for_analysis``)는 이번
  wave 범위 밖(향후 별도 어댑터)이지만, 더블 ``requests.get`` 으로 기존
  파싱/에러 분기가 그대로 살아있는지 가볍게 회귀 검증한다.
- AST: ``sonar_runner.py`` 본문에 직접 ``subprocess.run`` 호출이 없어야 하고,
  ``shell=True`` 도 어디에도 없어야 한다.
"""

from __future__ import annotations

import ast
import inspect
from typing import Any, Optional

import pytest

from analyzer.sonar_runner import SonarConfig, SonarRunner
from analyzer.static_tool_command_runner import (
    CommandResult,
    StaticToolCommandRunner,
)


# ============================================================
# 모듈 surface — shell 금지 / 직접 subprocess.run 금지
# ============================================================


def _calls_with_shell_true(tree: ast.AST) -> list[ast.Call]:
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


class TestSonarRunnerModuleSurface:
    def test_sonar_runner_no_direct_subprocess_run(self):
        """``sonar_runner.py`` 본문에 ``subprocess.run(...)`` 직접 호출 금지."""
        from analyzer import sonar_runner as mod

        tree = ast.parse(inspect.getsource(mod))
        assert _direct_subprocess_run_calls(tree) == [], (
            "subprocess.run 호출은 StaticToolCommandRunner 어댑터로 이동되어야 함"
        )

    def test_sonar_runner_no_shell_true(self):
        from analyzer import sonar_runner as mod

        tree = ast.parse(inspect.getsource(mod))
        assert _calls_with_shell_true(tree) == []

    def test_sonar_runner_no_os_system_or_eval(self):
        from analyzer import sonar_runner as mod

        src = inspect.getsource(mod)
        assert "os.system" not in src
        assert "os.popen" not in src
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                assert node.func.id not in {"eval", "exec"}

    def test_static_tool_command_runner_owns_subprocess_run(self):
        """어댑터 모듈이 여전히 정확히 한 군데에서 ``subprocess.run`` 을 호출한다."""
        from analyzer import static_tool_command_runner as mod

        tree = ast.parse(inspect.getsource(mod))
        assert len(_direct_subprocess_run_calls(tree)) == 1


# ============================================================
# 더블 Runner — argv / timeout 호출 이력을 보관
# ============================================================


class _RecordingRunner:
    """sonar-scanner argv / timeout 호출 이력을 보관하고 사전 등록된 응답을 돌려준다."""

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
        timeout: int = 120,
    ) -> CommandResult:
        self.calls.append({"argv": list(argv), "cwd": cwd, "timeout": timeout})
        if self.responses:
            item = self.responses.pop(0)
            if isinstance(item, BaseException):
                raise item
            return item
        return CommandResult(stdout="", stderr="", returncode=0)


# ============================================================
# run_scan: 실제 subprocess 미사용 + argv 형태 보존
# ============================================================


class TestRunScanDoesNotCallRealSubprocess:
    def test_run_scan_with_fake_runner_never_touches_subprocess(self, monkeypatch):
        """fake runner 가 주입되면 실제 ``subprocess.run`` 은 호출되지 않는다."""

        def _boom(*a, **kw):
            raise AssertionError("실제 subprocess.run 이 호출되면 안 됩니다")

        monkeypatch.setattr(
            "analyzer.static_tool_command_runner.subprocess.run", _boom
        )

        runner = _RecordingRunner()
        runner.queue(returncode=0)
        sonar = SonarRunner(
            config=SonarConfig(
                host_url="http://sonar.test",
                token="x",
                project_key="proj-x",
            ),
            scanner_runner=runner,
        )

        ok = sonar.run_scan("/tmp/repo")
        assert ok is True
        assert len(runner.calls) == 1

    def test_run_scan_does_not_touch_real_requests_get(self, monkeypatch):
        """run_scan() 경로는 HTTP API 를 절대 건드리지 않는다."""

        def _boom_http(*a, **kw):
            raise AssertionError("run_scan() 은 requests.get 을 호출하면 안 됩니다")

        monkeypatch.setattr("analyzer.sonar_runner.requests.get", _boom_http)

        runner = _RecordingRunner()
        runner.queue(returncode=0)
        sonar = SonarRunner(
            config=SonarConfig(host_url="http://sonar.test", token="x"),
            scanner_runner=runner,
        )

        assert sonar.run_scan("/tmp/repo") is True


class TestRunScanArgvShape:
    def test_run_scan_argv_contains_required_flags(self):
        runner = _RecordingRunner()
        runner.queue(returncode=0)
        sonar = SonarRunner(
            config=SonarConfig(
                host_url="http://sonar.test",
                token="x",
                project_key="proj-x",
            ),
            scanner_runner=runner,
        )
        sonar.run_scan("/tmp/repo")

        assert len(runner.calls) == 1
        argv = runner.calls[0]["argv"]
        assert argv[0] == "sonar-scanner"
        assert "-Dsonar.projectKey=proj-x" in argv
        assert "-Dsonar.host.url=http://sonar.test" in argv
        assert "-Dsonar.projectBaseDir=/tmp/repo" in argv
        # 어댑터에 timeout 300 으로 위임되어야 한다
        assert runner.calls[0]["timeout"] == 300

    def test_run_scan_default_project_path_is_dot(self):
        runner = _RecordingRunner()
        runner.queue(returncode=0)
        sonar = SonarRunner(
            config=SonarConfig(token="x"),
            scanner_runner=runner,
        )
        sonar.run_scan()

        argv = runner.calls[0]["argv"]
        assert "-Dsonar.projectBaseDir=." in argv

    def test_run_scan_argv_token_arg_uses_injected_token(self):
        """argv 에 token 이 포함되긴 하나 테스트 값은 토큰스럽지 않은 placeholder 다."""
        runner = _RecordingRunner()
        runner.queue(returncode=0)
        sonar = SonarRunner(
            config=SonarConfig(token="x"),
            scanner_runner=runner,
        )
        sonar.run_scan("/tmp/repo")

        argv = runner.calls[0]["argv"]
        # 정확한 값 내용은 검증하지 않음(스캐너가 어떻게 처리하는지는 본 테스트 범위 밖).
        # 다만 -Dsonar.token= 로 시작하는 인자가 1개 존재해야 한다.
        token_args = [a for a in argv if a.startswith("-Dsonar.token=")]
        assert len(token_args) == 1


# ============================================================
# run_scan: returncode / 예외 분기
# ============================================================


class TestRunScanReturnValue:
    def test_returncode_zero_returns_true(self):
        runner = _RecordingRunner()
        runner.queue(returncode=0)
        sonar = SonarRunner(
            config=SonarConfig(token=""), scanner_runner=runner
        )
        assert sonar.run_scan("/tmp/repo") is True

    def test_nonzero_returncode_returns_false(self):
        runner = _RecordingRunner()
        runner.queue(returncode=2, stderr="scan failed")
        sonar = SonarRunner(
            config=SonarConfig(token=""), scanner_runner=runner
        )
        assert sonar.run_scan("/tmp/repo") is False

    def test_filenotfound_returns_false_and_prints_korean_guidance(self, capsys):
        runner = _RecordingRunner()
        runner.queue_exc(FileNotFoundError("sonar-scanner"))
        sonar = SonarRunner(
            config=SonarConfig(token=""), scanner_runner=runner
        )

        ok = sonar.run_scan("/tmp/repo")
        out = capsys.readouterr().out

        assert ok is False
        assert "sonar-scanner가 설치되어 있지 않습니다" in out
        # 한국어 안내(설치 방법)도 그대로 출력되어야 한다
        assert "설치 방법" in out


# ============================================================
# 하위 호환: 인자 없는 / 기존 위치 인자 생성자 동작 보존
# ============================================================


class TestBackwardCompatibility:
    def test_default_constructor_still_works(self, monkeypatch):
        # SONAR_TOKEN 이 우연히 환경에 노출되어 있어도 토큰 그대로 들고 들어가는
        # 경로를 그대로 둔다(기존 동작 보존). 테스트에선 빈 값으로 둔다.
        monkeypatch.delenv("SONAR_TOKEN", raising=False)
        sonar = SonarRunner()
        assert hasattr(sonar, "_scanner_runner")
        assert isinstance(sonar._scanner_runner, StaticToolCommandRunner)
        assert sonar.config.token == ""
        assert sonar.base_url == "http://localhost:9000"

    def test_config_only_constructor_still_works(self):
        cfg = SonarConfig(host_url="http://x", token="", project_key="k")
        sonar = SonarRunner(config=cfg)
        assert sonar.config is cfg
        assert isinstance(sonar._scanner_runner, StaticToolCommandRunner)


# ============================================================
# HTTP 메서드 회귀 — 더블 requests.get 으로 기존 분기 보존 확인
# ============================================================


class _FakeResponse:
    def __init__(
        self,
        *,
        status_code: int = 200,
        json_data: Optional[dict] = None,
        raise_for_status: Optional[BaseException] = None,
    ):
        self.status_code = status_code
        self._json = json_data or {}
        self._raise = raise_for_status

    def json(self):
        return self._json

    def raise_for_status(self):
        if self._raise is not None:
            raise self._raise


class TestIsAvailable:
    def test_is_available_true_when_status_up(self, monkeypatch):
        def _fake_get(url, **kw):
            assert url.endswith("/api/system/status")
            return _FakeResponse(status_code=200, json_data={"status": "UP"})

        monkeypatch.setattr("analyzer.sonar_runner.requests.get", _fake_get)
        sonar = SonarRunner(config=SonarConfig(host_url="http://x", token=""))
        assert sonar.is_available() is True

    def test_is_available_false_when_connection_error(self, monkeypatch):
        import requests as _requests

        def _raise(url, **kw):
            raise _requests.ConnectionError("nope")

        monkeypatch.setattr("analyzer.sonar_runner.requests.get", _raise)
        sonar = SonarRunner(config=SonarConfig(host_url="http://x", token=""))
        assert sonar.is_available() is False


class TestGetIssues:
    def test_get_issues_parses_severity_mapping(self, monkeypatch):
        payload = {
            "issues": [
                {
                    "severity": "BLOCKER",
                    "rule": "python:S1",
                    "message": "msg-h",
                    "component": "proj-x:src/a.py",
                    "line": 3,
                },
                {
                    "severity": "MAJOR",
                    "rule": "python:S2",
                    "message": "msg-m",
                    "component": "proj-x:src/b.py",
                    "line": 7,
                },
                {
                    "severity": "MINOR",
                    "rule": "python:S3",
                    "message": "msg-l",
                    "component": "proj-x:src/c.py",
                    "line": 9,
                },
            ]
        }

        def _fake_get(url, **kw):
            return _FakeResponse(status_code=200, json_data=payload)

        monkeypatch.setattr("analyzer.sonar_runner.requests.get", _fake_get)
        sonar = SonarRunner(
            config=SonarConfig(host_url="http://x", token="", project_key="proj-x")
        )
        result = sonar.get_issues()

        assert result.total_issues == 3
        assert result.high_count == 1
        assert result.medium_count == 1
        assert result.low_count == 1
        # component 의 프로젝트 키 접두사가 떨어졌는지 확인
        paths = [v.file_path for v in result.vulnerabilities]
        assert "src/a.py" in paths
        assert "src/b.py" in paths

    def test_get_issues_request_exception_sets_error(self, monkeypatch):
        import requests as _requests

        def _raise(url, **kw):
            raise _requests.RequestException("boom")

        monkeypatch.setattr("analyzer.sonar_runner.requests.get", _raise)
        sonar = SonarRunner(
            config=SonarConfig(host_url="http://x", token="", project_key="p")
        )
        result = sonar.get_issues()
        assert result.total_issues == 0
        assert result.error == "boom"


class TestWaitForAnalysis:
    def test_wait_returns_true_on_success(self, monkeypatch):
        def _fake_get(url, **kw):
            return _FakeResponse(
                status_code=200,
                json_data={"tasks": [{"status": "SUCCESS"}]},
            )

        monkeypatch.setattr("analyzer.sonar_runner.requests.get", _fake_get)
        # sleep 이 호출되더라도 즉시 반환되도록 패치 (테스트 시간 단축).
        monkeypatch.setattr("analyzer.sonar_runner.time.sleep", lambda s: None)

        sonar = SonarRunner(
            config=SonarConfig(host_url="http://x", token="", project_key="p")
        )
        assert sonar.wait_for_analysis(timeout=1) is True

    def test_wait_returns_false_on_timeout(self, monkeypatch):
        # 항상 PENDING 상태만 반환 → timeout 까지 가서 False
        def _fake_get(url, **kw):
            return _FakeResponse(
                status_code=200,
                json_data={"tasks": [{"status": "PENDING"}]},
            )

        monkeypatch.setattr("analyzer.sonar_runner.requests.get", _fake_get)
        monkeypatch.setattr("analyzer.sonar_runner.time.sleep", lambda s: None)

        # time.time 을 점프시켜 timeout 즉시 도달하도록 한다
        ticks = iter([1000.0, 1000.0, 9999.0])
        monkeypatch.setattr(
            "analyzer.sonar_runner.time.time", lambda: next(ticks, 9999.0)
        )

        sonar = SonarRunner(
            config=SonarConfig(host_url="http://x", token="", project_key="p")
        )
        assert sonar.wait_for_analysis(timeout=10) is False


__all__: list[str] = []
