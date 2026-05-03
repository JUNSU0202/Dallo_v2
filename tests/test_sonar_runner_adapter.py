"""SonarQube runner 어댑터 단위 테스트.

Wave 3-H: ``analyzer/sonar_runner.py`` 의 ``run_scan()`` 이 직접 호출하던
``subprocess.run([...])`` 외부 도구 실행 책임을 ``StaticToolCommandRunner``
어댑터로 분리한 동작을 검증한다.
Wave 3-I: ``is_available`` / ``get_issues`` / ``wait_for_analysis`` 가 직접
호출하던 ``requests.get(...)`` HTTP 경계를 ``SonarHttpClient`` 어댑터로
분리한 동작을 검증한다.
Wave 3-J: ``wait_for_analysis()`` 가 직접 호출하던 ``time.time()`` /
``time.sleep()`` polling/clock 의존성을 생성자 주입형 ``clock`` / ``sleeper``
seam 으로 분리한 동작을 검증한다.

- ``SonarRunner`` 는 생성자에 더블(``scanner_runner`` / ``http_client`` /
  ``clock`` / ``sleeper``)을 주입받으면 실제 ``subprocess`` / ``requests`` /
  실제 sleep 호출 없이 동작해야 한다.
- ``run_scan()`` 의 argv 형태(project key, host url, project base dir)는
  유지되어야 하고, timeout 은 300초 이다.
- ``returncode == 0`` 은 True, 그 외는 False 를 반환한다.
- ``FileNotFoundError`` 는 기존 동작대로 False 반환 + 한국어 안내 출력으로
  보존된다.
- ``is_available`` / ``get_issues`` / ``wait_for_analysis`` 의 URL/params/
  auth/timeout 위임 형태와 응답 파싱/에러 분기를 회귀 검증한다.
- ``wait_for_analysis()`` 는 주입된 ``clock`` / ``sleeper`` 를 사용해야
  하며, 본문에서 ``time.time(`` / ``time.sleep(`` 을 직접 호출하지 않는다
  (생성자 default 참조는 허용).
- AST: ``sonar_runner.py`` 본문에 직접 ``subprocess.run`` 호출도, 직접
  ``requests.get`` 호출도 없어야 하고, ``shell=True`` 도 어디에도 없어야
  한다.
"""

from __future__ import annotations

import ast
import inspect
from typing import Any, Optional

import pytest

from analyzer.sonar_http_client import (
    HttpConnectionError,
    HttpRequestError,
    SonarHttpClient,
)
from analyzer.sonar_runner import SonarConfig, SonarRunner
from analyzer.static_tool_command_runner import (
    CommandResult,
    StaticToolCommandRunner,
)


# ============================================================
# 모듈 surface — shell 금지 / 직접 subprocess.run 금지 / 직접 requests.get 금지
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


def _direct_attr_calls(tree: ast.AST, base: str, attr: str) -> list[int]:
    lines: list[int] = []
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == attr
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == base
        ):
            lines.append(node.lineno)
    return lines


class TestSonarRunnerModuleSurface:
    def test_sonar_runner_no_direct_subprocess_run(self):
        """``sonar_runner.py`` 본문에 ``subprocess.run(...)`` 직접 호출 금지."""
        from analyzer import sonar_runner as mod

        tree = ast.parse(inspect.getsource(mod))
        assert _direct_attr_calls(tree, "subprocess", "run") == [], (
            "subprocess.run 호출은 StaticToolCommandRunner 어댑터로 이동되어야 함"
        )

    def test_sonar_runner_no_direct_requests_get(self):
        """``sonar_runner.py`` 본문에 ``requests.get(...)`` 직접 호출 금지."""
        from analyzer import sonar_runner as mod

        tree = ast.parse(inspect.getsource(mod))
        assert _direct_attr_calls(tree, "requests", "get") == [], (
            "requests.get 호출은 SonarHttpClient 어댑터로 이동되어야 함"
        )

    def test_sonar_runner_does_not_import_requests_module(self):
        """HTTP 경계가 어댑터로 분리되었으므로 ``requests`` 직접 import 도 사라져야 한다."""
        from analyzer import sonar_runner as mod

        assert not hasattr(mod, "requests"), (
            "sonar_runner 는 requests 를 직접 import 하지 않아야 함"
            " (HTTP 어댑터 경유)"
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
        assert len(_direct_attr_calls(tree, "subprocess", "run")) == 1

    def test_sonar_http_client_owns_requests_get(self):
        """HTTP 어댑터 모듈이 정확히 한 군데에서 ``requests.get`` 을 호출한다."""
        from analyzer import sonar_http_client as mod

        tree = ast.parse(inspect.getsource(mod))
        assert len(_direct_attr_calls(tree, "requests", "get")) == 1

    def test_wait_for_analysis_no_direct_time_calls(self):
        """``wait_for_analysis`` 본문에 ``time.time()`` / ``time.sleep()`` 직접 호출 금지.

        Wave 3-J: polling clock/sleeper 는 생성자에 주입된 seam 을 통해서만
        사용해야 한다. 생성자 default 참조(``time.time`` / ``time.sleep`` 그
        자체)는 호출이 아니라 attribute 참조이므로 본 검사를 통과한다.
        """
        from analyzer import sonar_runner as mod

        tree = ast.parse(inspect.getsource(mod))
        wait_fn = next(
            node for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef) and node.name == "wait_for_analysis"
        )
        assert _direct_attr_calls(wait_fn, "time", "time") == [], (
            "wait_for_analysis 는 time.time() 을 직접 호출하면 안 됨"
            " (주입된 self._clock 사용)"
        )
        assert _direct_attr_calls(wait_fn, "time", "sleep") == [], (
            "wait_for_analysis 는 time.sleep() 을 직접 호출하면 안 됨"
            " (주입된 self._sleeper 사용)"
        )


# ============================================================
# 더블 Runner / Http client — 호출 이력을 보관
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


class _RecordingHttpClient:
    """SonarHttpClient 더블 — get(...) 호출 이력 보관 + 사전 등록 응답/예외 반환."""

    def __init__(self):
        self.calls: list[dict] = []
        self.responses: list[Any] = []

    def queue(self, response: Any):
        self.responses.append(response)

    def queue_exc(self, exc: BaseException):
        self.responses.append(exc)

    def get(
        self,
        url: str,
        *,
        params: Optional[dict] = None,
        auth: Optional[tuple] = None,
        timeout: int = 30,
    ):
        self.calls.append(
            {"url": url, "params": params, "auth": auth, "timeout": timeout}
        )
        if not self.responses:
            return _FakeResponse(status_code=200, json_data={})
        item = self.responses.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item


# ============================================================
# run_scan: 실제 subprocess / 실제 HTTP 미사용 + argv 형태 보존
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
            http_client=_RecordingHttpClient(),
        )

        ok = sonar.run_scan("/tmp/repo")
        assert ok is True
        assert len(runner.calls) == 1

    def test_run_scan_does_not_touch_real_http(self, monkeypatch):
        """run_scan() 경로는 HTTP 어댑터 경계를 절대 건드리지 않는다."""

        def _boom_http(*a, **kw):
            raise AssertionError("run_scan() 은 HTTP 어댑터를 호출하면 안 됩니다")

        # 실제 requests.get 도 차단해서 이중 안전장치를 둔다.
        monkeypatch.setattr(
            "analyzer.sonar_http_client.requests.get", _boom_http
        )

        http = _RecordingHttpClient()
        # 만약 호출되면 즉시 실패하도록 큐에 예외를 넣어둔다.
        http.queue_exc(AssertionError("run_scan() 은 http_client.get 을 호출하면 안 됩니다"))

        runner = _RecordingRunner()
        runner.queue(returncode=0)
        sonar = SonarRunner(
            config=SonarConfig(host_url="http://sonar.test", token="x"),
            scanner_runner=runner,
            http_client=http,
        )

        assert sonar.run_scan("/tmp/repo") is True
        assert http.calls == []


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
            http_client=_RecordingHttpClient(),
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
            http_client=_RecordingHttpClient(),
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
            http_client=_RecordingHttpClient(),
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
            config=SonarConfig(token=""),
            scanner_runner=runner,
            http_client=_RecordingHttpClient(),
        )
        assert sonar.run_scan("/tmp/repo") is True

    def test_nonzero_returncode_returns_false(self):
        runner = _RecordingRunner()
        runner.queue(returncode=2, stderr="scan failed")
        sonar = SonarRunner(
            config=SonarConfig(token=""),
            scanner_runner=runner,
            http_client=_RecordingHttpClient(),
        )
        assert sonar.run_scan("/tmp/repo") is False

    def test_filenotfound_returns_false_and_prints_korean_guidance(self, capsys):
        runner = _RecordingRunner()
        runner.queue_exc(FileNotFoundError("sonar-scanner"))
        sonar = SonarRunner(
            config=SonarConfig(token=""),
            scanner_runner=runner,
            http_client=_RecordingHttpClient(),
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
        assert hasattr(sonar, "_http_client")
        assert isinstance(sonar._scanner_runner, StaticToolCommandRunner)
        assert isinstance(sonar._http_client, SonarHttpClient)
        # Wave 3-J: 기본 clock/sleeper 는 ``time`` 모듈의 함수로 채워진다.
        assert callable(sonar._clock)
        assert callable(sonar._sleeper)
        assert sonar.config.token == ""
        assert sonar.base_url == "http://localhost:9000"

    def test_config_only_constructor_still_works(self):
        cfg = SonarConfig(host_url="http://x", token="", project_key="k")
        sonar = SonarRunner(config=cfg)
        assert sonar.config is cfg
        assert isinstance(sonar._scanner_runner, StaticToolCommandRunner)
        assert isinstance(sonar._http_client, SonarHttpClient)
        assert callable(sonar._clock)
        assert callable(sonar._sleeper)

    def test_config_and_scanner_runner_constructor_still_works(self):
        runner = _RecordingRunner()
        sonar = SonarRunner(
            config=SonarConfig(token=""),
            scanner_runner=runner,
        )
        assert sonar._scanner_runner is runner
        # http_client / clock / sleeper 는 기본값으로 채워진다
        assert isinstance(sonar._http_client, SonarHttpClient)
        assert callable(sonar._clock)
        assert callable(sonar._sleeper)


# ============================================================
# is_available — URL / 응답 파싱 / ConnectionError 분기 보존
# ============================================================


class TestIsAvailable:
    def test_is_available_true_when_status_up(self):
        http = _RecordingHttpClient()
        http.queue(_FakeResponse(status_code=200, json_data={"status": "UP"}))
        sonar = SonarRunner(
            config=SonarConfig(host_url="http://x", token=""),
            http_client=http,
        )

        assert sonar.is_available() is True
        assert len(http.calls) == 1
        call = http.calls[0]
        assert call["url"] == "http://x/api/system/status"
        assert call["timeout"] == 5

    def test_is_available_false_when_status_not_up(self):
        http = _RecordingHttpClient()
        http.queue(_FakeResponse(status_code=200, json_data={"status": "DOWN"}))
        sonar = SonarRunner(
            config=SonarConfig(host_url="http://x", token=""),
            http_client=http,
        )
        assert sonar.is_available() is False

    def test_is_available_false_when_non_200(self):
        http = _RecordingHttpClient()
        http.queue(_FakeResponse(status_code=503, json_data={"status": "UP"}))
        sonar = SonarRunner(
            config=SonarConfig(host_url="http://x", token=""),
            http_client=http,
        )
        assert sonar.is_available() is False

    def test_is_available_false_when_connection_error(self):
        http = _RecordingHttpClient()
        http.queue_exc(HttpConnectionError("nope"))
        sonar = SonarRunner(
            config=SonarConfig(host_url="http://x", token=""),
            http_client=http,
        )
        assert sonar.is_available() is False


# ============================================================
# get_issues — params / auth / timeout 위임 + 응답 파싱 + 에러 분기
# ============================================================


class TestGetIssues:
    def test_get_issues_passes_url_params_auth_timeout(self):
        http = _RecordingHttpClient()
        http.queue(_FakeResponse(status_code=200, json_data={"issues": []}))
        sonar = SonarRunner(
            config=SonarConfig(host_url="http://x", token="", project_key="proj-x"),
            http_client=http,
        )

        result = sonar.get_issues(severity="MAJOR")

        assert result.total_issues == 0
        assert len(http.calls) == 1
        call = http.calls[0]
        assert call["url"] == "http://x/api/issues/search"
        assert call["timeout"] == 30
        assert call["auth"] == ("", "")
        assert call["params"]["componentKeys"] == "proj-x"
        assert call["params"]["ps"] == 100
        assert call["params"]["types"] == "VULNERABILITY,BUG,CODE_SMELL"
        assert call["params"]["severities"] == "MAJOR"

    def test_get_issues_omits_severities_when_not_filtered(self):
        http = _RecordingHttpClient()
        http.queue(_FakeResponse(status_code=200, json_data={"issues": []}))
        sonar = SonarRunner(
            config=SonarConfig(host_url="http://x", token="", project_key="p"),
            http_client=http,
        )
        sonar.get_issues()
        assert "severities" not in http.calls[0]["params"]

    def test_get_issues_parses_severity_mapping(self):
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
        http = _RecordingHttpClient()
        http.queue(_FakeResponse(status_code=200, json_data=payload))
        sonar = SonarRunner(
            config=SonarConfig(host_url="http://x", token="", project_key="proj-x"),
            http_client=http,
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

    def test_get_issues_request_exception_sets_error(self):
        http = _RecordingHttpClient()
        http.queue_exc(HttpRequestError("boom"))
        sonar = SonarRunner(
            config=SonarConfig(host_url="http://x", token="", project_key="p"),
            http_client=http,
        )
        result = sonar.get_issues()
        assert result.total_issues == 0
        assert result.error == "boom"

    def test_get_issues_raise_for_status_propagates_to_error(self):
        """``raise_for_status()`` 가 ``HttpRequestError`` 를 던지면 result.error 에 잡힌다."""
        http = _RecordingHttpClient()
        http.queue(
            _FakeResponse(
                status_code=500,
                json_data={"issues": []},
                raise_for_status=HttpRequestError("500"),
            )
        )
        sonar = SonarRunner(
            config=SonarConfig(host_url="http://x", token="", project_key="p"),
            http_client=http,
        )
        result = sonar.get_issues()
        assert result.total_issues == 0
        assert result.error == "500"


# ============================================================
# wait_for_analysis — params / auth / timeout 위임 + sleep 미차단
# ============================================================


class _FakeClock:
    """단조 증가하는 가짜 clock — 호출마다 미리 등록된 ticks 를 순서대로 반환."""

    def __init__(self, ticks: list[float]):
        self._ticks = list(ticks)
        self._last = ticks[-1] if ticks else 0.0

    def __call__(self) -> float:
        if self._ticks:
            self._last = self._ticks.pop(0)
        return self._last


class _FakeSleeper:
    """sleep 인자를 기록만 하고 실제 sleep 하지 않는 가짜 sleeper."""

    def __init__(self):
        self.calls: list[float] = []

    def __call__(self, seconds: float) -> None:
        self.calls.append(seconds)


class TestWaitForAnalysis:
    def test_wait_passes_url_params_auth_timeout(self):
        http = _RecordingHttpClient()
        http.queue(
            _FakeResponse(status_code=200, json_data={"tasks": [{"status": "SUCCESS"}]})
        )

        sonar = SonarRunner(
            config=SonarConfig(host_url="http://x", token="", project_key="p"),
            http_client=http,
            clock=_FakeClock([0.0, 0.0]),
            sleeper=_FakeSleeper(),
        )
        assert sonar.wait_for_analysis(timeout=1) is True

        call = http.calls[0]
        assert call["url"] == "http://x/api/ce/activity"
        assert call["timeout"] == 10
        assert call["auth"] == ("", "")
        assert call["params"]["component"] == "p"
        assert call["params"]["ps"] == 1
        assert call["params"]["onlyCurrents"] == "true"

    def test_wait_returns_true_on_success(self):
        http = _RecordingHttpClient()
        http.queue(
            _FakeResponse(status_code=200, json_data={"tasks": [{"status": "SUCCESS"}]})
        )
        sleeper = _FakeSleeper()

        sonar = SonarRunner(
            config=SonarConfig(host_url="http://x", token="", project_key="p"),
            http_client=http,
            clock=_FakeClock([0.0, 0.0]),
            sleeper=sleeper,
        )
        assert sonar.wait_for_analysis(timeout=1) is True
        # 첫 시도에서 SUCCESS 를 잡았으므로 sleep 은 호출되지 않는다.
        assert sleeper.calls == []

    def test_wait_returns_false_on_timeout(self):
        # 항상 PENDING 상태만 반환 → timeout 까지 가서 False
        http = _RecordingHttpClient()
        for _ in range(5):
            http.queue(
                _FakeResponse(
                    status_code=200,
                    json_data={"tasks": [{"status": "PENDING"}]},
                )
            )
        sleeper = _FakeSleeper()
        # start=1000.0, 두 번째 clock 호출에서 9999.0 으로 점프 → 즉시 timeout.
        clock = _FakeClock([1000.0, 9999.0])

        sonar = SonarRunner(
            config=SonarConfig(host_url="http://x", token="", project_key="p"),
            http_client=http,
            clock=clock,
            sleeper=sleeper,
        )
        assert sonar.wait_for_analysis(timeout=10) is False
        # 첫 루프에 진입조차 안 했으므로 HTTP 호출도, sleep 도 일어나지 않는다.
        assert http.calls == []
        assert sleeper.calls == []

    def test_wait_swallows_request_exception_and_keeps_polling(self):
        """첫 응답이 ``HttpRequestError`` 면 삼키고 다음 폴링에서 SUCCESS 를 잡는다."""
        http = _RecordingHttpClient()
        http.queue_exc(HttpRequestError("transient"))
        http.queue(
            _FakeResponse(status_code=200, json_data={"tasks": [{"status": "SUCCESS"}]})
        )
        sleeper = _FakeSleeper()

        sonar = SonarRunner(
            config=SonarConfig(host_url="http://x", token="", project_key="p"),
            http_client=http,
            clock=_FakeClock([0.0, 0.0, 0.0]),
            sleeper=sleeper,
        )
        assert sonar.wait_for_analysis(timeout=10) is True
        assert len(http.calls) == 2
        # 첫 시도 실패 후 1회 sleep, 두 번째 시도에서 SUCCESS.
        assert sleeper.calls == [5]


# ============================================================
# Wave 3-J: polling clock / sleeper seam — 주입된 더블만 사용
# ============================================================


class TestPollingClockInjection:
    def test_constructor_accepts_clock_and_sleeper(self):
        clock = _FakeClock([0.0])
        sleeper = _FakeSleeper()
        sonar = SonarRunner(
            config=SonarConfig(token=""),
            clock=clock,
            sleeper=sleeper,
        )
        assert sonar._clock is clock
        assert sonar._sleeper is sleeper

    def test_wait_uses_injected_sleeper_not_real_sleep(self, monkeypatch):
        """주입된 ``sleeper`` 가 사용되며, 실제 ``time.sleep`` 은 호출되지 않는다."""

        def _boom(*a, **kw):
            raise AssertionError("실제 time.sleep 이 호출되면 안 됩니다")

        # 모듈 레벨 ``time.sleep`` 을 차단 — 주입된 sleeper 만 호출되어야 한다.
        monkeypatch.setattr("analyzer.sonar_runner.time.sleep", _boom)

        http = _RecordingHttpClient()
        http.queue(
            _FakeResponse(status_code=200, json_data={"tasks": [{"status": "PENDING"}]})
        )
        http.queue(
            _FakeResponse(status_code=200, json_data={"tasks": [{"status": "SUCCESS"}]})
        )
        sleeper = _FakeSleeper()

        sonar = SonarRunner(
            config=SonarConfig(host_url="http://x", token="", project_key="p"),
            http_client=http,
            clock=_FakeClock([0.0, 0.0, 0.0]),
            sleeper=sleeper,
        )
        assert sonar.wait_for_analysis(timeout=30) is True
        # PENDING → sleep(5) → SUCCESS. 정확히 한 번 sleep.
        assert sleeper.calls == [5]

    def test_wait_uses_injected_clock_not_real_time(self, monkeypatch):
        """주입된 ``clock`` 이 사용되며, 실제 ``time.time`` 은 호출되지 않는다."""

        def _boom():
            raise AssertionError("실제 time.time 이 호출되면 안 됩니다")

        monkeypatch.setattr("analyzer.sonar_runner.time.time", _boom)

        http = _RecordingHttpClient()
        http.queue(
            _FakeResponse(status_code=200, json_data={"tasks": [{"status": "SUCCESS"}]})
        )

        sonar = SonarRunner(
            config=SonarConfig(host_url="http://x", token="", project_key="p"),
            http_client=http,
            clock=_FakeClock([10.0, 10.0]),
            sleeper=_FakeSleeper(),
        )
        assert sonar.wait_for_analysis(timeout=5) is True

    def test_wait_success_first_attempt_no_sleep(self):
        http = _RecordingHttpClient()
        http.queue(
            _FakeResponse(status_code=200, json_data={"tasks": [{"status": "SUCCESS"}]})
        )
        sleeper = _FakeSleeper()
        sonar = SonarRunner(
            config=SonarConfig(host_url="http://x", token="", project_key="p"),
            http_client=http,
            clock=_FakeClock([0.0, 0.0]),
            sleeper=sleeper,
        )
        assert sonar.wait_for_analysis(timeout=120) is True
        assert sleeper.calls == []
        assert len(http.calls) == 1

    def test_wait_success_second_attempt_one_sleep(self):
        http = _RecordingHttpClient()
        http.queue(
            _FakeResponse(status_code=200, json_data={"tasks": [{"status": "PENDING"}]})
        )
        http.queue(
            _FakeResponse(status_code=200, json_data={"tasks": [{"status": "SUCCESS"}]})
        )
        sleeper = _FakeSleeper()
        sonar = SonarRunner(
            config=SonarConfig(host_url="http://x", token="", project_key="p"),
            http_client=http,
            clock=_FakeClock([0.0, 0.0, 0.0]),
            sleeper=sleeper,
        )
        assert sonar.wait_for_analysis(timeout=120) is True
        assert sleeper.calls == [5]
        assert len(http.calls) == 2

    def test_wait_timeout_path_no_real_sleep(self, monkeypatch):
        """타임아웃 경로에서도 실제 sleep 은 호출되지 않아야 한다."""

        def _boom(*a, **kw):
            raise AssertionError("실제 time.sleep 이 호출되면 안 됩니다")

        monkeypatch.setattr("analyzer.sonar_runner.time.sleep", _boom)

        http = _RecordingHttpClient()
        http.queue(
            _FakeResponse(status_code=200, json_data={"tasks": [{"status": "PENDING"}]})
        )
        sleeper = _FakeSleeper()
        # start=0.0, 두 번째 호출에서 1000.0 으로 점프하여 timeout 직후 종료.
        clock = _FakeClock([0.0, 1000.0])

        sonar = SonarRunner(
            config=SonarConfig(host_url="http://x", token="", project_key="p"),
            http_client=http,
            clock=clock,
            sleeper=sleeper,
        )
        assert sonar.wait_for_analysis(timeout=5) is False


__all__: list[str] = []
