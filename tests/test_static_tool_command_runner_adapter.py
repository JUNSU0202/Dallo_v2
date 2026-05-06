"""정적 분석 도구 외부 명령 어댑터 단위 테스트.

Wave 3-G: ``analyzer/static_tool_command_runner.py`` 와 ``BanditRunner`` /
``SemgrepRunner`` 의 어댑터 분리 동작을 검증한다.

- 어댑터(Runner)는 list-argv 만 사용하고 ``shell=True`` 를 절대 쓰지 않는다.
- ``BanditRunner`` / ``SemgrepRunner`` 는 ``runner`` 더블을 주입받으면 실제
  ``subprocess`` 호출 없이 동작해야 한다.
- bandit / semgrep argv 가 기존 형태(commands, flags)를 유지해야 한다.
- bandit 미설치 / 출력 없음 / JSON 파싱 실패 / FileNotFoundError /
  TimeoutExpired 등 기존 에러 메시지(한국어) 분기가 그대로 보존되어야 한다.
- 어댑터/runner 어디에도 ``shell=True`` 또는 문자열 명령 실행이 등장하지
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

from analyzer.static_tool_command_runner import (
    CommandResult,
    StaticToolCommandRunner,
)
from analyzer.bandit_runner import BanditRunner
from analyzer.semgrep_runner import SemgrepRunner


# ============================================================
# 어댑터 모듈 surface — shell 금지, subprocess 사용 형태
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
        from analyzer import static_tool_command_runner as mod

        tree = ast.parse(inspect.getsource(mod))
        assert _calls_with_shell_true(tree) == [], "shell=True 호출 금지"

    def test_runner_module_does_not_use_os_system_or_eval(self):
        from analyzer import static_tool_command_runner as mod

        src = inspect.getsource(mod)
        assert "os.system" not in src
        assert "os.popen" not in src
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                assert node.func.id not in {"eval", "exec"}

    def test_bandit_module_no_longer_uses_subprocess_run_directly(self):
        """``bandit_runner.py`` 본문에 ``subprocess.run(...)`` 직접 호출이 없어야 한다.

        ``subprocess`` 모듈 자체는 ``TimeoutExpired`` 사용을 위해 import 가
        남을 수 있다.
        """
        from analyzer import bandit_runner as mod

        tree = ast.parse(inspect.getsource(mod))
        assert _direct_subprocess_run_calls(tree) == [], (
            "subprocess.run 호출은 StaticToolCommandRunner 어댑터로 이동되어야 함"
        )

    def test_semgrep_module_no_longer_uses_subprocess_run_directly(self):
        from analyzer import semgrep_runner as mod

        tree = ast.parse(inspect.getsource(mod))
        assert _direct_subprocess_run_calls(tree) == [], (
            "subprocess.run 호출은 StaticToolCommandRunner 어댑터로 이동되어야 함"
        )

    def test_bandit_module_no_shell_true(self):
        from analyzer import bandit_runner as mod

        tree = ast.parse(inspect.getsource(mod))
        assert _calls_with_shell_true(tree) == []

    def test_semgrep_module_no_shell_true(self):
        from analyzer import semgrep_runner as mod

        tree = ast.parse(inspect.getsource(mod))
        assert _calls_with_shell_true(tree) == []

    def test_adapter_module_owns_single_subprocess_run(self):
        """어댑터 모듈에는 정확히 한 곳에서만 ``subprocess.run`` 을 호출해야 한다."""
        from analyzer import static_tool_command_runner as mod

        tree = ast.parse(inspect.getsource(mod))
        assert len(_direct_subprocess_run_calls(tree)) == 1


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


class TestStaticToolCommandRunnerCallShape:
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
            "analyzer.static_tool_command_runner.subprocess.run", _fake_run
        )

        runner = StaticToolCommandRunner()
        out = runner.run(
            ["bandit", "-r", "/tmp/code"], cwd="/tmp/work", timeout=42
        )

        assert isinstance(out, CommandResult)
        assert out.stdout == "{}"
        assert out.returncode == 0
        # argv 는 그대로 list 로 전달되어야 함
        assert captured["argv"] == ["bandit", "-r", "/tmp/code"]
        kwargs = captured["kwargs"]
        # shell 키워드는 절대 True 가 아니어야 함 (없거나 False)
        assert kwargs.get("shell", False) is False
        # capture_output / text=True 로 stdout 을 텍스트로 가져옴
        assert kwargs.get("capture_output") is True
        assert kwargs.get("text") is True
        assert kwargs.get("timeout") == 42
        assert kwargs.get("cwd") == "/tmp/work"

    def test_runner_default_timeout_is_120(self, monkeypatch):
        captured: dict = {}

        class _FakeProc:
            stdout = ""
            stderr = ""
            returncode = 0

        def _fake_run(argv, **kwargs):
            captured["kwargs"] = kwargs
            return _FakeProc()

        monkeypatch.setattr(
            "analyzer.static_tool_command_runner.subprocess.run", _fake_run
        )

        runner = StaticToolCommandRunner()
        runner.run(["bandit"])
        assert captured["kwargs"].get("timeout") == 120

    def test_runner_rejects_non_list_argv(self):
        runner = StaticToolCommandRunner()
        with pytest.raises(ValueError):
            runner.run("bandit -r /tmp/x")  # type: ignore[arg-type]
        with pytest.raises(ValueError):
            runner.run([])

    def test_runner_propagates_timeout(self, monkeypatch):
        def _raise_timeout(argv, **kwargs):
            raise subprocess.TimeoutExpired(cmd=argv, timeout=kwargs.get("timeout", 0))

        monkeypatch.setattr(
            "analyzer.static_tool_command_runner.subprocess.run", _raise_timeout
        )
        runner = StaticToolCommandRunner()
        with pytest.raises(subprocess.TimeoutExpired):
            runner.run(["bandit"], timeout=1)

    def test_runner_propagates_filenotfound(self, monkeypatch):
        def _raise_fnf(argv, **kwargs):
            raise FileNotFoundError(argv[0])

        monkeypatch.setattr(
            "analyzer.static_tool_command_runner.subprocess.run", _raise_fnf
        )
        runner = StaticToolCommandRunner()
        with pytest.raises(FileNotFoundError):
            runner.run(["bandit"])

    def test_runner_normalizes_none_streams_to_empty_strings(self, monkeypatch):
        class _FakeProc:
            stdout = None
            stderr = None
            returncode = 0

        monkeypatch.setattr(
            "analyzer.static_tool_command_runner.subprocess.run",
            lambda argv, **kw: _FakeProc(),
        )
        runner = StaticToolCommandRunner()
        out = runner.run(["bandit"])
        assert out.stdout == ""
        assert out.stderr == ""


# ============================================================
# 더블 Runner — 호출 기록을 보관
# ============================================================

class _RecordingRunner:
    """argv / cwd / timeout 호출 이력을 보관하고, 사전 등록된 응답을 돌려준다."""

    def __init__(self):
        self.calls: list[dict] = []
        # key: argv[0] (e.g. "bandit", "semgrep")
        self.responses: dict[str, Any] = {}

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
        self.calls.append(
            {"argv": list(argv), "cwd": cwd, "timeout": timeout, "env": env}
        )
        argv0 = argv[0]
        if argv0 in self.responses and self.responses[argv0]:
            item = self.responses[argv0].pop(0)
            if isinstance(item, BaseException):
                raise item
            return item
        return CommandResult(stdout="", stderr="", returncode=0)


# ============================================================
# BanditRunner: 실제 subprocess 미사용 + argv 형태 보존
# ============================================================

class TestBanditRunnerDoesNotCallRealSubprocess:
    def test_bandit_runner_with_fake_runner_never_touches_subprocess(self, monkeypatch):
        """fake runner 가 주입되면 실제 ``subprocess.run`` 은 호출되지 않는다."""
        def _boom(*a, **kw):
            raise AssertionError("실제 subprocess.run 이 호출되면 안 됩니다")

        monkeypatch.setattr(
            "analyzer.static_tool_command_runner.subprocess.run", _boom
        )

        runner = _RecordingRunner()
        runner.queue(
            "bandit",
            stdout=json.dumps({"results": [], "metrics": {"_totals": {}}}),
        )
        bandit = BanditRunner(runner=runner)

        result = bandit.run("/tmp/target")
        assert result.tool == "bandit"
        assert result.error is None
        assert len(runner.calls) == 1


class TestBanditArgvShape:
    def test_bandit_argv_contains_required_flags(self, tmp_path):
        runner = _RecordingRunner()
        runner.queue(
            "bandit",
            stdout=json.dumps({"results": [], "metrics": {"_totals": {}}}),
        )
        # 존재하지 않는 config 경로 → -c 플래그 미포함
        bandit = BanditRunner(
            config_path=str(tmp_path / "no_such.yml"),
            runner=runner,
        )
        bandit.run("/tmp/target")

        assert len(runner.calls) == 1
        argv = runner.calls[0]["argv"]
        assert argv[0] == "bandit"
        assert "-r" in argv
        # -r 다음 인자가 target 경로
        idx = argv.index("-r")
        assert argv[idx + 1] == "/tmp/target"
        assert "-f" in argv
        f_idx = argv.index("-f")
        assert argv[f_idx + 1] == "json"
        assert "-q" in argv
        assert "--confidence-level" in argv
        assert "--severity-level" in argv
        # config 미존재 → -c 미포함
        assert "-c" not in argv
        # timeout 보존
        assert runner.calls[0]["timeout"] == 120

    def test_bandit_argv_includes_config_when_file_exists(self, tmp_path):
        cfg = tmp_path / "bandit.yml"
        cfg.write_text("# cfg\n", encoding="utf-8")

        runner = _RecordingRunner()
        runner.queue(
            "bandit",
            stdout=json.dumps({"results": [], "metrics": {"_totals": {}}}),
        )
        bandit = BanditRunner(config_path=str(cfg), runner=runner)
        bandit.run("/tmp/target")

        argv = runner.calls[0]["argv"]
        assert "-c" in argv
        idx = argv.index("-c")
        assert argv[idx + 1] == str(cfg)


# ============================================================
# BanditRunner: 결과 파싱 / 에러 분기
# ============================================================

class TestBanditParsing:
    def _payload(self):
        return {
            "results": [
                {
                    "test_id": "B608",
                    "test_name": "hardcoded_sql",
                    "issue_severity": "HIGH",
                    "issue_confidence": "HIGH",
                    "issue_text": "SQL injection",
                    "filename": "x.py",
                    "line_number": 12,
                    "code": "x=1",
                    "more_info": "https://example.test/B608",
                    "issue_cwe": {"id": 89},
                }
            ],
            "metrics": {"_totals": {"SEVERITY.HIGH": 1, "SEVERITY.MEDIUM": 0, "SEVERITY.LOW": 0}},
        }

    def test_valid_json_parses_to_expected_shape(self):
        runner = _RecordingRunner()
        runner.queue("bandit", stdout=json.dumps(self._payload()))
        bandit = BanditRunner(runner=runner)

        result = bandit.run("/tmp/target")
        d = result.to_dict()

        assert d["tool"] == "bandit"
        assert d["summary"]["total"] == 1
        assert d["summary"]["high"] == 1
        assert d["vulnerabilities"][0]["rule_id"] == "B608"
        assert d["vulnerabilities"][0]["cwe_id"] == "CWE-89"

    def test_progress_bar_prefix_is_recovered(self):
        """stdout 앞에 progress bar 같은 비-JSON 접두사가 있어도 파싱 성공."""
        noisy = (
            "Working... ━━━ 100%\n"
            + json.dumps(self._payload())
        )
        runner = _RecordingRunner()
        runner.queue("bandit", stdout=noisy)
        bandit = BanditRunner(runner=runner)

        result = bandit.run("/tmp/target")
        assert result.error is None
        assert result.total_issues == 1

    def test_no_stdout_uses_stderr_as_error(self):
        runner = _RecordingRunner()
        runner.queue("bandit", stdout="", stderr="boom\n", returncode=1)
        bandit = BanditRunner(runner=runner)

        result = bandit.run("/tmp/target")
        assert result.error == "boom"
        assert result.total_issues == 0

    def test_timeout_exception_preserves_korean_message(self):
        runner = _RecordingRunner()
        runner.queue_exc(
            "bandit",
            subprocess.TimeoutExpired(cmd=["bandit"], timeout=120),
        )
        bandit = BanditRunner(runner=runner)

        result = bandit.run("/tmp/target")
        assert result.error == "Bandit 분석 시간 초과 (120초)"

    def test_filenotfound_preserves_korean_message(self):
        runner = _RecordingRunner()
        runner.queue_exc("bandit", FileNotFoundError("bandit"))
        bandit = BanditRunner(runner=runner)

        result = bandit.run("/tmp/target")
        assert result.error is not None
        assert "Bandit이 설치되어 있지 않습니다" in result.error

    def test_invalid_json_yields_korean_error(self):
        runner = _RecordingRunner()
        runner.queue("bandit", stdout="not-json{{")
        bandit = BanditRunner(runner=runner)

        result = bandit.run("/tmp/target")
        assert result.error is not None
        assert "Bandit 출력 JSON 파싱 실패" in result.error


# ============================================================
# BanditRunner: child env sanitizer (Wave 4-F)
# ============================================================

class TestBanditChildEnvSanitizer:
    """Wave 4-F: BanditRunner 가 부모 환경을 그대로 상속시키지 않고
    ``build_child_env`` 로 sanitize 한 env 를 child 에 전달하는지 검증.

    실제 subprocess 호출 없이 monkeypatch 로 ``os.environ`` 만 교체한 상태에서
    ``_RecordingRunner`` 의 호출 기록을 확인한다. 값은 짧은 placeholder 만
    사용해 실제 시크릿이 테스트에 노출되지 않도록 한다.
    """

    def _ambient_parent_env(self) -> dict[str, str]:
        return {
            # 필수 (allowlist 통과)
            "PATH": "/usr/bin",
            "HOME": "/tmp/home",
            "LANG": "C.UTF-8",
            "VIRTUAL_ENV": "/tmp/venv",
            "PYTHONPATH": "/tmp/site",
            "HTTP_PROXY": "http://proxy:3128",
            "CI": "true",
            # ambient 시크릿 (deny 되어야 함)
            "ANTHROPIC_API_KEY": "x",
            "GITHUB_TOKEN": "x",
            "AWS_SECRET_ACCESS_KEY": "x",
            "NPM_TOKEN": "x",
            "DATABASE_URL": "x",
        }

    def _run_bandit_with_ambient_env(self, monkeypatch) -> dict:
        monkeypatch.setattr(os, "environ", self._ambient_parent_env())

        runner = _RecordingRunner()
        runner.queue(
            "bandit",
            stdout=json.dumps({"results": [], "metrics": {"_totals": {}}}),
        )
        bandit = BanditRunner(runner=runner)
        bandit.run("/tmp/target")

        assert len(runner.calls) == 1
        return runner.calls[0]

    def test_bandit_child_env_is_not_none(self, monkeypatch):
        call = self._run_bandit_with_ambient_env(monkeypatch)
        assert call["env"] is not None
        assert isinstance(call["env"], dict)

    def test_bandit_child_env_strips_ambient_secrets(self, monkeypatch):
        call = self._run_bandit_with_ambient_env(monkeypatch)
        env = call["env"]
        for secret_key in (
            "ANTHROPIC_API_KEY",
            "GITHUB_TOKEN",
            "AWS_SECRET_ACCESS_KEY",
            "NPM_TOKEN",
            "DATABASE_URL",
        ):
            assert secret_key not in env, (
                f"{secret_key} 는 child env 에서 제거되어야 합니다"
            )

    def test_bandit_child_env_preserves_required_vars(self, monkeypatch):
        call = self._run_bandit_with_ambient_env(monkeypatch)
        env = call["env"]
        for required in (
            "PATH",
            "HOME",
            "LANG",
            "VIRTUAL_ENV",
            "PYTHONPATH",
            "HTTP_PROXY",
            "CI",
        ):
            assert required in env, (
                f"{required} 는 child env 에 보존되어야 합니다"
            )

    def test_bandit_child_env_does_not_inject_sonar_token(self, monkeypatch):
        """Wave 4-E 에서 Sonar 전용으로 추가했던 ``SONAR_TOKEN`` extras 가
        Bandit child env 에는 주입되지 않아야 한다."""
        call = self._run_bandit_with_ambient_env(monkeypatch)
        assert "SONAR_TOKEN" not in call["env"]


# ============================================================
# SemgrepRunner: 실제 subprocess 미사용 + argv 형태 보존
# ============================================================

class TestSemgrepRunnerDoesNotCallRealSubprocess:
    def test_semgrep_runner_with_fake_runner_never_touches_subprocess(self, monkeypatch):
        def _boom(*a, **kw):
            raise AssertionError("실제 subprocess.run 이 호출되면 안 됩니다")

        monkeypatch.setattr(
            "analyzer.static_tool_command_runner.subprocess.run", _boom
        )

        runner = _RecordingRunner()
        runner.queue("semgrep", stdout=json.dumps({"results": []}))
        semgrep = SemgrepRunner(runner=runner)

        result = semgrep.run("/tmp/code.py")
        assert result.tool == "semgrep"
        assert result.error is None
        assert len(runner.calls) == 1


class TestSemgrepArgvShape:
    def test_semgrep_argv_contains_required_flags(self):
        runner = _RecordingRunner()
        runner.queue("semgrep", stdout=json.dumps({"results": []}))
        semgrep = SemgrepRunner(config="auto", runner=runner)
        semgrep.run("/tmp/code.py")

        assert len(runner.calls) == 1
        argv = runner.calls[0]["argv"]
        assert argv[0] == "semgrep"
        assert "--config" in argv
        c_idx = argv.index("--config")
        assert argv[c_idx + 1] == "auto"
        assert "--json" in argv
        assert "--quiet" in argv
        # 마지막 인자(또는 어딘가)에 target 경로 포함
        assert "/tmp/code.py" in argv
        assert runner.calls[0]["timeout"] == 120

    def test_semgrep_argv_uses_custom_config(self):
        runner = _RecordingRunner()
        runner.queue("semgrep", stdout=json.dumps({"results": []}))
        semgrep = SemgrepRunner(config="p/owasp-top-ten", runner=runner)
        semgrep.run("/tmp/code.java")

        argv = runner.calls[0]["argv"]
        c_idx = argv.index("--config")
        assert argv[c_idx + 1] == "p/owasp-top-ten"


# ============================================================
# SemgrepRunner: 결과 파싱 / 에러 분기
# ============================================================

class TestSemgrepParsing:
    def _payload(self):
        return {
            "results": [
                {
                    "check_id": "python.lang.security.dangerous-eval",
                    "path": "x.py",
                    "start": {"line": 5},
                    "end": {"line": 5},
                    "extra": {
                        "severity": "ERROR",
                        "message": "Dangerous eval",
                        "metadata": {
                            "cwe": ["CWE-95: Improper Neutralization"],
                            "source": "https://example.test/eval",
                        },
                        "lines": "result = compute(user_input)" + "x" * 30,  # 길이 충분
                    },
                }
            ]
        }

    def test_valid_json_parses_severity_and_cwe(self):
        runner = _RecordingRunner()
        runner.queue("semgrep", stdout=json.dumps(self._payload()))
        semgrep = SemgrepRunner(runner=runner)

        result = semgrep.run("/tmp/x.py")
        d = result.to_dict()

        assert d["tool"] == "semgrep"
        assert d["summary"]["total"] == 1
        # ERROR → HIGH
        assert d["summary"]["high"] == 1
        v = d["vulnerabilities"][0]
        assert v["rule_id"] == "dangerous-eval"
        assert v["cwe_id"] == "CWE-95"

    def test_no_stdout_returncode_zero_yields_zero_issues(self):
        """stdout 비어있고 returncode=0 → 정상 종료, 결과 0건."""
        runner = _RecordingRunner()
        runner.queue("semgrep", stdout="", stderr="", returncode=0)
        semgrep = SemgrepRunner(runner=runner)

        result = semgrep.run("/tmp/x.py")
        assert result.error is None
        assert result.total_issues == 0

    def test_no_stdout_with_stderr_yields_error(self):
        runner = _RecordingRunner()
        runner.queue("semgrep", stdout="", stderr="config error", returncode=1)
        semgrep = SemgrepRunner(runner=runner)

        result = semgrep.run("/tmp/x.py")
        assert result.error == "config error"

    def test_no_stdout_failure_without_stderr_uses_default_message(self):
        runner = _RecordingRunner()
        runner.queue("semgrep", stdout="", stderr="", returncode=2)
        semgrep = SemgrepRunner(runner=runner)

        result = semgrep.run("/tmp/x.py")
        assert result.error == "Semgrep 실행 실패"

    def test_timeout_exception_preserves_korean_message(self):
        runner = _RecordingRunner()
        runner.queue_exc(
            "semgrep",
            subprocess.TimeoutExpired(cmd=["semgrep"], timeout=120),
        )
        semgrep = SemgrepRunner(runner=runner)

        result = semgrep.run("/tmp/x.py")
        assert result.error == "Semgrep 분석 시간 초과 (120초)"

    def test_filenotfound_preserves_korean_message(self):
        runner = _RecordingRunner()
        runner.queue_exc("semgrep", FileNotFoundError("semgrep"))
        semgrep = SemgrepRunner(runner=runner)

        result = semgrep.run("/tmp/x.py")
        assert result.error is not None
        assert "Semgrep이 설치되어 있지 않습니다" in result.error

    def test_invalid_json_yields_korean_error(self):
        runner = _RecordingRunner()
        runner.queue("semgrep", stdout="not-json{{")
        semgrep = SemgrepRunner(runner=runner)

        result = semgrep.run("/tmp/x.py")
        assert result.error is not None
        assert "Semgrep 출력 JSON 파싱 실패" in result.error


# ============================================================
# SemgrepRunner: child env sanitizer (Wave 4-G)
# ============================================================

class TestSemgrepChildEnvSanitizer:
    """Wave 4-G: SemgrepRunner 가 부모 환경을 그대로 상속시키지 않고
    ``build_child_env`` + Semgrep 전용 allowlist 로 sanitize 한 env 를 child
    에 전달하는지 검증.

    실제 subprocess 호출 없이 monkeypatch 로 ``os.environ`` 만 교체한 상태에서
    ``_RecordingRunner`` 의 호출 기록을 확인한다. 값은 짧은 placeholder 만
    사용해 실제 시크릿이 테스트에 노출되지 않도록 한다.
    """

    def _ambient_parent_env(self) -> dict[str, str]:
        return {
            # 필수 (기본 allowlist 통과)
            "PATH": "/usr/bin",
            "HOME": "/tmp/home",
            "LANG": "C.UTF-8",
            "HTTP_PROXY": "http://proxy:3128",
            "CI": "true",
            # Semgrep 전용 운영 변수 (caller-level allowlist 통과)
            "SSL_CERT_FILE": "/etc/ssl/certs/ca.pem",
            "SSL_CERT_DIR": "/etc/ssl/certs",
            "REQUESTS_CA_BUNDLE": "/etc/ssl/certs/ca.pem",
            "CURL_CA_BUNDLE": "/etc/ssl/certs/ca.pem",
            "XDG_CACHE_HOME": "/tmp/cache",
            "XDG_CONFIG_HOME": "/tmp/config",
            "SEMGREP_SETTINGS_FILE": "/tmp/semgrep.yml",
            "SEMGREP_SEND_METRICS": "off",
            "SEMGREP_ENABLE_VERSION_CHECK": "0",
            # ambient 시크릿 (deny 되어야 함)
            "ANTHROPIC_API_KEY": "x",
            "GITHUB_TOKEN": "x",
            "AWS_SECRET_ACCESS_KEY": "x",
            "NPM_TOKEN": "x",
            "DATABASE_URL": "x",
            "SEMGREP_APP_TOKEN": "x",
            "SONAR_TOKEN": "x",
        }

    def _run_semgrep_with_ambient_env(self, monkeypatch) -> dict:
        monkeypatch.setattr(os, "environ", self._ambient_parent_env())

        runner = _RecordingRunner()
        runner.queue("semgrep", stdout=json.dumps({"results": []}))
        semgrep = SemgrepRunner(runner=runner)
        semgrep.run("/tmp/x.py")

        assert len(runner.calls) == 1
        return runner.calls[0]

    def test_semgrep_child_env_is_not_none(self, monkeypatch):
        call = self._run_semgrep_with_ambient_env(monkeypatch)
        assert call["env"] is not None
        assert isinstance(call["env"], dict)

    def test_semgrep_child_env_strips_ambient_secrets(self, monkeypatch):
        call = self._run_semgrep_with_ambient_env(monkeypatch)
        env = call["env"]
        for secret_key in (
            "ANTHROPIC_API_KEY",
            "GITHUB_TOKEN",
            "AWS_SECRET_ACCESS_KEY",
            "NPM_TOKEN",
            "DATABASE_URL",
            "SEMGREP_APP_TOKEN",
        ):
            assert secret_key not in env, (
                f"{secret_key} 는 child env 에서 제거되어야 합니다"
            )

    def test_semgrep_child_env_preserves_required_base_vars(self, monkeypatch):
        call = self._run_semgrep_with_ambient_env(monkeypatch)
        env = call["env"]
        for required in (
            "PATH",
            "HOME",
            "LANG",
            "HTTP_PROXY",
            "CI",
        ):
            assert required in env, (
                f"{required} 는 child env 에 보존되어야 합니다"
            )

    def test_semgrep_child_env_preserves_semgrep_operational_vars(self, monkeypatch):
        call = self._run_semgrep_with_ambient_env(monkeypatch)
        env = call["env"]
        for required in (
            "SSL_CERT_FILE",
            "REQUESTS_CA_BUNDLE",
            "CURL_CA_BUNDLE",
            "SSL_CERT_DIR",
            "XDG_CACHE_HOME",
            "XDG_CONFIG_HOME",
            "SEMGREP_SETTINGS_FILE",
            "SEMGREP_SEND_METRICS",
            "SEMGREP_ENABLE_VERSION_CHECK",
        ):
            assert required in env, (
                f"{required} 는 Semgrep child env 에 보존되어야 합니다"
            )

    def test_semgrep_child_env_does_not_inject_sonar_token(self, monkeypatch):
        """Wave 4-E 에서 Sonar 전용으로 추가했던 ``SONAR_TOKEN`` 이
        Semgrep child env 에는 주입되지 않아야 한다 (default deny 적용)."""
        call = self._run_semgrep_with_ambient_env(monkeypatch)
        assert "SONAR_TOKEN" not in call["env"]


# ============================================================
# 하위 호환: 인자 없는 생성자 동작
# ============================================================

class TestBackwardCompatibility:
    def test_bandit_default_constructor_still_works(self):
        bandit = BanditRunner()
        assert hasattr(bandit, "_runner")
        assert isinstance(bandit._runner, StaticToolCommandRunner)

    def test_semgrep_default_constructor_still_works(self):
        semgrep = SemgrepRunner()
        assert hasattr(semgrep, "_runner")
        assert isinstance(semgrep._runner, StaticToolCommandRunner)

    def test_bandit_positional_config_path_still_works(self):
        # 기존: BanditRunner("config/bandit.yml") 형태로 호출하던 코드 보존.
        bandit = BanditRunner("config/bandit.yml")
        assert bandit.config_path == "config/bandit.yml"

    def test_semgrep_positional_config_still_works(self):
        # 기존: SemgrepRunner("auto") / SemgrepRunner("p/owasp-top-ten") 보존.
        semgrep = SemgrepRunner("p/security-audit")
        assert semgrep.config == "p/security-audit"


__all__: list[str] = []
