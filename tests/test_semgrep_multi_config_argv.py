"""Semgrep multi-config argv seam test (Wave 5-H1)

``SemgrepRunner`` 의 ``config`` 파라미터를 단일 문자열뿐 아니라 다중 config
시퀀스(list/tuple)로도 받을 수 있게 하는 argv seam 의 회귀 가드.

- 단일 문자열 ``config="auto"`` 는 기존과 동일하게 정확히 한 쌍의
  ``--config auto`` 만 argv 에 포함된다 (Wave 4-G 이전 동작 보존).
- 다중 config 시퀀스(``("p/security-audit", "p/owasp-top-ten")``) 는
  순서를 보존한 채 반복되는 ``--config <value>`` 쌍을 emit 한다.
- 빈 시퀀스는 명시적으로 거부된다 (룰셋 0개로 silent disable 방지).
- 비-문자열 entry 는 명시적으로 거부된다.
- 기본 keyword 호환 (``file_io``, ``runner``) 유지.
- child env sanitizer 가 ``SEMGREP_APP_TOKEN`` 등 시크릿을 그대로 통과시키지
  않는지 회귀 가드 (Wave 4-G 정책 보존 확인).
- 본 테스트는 실제 ``semgrep`` subprocess / 네트워크 / LLM / 파일 시스템 쓰기
  에 의존하지 않는다.
"""

from __future__ import annotations

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyzer.semgrep_runner import SemgrepRunner
from analyzer.static_tool_command_runner import CommandResult


# ============================================================
# 더블 — Static command runner
# ============================================================


class _FakeCommandRunner:
    def __init__(self, stdout: str = "", stderr: str = "", returncode: int = 0):
        self._stdout = stdout
        self._stderr = stderr
        self._returncode = returncode
        self.calls: list[dict] = []

    def run(self, argv, *, cwd=None, timeout=120, env=None):
        self.calls.append({"argv": list(argv), "env": dict(env) if env else env,
                           "timeout": timeout})
        return CommandResult(
            stdout=self._stdout, stderr=self._stderr, returncode=self._returncode
        )


def _empty_results_stdout() -> str:
    return json.dumps({"results": []})


def _config_pairs(argv: list[str]) -> list[str]:
    """argv 에서 ``--config <value>`` 쌍의 value 만 순서대로 추출."""
    pairs: list[str] = []
    i = 0
    while i < len(argv):
        if argv[i] == "--config" and i + 1 < len(argv):
            pairs.append(argv[i + 1])
            i += 2
        else:
            i += 1
    return pairs


# ============================================================
# 단일 config — 기존 동작 보존
# ============================================================


class TestSemgrepSingleConfigArgvPreserved:
    def test_single_string_config_emits_one_config_pair(self):
        cmd_runner = _FakeCommandRunner(stdout=_empty_results_stdout())
        runner = SemgrepRunner(config="auto", runner=cmd_runner)

        result = runner.run("test_targets/")

        assert result.error is None
        assert len(cmd_runner.calls) == 1
        argv = cmd_runner.calls[0]["argv"]
        assert argv[0] == "semgrep"
        # 정확히 한 쌍의 --config auto.
        assert argv.count("--config") == 1
        assert _config_pairs(argv) == ["auto"]
        # 기존 argv 슬롯 보존: --json --quiet <target>.
        assert "--json" in argv
        assert "--quiet" in argv
        assert argv[-1] == "test_targets/"
        # 타임아웃 보존.
        assert cmd_runner.calls[0]["timeout"] == 120

    def test_default_constructor_still_uses_auto(self):
        cmd_runner = _FakeCommandRunner(stdout=_empty_results_stdout())
        runner = SemgrepRunner(runner=cmd_runner)
        assert runner.config == "auto"

        runner.run("test_targets/")
        argv = cmd_runner.calls[0]["argv"]
        assert _config_pairs(argv) == ["auto"]


# ============================================================
# 다중 config — 신규 동작
# ============================================================


class TestSemgrepMultiConfigArgv:
    def test_tuple_of_configs_emits_repeated_config_pairs_in_order(self):
        cmd_runner = _FakeCommandRunner(stdout=_empty_results_stdout())
        configs = ("p/security-audit", "p/owasp-top-ten")
        runner = SemgrepRunner(config=configs, runner=cmd_runner)

        result = runner.run("test_targets/")

        assert result.error is None
        argv = cmd_runner.calls[0]["argv"]
        assert argv[0] == "semgrep"
        # 순서 보존: --config p/security-audit --config p/owasp-top-ten.
        assert _config_pairs(argv) == ["p/security-audit", "p/owasp-top-ten"]
        # 정확히 두 쌍.
        assert argv.count("--config") == 2
        # 기존 슬롯 보존.
        assert "--json" in argv
        assert "--quiet" in argv
        assert argv[-1] == "test_targets/"

    def test_list_of_configs_emits_repeated_config_pairs_in_order(self):
        cmd_runner = _FakeCommandRunner(stdout=_empty_results_stdout())
        configs = ["p/security-audit", "p/owasp-top-ten", "p/java"]
        runner = SemgrepRunner(config=configs, runner=cmd_runner)

        runner.run("test_targets/")

        argv = cmd_runner.calls[0]["argv"]
        assert _config_pairs(argv) == ["p/security-audit", "p/owasp-top-ten", "p/java"]
        assert argv.count("--config") == 3

    def test_multi_config_parses_fake_json_output(self):
        # 다중 config 라도 fake JSON 결과 파싱이 동일하게 동작해야 한다.
        finding = {
            "check_id": "rules.test_rule",
            "extra": {
                "severity": "ERROR",
                "message": "test",
                "lines": "this is a long enough lines field to skip enrichment",
                "metadata": {"cwe": ["CWE-89"], "source": "src"},
            },
            "path": "fake/file.py",
            "start": {"line": 1},
            "end": {"line": 1},
        }
        cmd_runner = _FakeCommandRunner(
            stdout=json.dumps({"results": [finding]})
        )
        runner = SemgrepRunner(
            config=("p/security-audit", "p/owasp-top-ten"),
            runner=cmd_runner,
        )

        result = runner.run("test_targets/")

        assert result.error is None
        assert result.total_issues == 1
        assert result.high_count == 1
        assert len(result.vulnerabilities) == 1


# ============================================================
# 입력 검증 — 빈 시퀀스 / 비-문자열 entry 거부
# ============================================================


class TestSemgrepConfigValidation:
    def test_empty_tuple_rejected(self):
        with pytest.raises((ValueError, TypeError)):
            SemgrepRunner(config=(), runner=_FakeCommandRunner())

    def test_empty_list_rejected(self):
        with pytest.raises((ValueError, TypeError)):
            SemgrepRunner(config=[], runner=_FakeCommandRunner())

    def test_non_string_entry_rejected(self):
        with pytest.raises((ValueError, TypeError)):
            SemgrepRunner(config=("p/security-audit", 42), runner=_FakeCommandRunner())

    def test_none_entry_rejected(self):
        with pytest.raises((ValueError, TypeError)):
            SemgrepRunner(config=("p/security-audit", None), runner=_FakeCommandRunner())

    def test_plain_string_is_single_config_not_character_sequence(self):
        # ``str`` 도 iterable 이지만 문자 시퀀스로 분해되어선 안 된다.
        cmd_runner = _FakeCommandRunner(stdout=_empty_results_stdout())
        runner = SemgrepRunner(config="auto", runner=cmd_runner)

        runner.run("test_targets/")

        argv = cmd_runner.calls[0]["argv"]
        # "auto" 가 a/u/t/o 4 개 config 로 폭발하면 안 된다.
        assert _config_pairs(argv) == ["auto"]


# ============================================================
# 보안 — child env sanitizer 가 SEMGREP_APP_TOKEN 등 시크릿을 차단
# ============================================================


class TestSemgrepEnvSanitizerStillBlocksSecrets:
    def test_ambient_semgrep_app_token_not_forwarded(self, monkeypatch):
        # 부모 프로세스에 ambient 시크릿이 있다고 가정.
        monkeypatch.setenv("SEMGREP_APP_TOKEN", "fake-token-should-not-leak")
        monkeypatch.setenv("ANTHROPIC_API_KEY", "fake-anthropic-should-not-leak")
        monkeypatch.setenv("GITHUB_TOKEN", "fake-gh-should-not-leak")

        cmd_runner = _FakeCommandRunner(stdout=_empty_results_stdout())
        runner = SemgrepRunner(
            config=("p/security-audit", "p/owasp-top-ten"),
            runner=cmd_runner,
        )

        runner.run("test_targets/")

        env = cmd_runner.calls[0]["env"]
        assert env is not None
        # 시크릿스러운 키 / 명시적 well-known 시크릿 변수명은 차단되어야 한다.
        assert "SEMGREP_APP_TOKEN" not in env
        assert "ANTHROPIC_API_KEY" not in env
        assert "GITHUB_TOKEN" not in env
        # 토큰 값 자체도 어떤 키의 값으로도 누출되어선 안 된다.
        for v in env.values():
            assert "fake-token-should-not-leak" not in v
            assert "fake-anthropic-should-not-leak" not in v
            assert "fake-gh-should-not-leak" not in v


__all__: list[str] = []
