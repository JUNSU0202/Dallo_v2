"""Semgrep file I/O seam test (Wave 4-N)

``SemgrepRunner`` 의 결과 JSON 저장 경로 + snippet enrichment 라인 읽기 경계를
keyword-only ``file_io`` 어댑터로 fakeable 화한 동작을 회귀 검증한다.

- 출력 JSON 저장은 주입된 ``file_io.write_json`` 으로만 일어나야 한다.
- 짧은 ``lines`` 응답에 대한 snippet enrichment 는 주입된
  ``file_io.read_text_lines`` 만 호출해야 한다.
- read_text_lines 가 예외를 던져도 호출자가 swallowing 하여 result 동작이
  보존되어야 한다 (현재 ``except Exception: pass`` 의도된 동작).
- ``output_path=None`` 은 어떠한 ``write_json`` 호출도 발생시키지 않는다.
- 기본 생성자(``SemgrepRunner()`` / ``SemgrepRunner(config="auto")``) 호환과
  ``runner=`` 키워드 호환이 유지되어야 한다.
- 본 테스트는 외부 semgrep / 네트워크 / 실제 파일 쓰기에 의존하지 않는다.
"""

from __future__ import annotations

import inspect
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyzer.semgrep_runner import SemgrepRunner
from analyzer.static_tool_command_runner import CommandResult


# ============================================================
# 더블 — Static command runner / FileIO
# ============================================================


class _FakeCommandRunner:
    def __init__(self, stdout: str = "", stderr: str = "", returncode: int = 0):
        self._stdout = stdout
        self._stderr = stderr
        self._returncode = returncode
        self.calls: list[dict] = []

    def run(self, argv, *, cwd=None, timeout=120, env=None):
        self.calls.append({"argv": list(argv), "env": env, "timeout": timeout})
        return CommandResult(
            stdout=self._stdout, stderr=self._stderr, returncode=self._returncode
        )


class _FakeFileIO:
    """write_json/read_text_lines 호출을 기록하는 더블."""

    def __init__(self, line_provider=None, raise_on_read=None):
        self.write_calls: list[tuple[str, object]] = []
        self.read_calls: list[str] = []
        self._line_provider = line_provider
        self._raise_on_read = raise_on_read

    def write_json(self, path, payload):
        self.write_calls.append((path, payload))

    def read_text_lines(self, path):
        self.read_calls.append(path)
        if self._raise_on_read is not None:
            raise self._raise_on_read
        if self._line_provider is None:
            return []
        return self._line_provider(path)


def _semgrep_finding(*, lines: str = "x", path: str = "fake/file.py", start: int = 5,
                    end: int = 5) -> dict:
    return {
        "check_id": "rules.test_rule",
        "extra": {
            "severity": "WARNING",
            "message": "test message",
            "lines": lines,
            "metadata": {"cwe": ["CWE-89: SQL Injection"], "source": "src"},
        },
        "path": path,
        "start": {"line": start},
        "end": {"line": end},
    }


def _semgrep_stdout(findings: list[dict]) -> str:
    return json.dumps({"results": findings})


# ============================================================
# 시그니처 — keyword-only file_io 매개변수
# ============================================================


class TestSemgrepConstructorSignature:
    def test_file_io_param_is_keyword_only_and_optional(self):
        sig = inspect.signature(SemgrepRunner.__init__)
        assert "file_io" in sig.parameters
        param = sig.parameters["file_io"]
        assert param.kind == inspect.Parameter.KEYWORD_ONLY
        assert param.default is None

    def test_default_construction_still_works(self):
        # 두 형태 모두 깨지면 안 된다.
        assert SemgrepRunner() is not None
        assert SemgrepRunner(config="auto") is not None

    def test_existing_kwargs_still_accepted(self):
        runner = SemgrepRunner(config="p/security-audit", runner=_FakeCommandRunner())
        assert runner.config == "p/security-audit"

    def test_file_io_is_keyword_only_positional_rejected(self):
        with pytest.raises(TypeError):
            SemgrepRunner("auto", _FakeCommandRunner(), _FakeFileIO())


# ============================================================
# 주입된 file_io — 출력 JSON 저장 경로
# ============================================================


class TestSemgrepOutputWriteSeam:
    def test_injected_file_io_used_for_output_write(self, tmp_path):
        # 짧은 lines 가 enrichment 를 트리거하지 않도록 길게 주어, write 만 검증.
        finding = _semgrep_finding(
            lines="this line is definitely longer than twenty characters of code"
        )
        cmd_runner = _FakeCommandRunner(stdout=_semgrep_stdout([finding]))
        fake_io = _FakeFileIO()
        runner = SemgrepRunner(runner=cmd_runner, file_io=fake_io)

        out_path = str(tmp_path / "nested" / "semgrep_report.json")
        result = runner.run("test_targets/", output_path=out_path)

        assert result.error is None
        assert len(fake_io.write_calls) == 1
        path, payload = fake_io.write_calls[0]
        assert path == out_path
        assert isinstance(payload, dict)
        assert payload["results"][0]["check_id"] == "rules.test_rule"
        # snippet enrichment 도 트리거되지 않아 read_calls 는 비어 있어야 한다.
        assert fake_io.read_calls == []
        # 실제 디스크는 건드리지 않는다.
        assert not os.path.exists(out_path)
        assert not os.path.exists(os.path.dirname(out_path))

    def test_output_path_none_does_not_write(self):
        finding = _semgrep_finding(
            lines="this line is definitely longer than twenty characters of code"
        )
        cmd_runner = _FakeCommandRunner(stdout=_semgrep_stdout([finding]))
        fake_io = _FakeFileIO()
        runner = SemgrepRunner(runner=cmd_runner, file_io=fake_io)

        result = runner.run("test_targets/", output_path=None)

        assert result.error is None
        assert fake_io.write_calls == []

    def test_empty_stdout_returncode_zero_no_write(self):
        # stdout 비고 returncode==0 → 결과 0건, 어떤 write 도 없어야 한다.
        cmd_runner = _FakeCommandRunner(stdout="", stderr="", returncode=0)
        fake_io = _FakeFileIO()
        runner = SemgrepRunner(runner=cmd_runner, file_io=fake_io)

        result = runner.run("test_targets/", output_path="/tmp/should_not.json")

        assert result.total_issues == 0
        assert fake_io.write_calls == []


# ============================================================
# 주입된 file_io — snippet enrichment 라인 읽기 경계
# ============================================================


class TestSemgrepSnippetReadSeam:
    def test_injected_file_io_used_for_snippet_read(self):
        # lines 가 짧고 start_line>0 → enrichment 트리거.
        finding = _semgrep_finding(lines="x", path="fake/sample.py", start=5, end=5)
        cmd_runner = _FakeCommandRunner(stdout=_semgrep_stdout([finding]))

        provided_lines = [f"line {i}\n" for i in range(1, 11)]
        fake_io = _FakeFileIO(line_provider=lambda p: provided_lines)
        runner = SemgrepRunner(runner=cmd_runner, file_io=fake_io)

        result = runner.run("test_targets/", output_path=None)

        assert result.error is None
        assert fake_io.read_calls == ["fake/sample.py"]
        # snippet 윈도우 보존: ctx_start = max(0, 5-3)=2, ctx_end = min(10, 5+2)=7
        # → provided_lines[2:7] = lines 3..7
        expected = "".join(provided_lines[2:7])
        assert len(result.vulnerabilities) == 1
        assert result.vulnerabilities[0].code_snippet == expected

    def test_snippet_read_exception_is_swallowed(self):
        finding = _semgrep_finding(lines="x", path="missing.py", start=5, end=5)
        cmd_runner = _FakeCommandRunner(stdout=_semgrep_stdout([finding]))
        fake_io = _FakeFileIO(raise_on_read=OSError("fake missing"))
        runner = SemgrepRunner(runner=cmd_runner, file_io=fake_io)

        # 예외가 caller 에서 swallowing 되어 결과는 정상 반환되어야 한다.
        result = runner.run("test_targets/", output_path=None)

        assert result.error is None
        assert fake_io.read_calls == ["missing.py"]
        assert len(result.vulnerabilities) == 1
        # snippet enrichment 가 실패했으므로 원본 lines("x") 가 보존된다.
        assert result.vulnerabilities[0].code_snippet == "x"

    def test_long_lines_skip_enrichment(self):
        # lines.strip() 길이가 20 이상이면 read 가 호출되지 않는다 (조건 보존).
        finding = _semgrep_finding(
            lines="this line is definitely longer than twenty characters of code"
        )
        cmd_runner = _FakeCommandRunner(stdout=_semgrep_stdout([finding]))
        fake_io = _FakeFileIO()
        runner = SemgrepRunner(runner=cmd_runner, file_io=fake_io)

        result = runner.run("test_targets/", output_path=None)

        assert result.error is None
        assert fake_io.read_calls == []


# ============================================================
# 기본 어댑터 lazy 보존 — file_io=None 일 때 실제 디스크에 쓰여야 한다
# ============================================================


class TestSemgrepDefaultLazyFileIO:
    def test_default_file_io_lazy_writes_real_disk(self, tmp_path):
        finding = _semgrep_finding(
            lines="this line is definitely longer than twenty characters of code"
        )
        cmd_runner = _FakeCommandRunner(stdout=_semgrep_stdout([finding]))
        runner = SemgrepRunner(runner=cmd_runner)

        out_path = str(tmp_path / "semgrep_report.json")
        result = runner.run("test_targets/", output_path=out_path)

        assert result.error is None
        assert os.path.exists(out_path)
        with open(out_path, "r", encoding="utf-8") as f:
            content = f.read()
        # JSON 옵션(들여쓰기) 보존 확인.
        assert "  " in content


__all__: list[str] = []
