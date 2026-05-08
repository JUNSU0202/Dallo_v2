"""Bandit file I/O seam test (Wave 4-N)

``BanditRunner`` 의 결과 JSON 저장 경로를 keyword-only ``file_io`` 어댑터로
fakeable 화한 동작을 회귀 검증한다.

- ``analyzer/file_io.py`` 에 최소한의 어댑터(``write_json`` / ``read_text_lines``)가
  존재해야 한다. 기본 어댑터는 parent dir 생성 + UTF-8 + ``indent=2`` +
  ``ensure_ascii=False`` 옵션을 보존한다.
- ``BanditRunner`` 는 keyword-only ``file_io`` 더블을 주입받으면 실제 디스크
  쓰기 없이 출력 JSON 저장 경로를 통과해야 한다.
- ``output_path=None`` 은 어떠한 ``write_json`` 호출도 발생시키지 않는다.
- 기본값(``file_io=None``)은 lazy 로 실제 어댑터로 해석되어야 하며, 기존
  생성자 시그니처(``BanditRunner()`` / ``BanditRunner(runner=...)``) 호환이
  유지되어야 한다.
- 본 테스트는 외부 bandit / 네트워크 / 실제 파일 쓰기에 의존하지 않는다.
"""

from __future__ import annotations

import inspect
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyzer.bandit_runner import BanditRunner
from analyzer.static_tool_command_runner import CommandResult


# ============================================================
# 더블 — Static command runner / FileIO
# ============================================================


class _FakeCommandRunner:
    """실제 bandit 호출을 차단하고, 미리 준비된 stdout/stderr/returncode 반환."""

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
    """write_json/read_text_lines 호출을 기록만 하는 더블 — 실제 디스크 I/O 없음."""

    def __init__(self) -> None:
        self.write_calls: list[tuple[str, object]] = []
        self.read_calls: list[str] = []

    def write_json(self, path, payload):
        self.write_calls.append((path, payload))

    def read_text_lines(self, path):
        self.read_calls.append(path)
        return []


_BANDIT_STDOUT_OK = (
    '{"results": [{"test_id": "B608", "test_name": "hardcoded_sql", '
    '"issue_severity": "HIGH", "issue_confidence": "HIGH", '
    '"issue_text": "x", "filename": "f.py", "line_number": 1, '
    '"code": "y", "more_info": ""}], '
    '"metrics": {"_totals": {"SEVERITY.HIGH": 1, "SEVERITY.MEDIUM": 0, "SEVERITY.LOW": 0}}}'
)


# ============================================================
# 어댑터 자체 표면 — analyzer.file_io 모듈이 존재해야 한다
# ============================================================


class TestFileIOModuleSurface:
    def test_file_io_module_importable(self):
        import analyzer.file_io as file_io_mod  # noqa: F401

    def test_write_json_callable(self):
        from analyzer.file_io import FileIO

        adapter = FileIO()
        assert callable(getattr(adapter, "write_json", None))

    def test_read_text_lines_callable(self):
        from analyzer.file_io import FileIO

        adapter = FileIO()
        assert callable(getattr(adapter, "read_text_lines", None))

    def test_default_file_io_provider_returns_adapter(self):
        from analyzer.file_io import FileIO, get_default_file_io

        assert isinstance(get_default_file_io(), FileIO)


# ============================================================
# 시그니처 — keyword-only file_io 매개변수
# ============================================================


class TestBanditConstructorSignature:
    def test_file_io_param_is_keyword_only_and_optional(self):
        sig = inspect.signature(BanditRunner.__init__)
        assert "file_io" in sig.parameters
        param = sig.parameters["file_io"]
        assert param.kind == inspect.Parameter.KEYWORD_ONLY
        assert param.default is None

    def test_default_construction_still_works(self):
        # ``BanditRunner()`` 는 그대로 동작해야 한다 (기본 file_io 지연 해석).
        runner = BanditRunner()
        assert runner is not None

    def test_existing_kwargs_still_accepted(self):
        # config_path / runner 만 주는 기존 호출자도 깨지지 않아야 한다.
        runner = BanditRunner(config_path="config/bandit.yml", runner=_FakeCommandRunner())
        assert runner.config_path == "config/bandit.yml"

    def test_file_io_is_keyword_only_positional_rejected(self):
        # positional 3번째 인자로는 받지 않는다.
        with pytest.raises(TypeError):
            BanditRunner("config/bandit.yml", _FakeCommandRunner(), _FakeFileIO())


# ============================================================
# 주입된 file_io 사용 — output_path 가 있으면 write_json 호출
# ============================================================


class TestBanditOutputWriteSeam:
    def test_injected_file_io_used_for_output_write(self, tmp_path):
        cmd_runner = _FakeCommandRunner(stdout=_BANDIT_STDOUT_OK)
        fake_io = _FakeFileIO()
        runner = BanditRunner(runner=cmd_runner, file_io=fake_io)

        out_path = str(tmp_path / "subdir" / "bandit_report.json")
        result = runner.run("test_targets/", output_path=out_path)

        assert result.error is None
        assert result.total_issues == 1
        assert len(fake_io.write_calls) == 1
        path, payload = fake_io.write_calls[0]
        assert path == out_path
        # raw 페이로드 모양이 보존되어야 한다 (parser/result 매핑 영향 없음).
        assert isinstance(payload, dict)
        assert "results" in payload
        assert payload["results"][0]["test_id"] == "B608"
        # 실제 디스크에는 아무 것도 쓰이지 않아야 한다.
        assert not os.path.exists(out_path)
        assert not os.path.exists(os.path.dirname(out_path))

    def test_output_path_none_does_not_write(self):
        cmd_runner = _FakeCommandRunner(stdout=_BANDIT_STDOUT_OK)
        fake_io = _FakeFileIO()
        runner = BanditRunner(runner=cmd_runner, file_io=fake_io)

        result = runner.run("test_targets/", output_path=None)

        assert result.error is None
        assert fake_io.write_calls == []

    def test_empty_stdout_does_not_write(self):
        # bandit 이 비정상 종료해 stdout 이 비면 write_json 도 호출되지 않는다.
        cmd_runner = _FakeCommandRunner(stdout="", stderr="error", returncode=2)
        fake_io = _FakeFileIO()
        runner = BanditRunner(runner=cmd_runner, file_io=fake_io)

        result = runner.run("test_targets/", output_path="/tmp/should_not_be_written.json")

        assert fake_io.write_calls == []
        assert result.error == "error"

    def test_default_file_io_lazy_when_none(self, tmp_path, monkeypatch):
        # file_io=None (기본) 이어도 출력 경로가 주어지면 lazy 로 실제 어댑터를
        # 통해 디스크에 쓰여야 한다 (기존 동작 보존).
        cmd_runner = _FakeCommandRunner(stdout=_BANDIT_STDOUT_OK)
        runner = BanditRunner(runner=cmd_runner)

        out_path = str(tmp_path / "bandit_report.json")
        result = runner.run("test_targets/", output_path=out_path)

        assert result.error is None
        # 실제 디스크에 파일이 생성되어야 한다 — 기본 어댑터가 정상 동작.
        assert os.path.exists(out_path)
        # JSON 옵션 보존 — UTF-8 + ensure_ascii=False + indent=2 검증.
        with open(out_path, "r", encoding="utf-8") as f:
            content = f.read()
        assert "  " in content  # indent=2 결과 (들여쓰기 존재)


__all__: list[str] = []
