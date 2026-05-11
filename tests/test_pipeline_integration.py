"""
파이프라인 통합 테스트 (tests/test_pipeline_integration.py)

정적 분석 결과 → 중복 제거 → 위험도 산정 순서로 호출되는지 검증.
LLM 호출은 mock으로 대체.
"""

import inspect
import os
import sys
from datetime import datetime
from unittest.mock import patch, MagicMock

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shared.schemas import VulnerabilityReport


def _make_vulns():
    """테스트용 취약점 목록 생성 — 중복 포함"""
    code = "query = f'SELECT * FROM users WHERE id = {user_id}'"
    return [
        VulnerabilityReport(
            id="vuln_B608_10", tool="bandit", rule_id="B608",
            severity="HIGH", confidence="HIGH",
            title="SQL Injection", description="SQL injection via f-string",
            file_path="test.py", line_number=10,
            code_snippet=code, function_code=code,
            cwe_id="CWE-89",
        ),
        VulnerabilityReport(
            id="vuln_B608_20", tool="bandit", rule_id="B608",
            severity="HIGH", confidence="HIGH",
            title="SQL Injection", description="SQL injection via f-string",
            file_path="test.py", line_number=20,
            code_snippet=code, function_code=code,
            cwe_id="CWE-89",
        ),
        VulnerabilityReport(
            id="vuln_B303_30", tool="bandit", rule_id="B303",
            severity="MEDIUM", confidence="HIGH",
            title="Weak Hash", description="Use of md5",
            file_path="test.py", line_number=30,
            code_snippet="hashlib.md5(data)", function_code="hashlib.md5(data)",
            cwe_id="CWE-328",
        ),
    ]


class TestPipelineOrder:
    """파이프라인이 정적 분석 → 중복 제거 → 위험도 산정 → LLM 순서로 동작하는지 검증"""

    def test_dedup_then_risk_then_llm(self):
        """중복 제거 → 위험도 산정 → LLM 대표만 전달"""
        from analyzer.deduplicator import deduplicate
        from analyzer.risk_scorer import score_vulnerabilities

        vulns = _make_vulns()

        # Step 1: 중복 제거
        dedup_result = deduplicate(vulns)
        for v in vulns:
            v.duplicate_group_id = dedup_result.group_map.get(v.id, "")
        llm_targets = dedup_result.representatives

        # 동일 rule_id + 동일 코드 → 2개가 1개로 합쳐져야 함
        assert len(llm_targets) == 2  # B608 대표 1 + B303 1
        assert dedup_result.total_deduplicated == 1  # B608 중복 1개 제거

        # Step 2: 위험도 산정
        score_vulnerabilities(vulns)

        # SQL Injection(CWE-89)은 critical, Weak Hash(CWE-328)는 medium
        b608_vuln = next(v for v in vulns if v.rule_id == "B608")
        b303_vuln = next(v for v in vulns if v.rule_id == "B303")
        assert b608_vuln.risk_level == "critical"
        assert b303_vuln.risk_level == "medium"

        # Step 3: LLM에는 대표만 전달 (2건, 원래 3건)
        assert len(llm_targets) < len(vulns)

    def test_duplicate_group_id_assigned(self):
        """중복 그룹 ID가 모든 취약점에 부여되는지 검증"""
        from analyzer.deduplicator import deduplicate

        vulns = _make_vulns()
        dedup_result = deduplicate(vulns)
        for v in vulns:
            v.duplicate_group_id = dedup_result.group_map.get(v.id, "")

        # 모든 취약점에 그룹 ID 할당됨
        for v in vulns:
            assert v.duplicate_group_id != "", f"{v.id}에 그룹 ID 미할당"

        # B608 2개는 같은 그룹
        b608_vulns = [v for v in vulns if v.rule_id == "B608"]
        assert b608_vulns[0].duplicate_group_id == b608_vulns[1].duplicate_group_id

        # B303은 다른 그룹
        b303_vuln = next(v for v in vulns if v.rule_id == "B303")
        assert b303_vuln.duplicate_group_id != b608_vulns[0].duplicate_group_id

    def test_risk_score_persists_on_schema(self):
        """schemas.py의 risk_level, cvss_score 필드가 실제로 채워지는지 검증"""
        from analyzer.risk_scorer import score_vulnerabilities

        vulns = _make_vulns()
        score_vulnerabilities(vulns)

        for v in vulns:
            assert v.risk_level in ("critical", "high", "medium", "low"), \
                f"{v.id}: risk_level={v.risk_level}"
            assert 0 < v.cvss_score <= 10.0, \
                f"{v.id}: cvss_score={v.cvss_score}"

    def test_empty_vulns_no_error(self):
        """취약점 0건이어도 에러 없이 동작"""
        from analyzer.deduplicator import deduplicate
        from analyzer.risk_scorer import score_vulnerabilities

        result = deduplicate([])
        assert len(result.representatives) == 0

        score_vulnerabilities([])  # no error


# ============================================================
# Wave 4-U: _build_result fakeable clock seam
# ============================================================

class TestBuildResultClockSeam:
    """``analyzer.pipeline._build_result`` 의 ``datetime.now()`` 경계를
    keyword-only ``now`` 인자로 fakeable 화한 회귀 가드.

    Wave 4-P (DB clock seam) / 4-T (analysis pipeline clock seam) 와 동일한
    패턴: ``now is None`` 일 때만 ``datetime.now()`` 를 호출 → 운영 동작 무변경,
    테스트는 ``now=fixed`` 로 ``completed_at`` 을 결정적으로 검증.
    """

    def _empty_args(self):
        """``_build_result`` 호출에 사용할 최소 인자 집합."""
        return dict(
            job_id="job_clock_seam",
            vuln_reports=[],
            patches=[],
            elapsed=1.23,
        )

    def test_build_result_uses_fixed_now(self):
        """``now=fixed`` 주입 시 session dict 의 ``completed_at`` 이
        ``fixed.isoformat()`` 으로 결정된다."""
        from analyzer.pipeline import _build_result

        fixed = datetime(2026, 1, 2, 3, 4, 5)
        result = _build_result(**self._empty_args(), now=fixed)

        assert result["completed_at"] == fixed.isoformat(), (
            f"fixed now 가 completed_at 에 반영되지 않음: {result['completed_at']}"
        )

    def test_build_result_now_is_keyword_only(self):
        """``now`` 는 keyword-only 이어야 한다 — positional 호출은 ``TypeError``."""
        from analyzer.pipeline import _build_result

        sig = inspect.signature(_build_result)
        assert "now" in sig.parameters, "_build_result 에 now 인자가 없다"
        assert (
            sig.parameters["now"].kind is inspect.Parameter.KEYWORD_ONLY
        ), "now 는 keyword-only 이어야 한다"

        fixed = datetime(2026, 1, 2, 3, 4, 5)
        # positional 호출은 거부되어야 한다
        with pytest.raises(TypeError):
            _build_result(
                "job_clock_seam", [], [], 1.23, fixed,  # type: ignore[misc]
            )

    def test_build_result_default_path_uses_module_datetime(self, monkeypatch):
        """``now`` 미주입 시 모듈 레벨 ``datetime.now()`` 가 그대로 사용된다.

        ``analyzer.pipeline.datetime`` 을 fake 로 교체해 default 경로가 여전히
        module-level import 를 통과함을 회귀 검증한다.
        """
        import analyzer.pipeline as pipeline_mod

        class _FakeDT:
            @staticmethod
            def now():
                return datetime(2026, 6, 7, 8, 9, 10)

        monkeypatch.setattr(pipeline_mod, "datetime", _FakeDT)
        result = pipeline_mod._build_result(**self._empty_args())

        assert result["completed_at"] == "2026-06-07T08:09:10", (
            f"default 경로 datetime.now 회귀: {result['completed_at']}"
        )

    def test_build_result_preserves_existing_keys_and_shape(self):
        """``now`` 주입 여부와 무관하게 session dict 의 키 셋과
        ``duration_seconds`` 셰이프가 보존된다."""
        from analyzer.pipeline import _build_result

        fixed = datetime(2026, 1, 2, 3, 4, 5)
        result = _build_result(**self._empty_args(), now=fixed)

        expected_keys = {
            "session_id", "repo", "pr_number", "commit_sha", "branch",
            "summary", "vulnerabilities", "patches",
            "started_at", "completed_at", "duration_seconds",
        }
        assert expected_keys.issubset(result.keys()), (
            f"session dict 키 회귀: 누락={expected_keys - set(result.keys())}"
        )
        # Wave 4-T 이전과 동일한 고정 필드들
        assert result["session_id"] == "job_clock_seam"
        assert result["repo"] == "dashboard-upload"
        assert result["pr_number"] == 0
        assert result["commit_sha"] == "direct-upload"
        # elapsed 가 round(..., 2) 로 그대로 전달되어야 한다
        assert result["duration_seconds"] == 1.23
        # 빈 입력 → summary total 0
        assert result["summary"]["total"] == 0
        assert result["vulnerabilities"] == []
        assert result["patches"] == []

    def test_build_result_isoformat_round_trip(self):
        """``completed_at`` 은 fixed ``now`` 의 ``isoformat()`` 과 정확히 동치이며,
        ``datetime.fromisoformat`` 으로 다시 원래 ``datetime`` 으로 round-trip 한다."""
        from analyzer.pipeline import _build_result

        fixed = datetime(2026, 12, 31, 23, 59, 58, 123456)
        result = _build_result(**self._empty_args(), now=fixed)

        assert result["completed_at"] == fixed.isoformat()
        # round-trip: 문자열 → datetime 으로 정확히 복원되어야 한다
        assert datetime.fromisoformat(result["completed_at"]) == fixed


# ============================================================
# Wave 4-V: execute_pipeline elapsed clock seam
# ============================================================

class TestExecutePipelineClockSeam:
    """``analyzer.pipeline.execute_pipeline`` 의 elapsed ``time.time()`` 경계를
    keyword-only ``clock`` 인자로 fakeable 화한 회귀 가드.

    Wave 4-U (_build_result completed_at clock seam) 와 동일한 패턴:
    ``clock is None`` 일 때만 모듈 ``time.time`` 을 사용 → 운영 동작 무변경,
    테스트는 ``clock=fake`` 로 ``duration_seconds`` 를 결정적으로 검증.
    """

    @pytest.fixture
    def stub_pipeline_io(self, monkeypatch):
        """``execute_pipeline`` 의 외부 의존 단계 (정적 분석/DB 저장) 를 무력화.

        elapsed 만 결정적으로 검증하기 위해 정적 분석은 빈 결과를 돌려주고,
        DB 저장은 no-op 으로 만든다. LLM 은 ``use_llm=False`` 로 호출부에서
        스킵한다. 실 semgrep/bandit/LLM/DB/network 호출은 발생하지 않는다.
        """
        import analyzer.pipeline as pipeline_mod
        monkeypatch.setattr(
            pipeline_mod, "_run_static_analysis", lambda *a, **kw: [],
        )
        monkeypatch.setattr(
            pipeline_mod, "_persist_to_db", lambda *a, **kw: None,
        )

    def test_clock_param_is_keyword_only_with_default_none(self):
        """``clock`` 은 keyword-only 이고 default 는 ``None`` 이다."""
        import inspect as _inspect
        from analyzer.pipeline import execute_pipeline

        sig = _inspect.signature(execute_pipeline)
        assert "clock" in sig.parameters, (
            "execute_pipeline 에 clock 인자가 없다"
        )
        param = sig.parameters["clock"]
        assert param.kind is _inspect.Parameter.KEYWORD_ONLY, (
            f"clock 은 keyword-only 이어야 한다 (got {param.kind})"
        )
        assert param.default is None, (
            f"clock default 는 None 이어야 한다 (got {param.default!r})"
        )

    def test_fake_clock_makes_duration_seconds_deterministic(
        self, stub_pipeline_io,
    ):
        """주입된 ``clock`` 의 (start, end) tick 차이가 ``duration_seconds`` 에
        round(2) 로 반영된다 — wall-clock 의존 제거."""
        from analyzer.pipeline import execute_pipeline

        ticks = iter([100.0, 101.23])

        result = execute_pipeline(
            job_id="job_clk",
            code="x = 1\n",
            filename="x.py",
            use_llm=False,
            clock=lambda: next(ticks),
        )

        assert result.result_data["duration_seconds"] == 1.23, (
            f"fake clock 이 duration_seconds 에 반영되지 않음: "
            f"{result.result_data['duration_seconds']}"
        )

    def test_fake_clock_does_not_call_module_time_time(
        self, stub_pipeline_io, monkeypatch,
    ):
        """``clock`` 이 주입되면 모듈 ``time.time`` 은 한 번도 호출되지 않는다.

        ``analyzer.pipeline.time`` 을 spy 로 교체해 ``clock`` 주입 경로가
        모듈 ``time`` 을 우회함을 직접 검증한다.
        """
        import analyzer.pipeline as pipeline_mod

        class _SpyTime:
            def __init__(self):
                self.calls = 0

            def time(self):
                self.calls += 1
                return 999.0

        spy = _SpyTime()
        monkeypatch.setattr(pipeline_mod, "time", spy)

        ticks = iter([200.0, 200.5])
        pipeline_mod.execute_pipeline(
            job_id="job_clk_no_time",
            code="x = 1\n",
            filename="x.py",
            use_llm=False,
            clock=lambda: next(ticks),
        )

        assert spy.calls == 0, (
            f"clock 주입 시 모듈 time.time 이 {spy.calls}회 호출됨"
        )

    def test_default_path_uses_module_time_time(
        self, stub_pipeline_io, monkeypatch,
    ):
        """``clock`` 미주입(default=None) 시 모듈 ``time.time`` 으로 elapsed 가
        계산된다 — ``analyzer.pipeline.time`` 을 fake 로 교체해 default 경로가
        여전히 모듈 레벨 import 를 통과함을 회귀 검증한다.
        """
        import analyzer.pipeline as pipeline_mod

        class _FakeTimeModule:
            def __init__(self, ticks):
                self.calls = 0
                self._ticks = iter(ticks)

            def time(self):
                self.calls += 1
                return next(self._ticks)

        fake_time = _FakeTimeModule([300.0, 302.5])
        monkeypatch.setattr(pipeline_mod, "time", fake_time)

        result = pipeline_mod.execute_pipeline(
            job_id="job_default_clk",
            code="x = 1\n",
            filename="x.py",
            use_llm=False,
            # clock 미주입 — default None
        )

        assert result.result_data["duration_seconds"] == 2.5, (
            f"default 경로 elapsed 회귀: "
            f"{result.result_data['duration_seconds']}"
        )
        assert fake_time.calls == 2, (
            "default 경로에서 모듈 time.time 가 정확히 2회(start/end) "
            f"호출되지 않음: {fake_time.calls}회"
        )

    def test_existing_keyword_call_shape_preserved(self, stub_pipeline_io):
        """``clock`` 인자 없이 기존 keyword 호출이 그대로 동작하고
        결과 dict 의 키 셰이프가 보존된다."""
        from analyzer.pipeline import execute_pipeline

        result = execute_pipeline(
            job_id="job_shape",
            code="x = 1\n",
            filename="x.py",
            use_llm=False,
            provider="gemini",
            model="gemini-2.0-flash-lite",
            multi_patch=False,
        )

        assert result.language == "python"
        # PipelineResult 셰이프 보존
        assert hasattr(result, "result_data")
        assert hasattr(result, "llm_error")
        assert hasattr(result, "db_error")

        # result_data session dict 키 셰이프 보존
        expected_keys = {
            "session_id", "repo", "pr_number", "commit_sha", "branch",
            "summary", "vulnerabilities", "patches",
            "started_at", "completed_at", "duration_seconds",
        }
        assert expected_keys.issubset(result.result_data.keys()), (
            f"result_data 키 회귀: "
            f"누락={expected_keys - set(result.result_data.keys())}"
        )
        assert result.result_data["session_id"] == "job_shape"
        # round(elapsed, 2) 셰이프 — float
        assert isinstance(result.result_data["duration_seconds"], float)

    def test_execute_pipeline_body_has_no_direct_time_time_call(self):
        """``execute_pipeline`` 본체 AST 에 ``time.time()`` 직접 호출이
        남아 있지 않다 — clock seam 우회 회귀 가드."""
        import ast
        import inspect as _inspect
        from analyzer.pipeline import execute_pipeline

        src = _inspect.getsource(execute_pipeline)
        tree = ast.parse(src)

        offenders: list[int] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if (
                isinstance(func, ast.Attribute)
                and isinstance(func.value, ast.Name)
                and func.value.id == "time"
                and func.attr == "time"
            ):
                offenders.append(node.lineno)

        assert offenders == [], (
            f"execute_pipeline 본체에 time.time() 직접 호출이 남아 있다 "
            f"(줄: {offenders}) — clock seam 우회"
        )


# ============================================================
# Wave 4-X: execute_pipeline file I/O seam
# ============================================================


class _FakeFileIO:
    """``write_text`` 호출만 기록하는 더블 — 실제 디스크 쓰기 없음."""

    def __init__(self) -> None:
        self.write_text_calls: list[tuple[str, str]] = []

    def write_text(self, path: str, content: str) -> None:
        self.write_text_calls.append((path, content))


class TestExecutePipelineFileIOSeam:
    """``analyzer.pipeline.execute_pipeline`` 의 임시 파일 쓰기 경계를
    keyword-only ``file_io`` 어댑터로 fakeable 화한 회귀 가드.

    Wave 4-N (Bandit/Semgrep file I/O seam) 와 동일한 패턴:
    ``file_io is None`` 일 때만 ``get_default_file_io()`` lazy default 를
    사용 → 운영 동작 무변경, 테스트는 ``file_io=fake`` 로 임시 파일 쓰기를
    실제 디스크 없이 검증.
    """

    @pytest.fixture
    def stub_pipeline_io(self, monkeypatch):
        """``execute_pipeline`` 의 외부 의존 단계 (정적 분석/DB 저장) 를 무력화.

        실 semgrep/bandit/LLM/DB/network 호출이 발생하지 않도록 한다.
        """
        import analyzer.pipeline as pipeline_mod
        monkeypatch.setattr(
            pipeline_mod, "_run_static_analysis", lambda *a, **kw: [],
        )
        monkeypatch.setattr(
            pipeline_mod, "_persist_to_db", lambda *a, **kw: None,
        )

    def test_file_io_param_is_keyword_only_with_default_none(self):
        """``file_io`` 는 keyword-only 이고 default 는 ``None`` 이다."""
        import inspect as _inspect
        from analyzer.pipeline import execute_pipeline

        sig = _inspect.signature(execute_pipeline)
        assert "file_io" in sig.parameters, (
            "execute_pipeline 에 file_io 인자가 없다"
        )
        param = sig.parameters["file_io"]
        assert param.kind is _inspect.Parameter.KEYWORD_ONLY, (
            f"file_io 는 keyword-only 이어야 한다 (got {param.kind})"
        )
        assert param.default is None, (
            f"file_io default 는 None 이어야 한다 (got {param.default!r})"
        )

    def test_injected_file_io_receives_temp_path_and_code(
        self, stub_pipeline_io, monkeypatch, tmp_path,
    ):
        """fake ``file_io`` 주입 시 ``write_text`` 가 임시 파일 경로 + 원본
        코드를 정확히 받는다."""
        import analyzer.pipeline as pipeline_mod

        forced_tmpdir = str(tmp_path / "dallo_analyze_fixed")
        os.makedirs(forced_tmpdir, exist_ok=True)
        monkeypatch.setattr(
            pipeline_mod.tempfile,
            "mkdtemp",
            lambda prefix=None: forced_tmpdir,
        )

        fake_io = _FakeFileIO()
        code = "x = 1\n"
        expected_path = os.path.join(forced_tmpdir, "x.py")

        pipeline_mod.execute_pipeline(
            job_id="job_fio_inject",
            code=code,
            filename="x.py",
            use_llm=False,
            file_io=fake_io,
        )

        assert len(fake_io.write_text_calls) == 1, (
            f"file_io.write_text 가 정확히 1회 호출되어야 한다 "
            f"(got {len(fake_io.write_text_calls)})"
        )
        path, content = fake_io.write_text_calls[0]
        assert path == expected_path, (
            f"file_io.write_text path 불일치: {path} != {expected_path}"
        )
        assert content == code, (
            f"file_io.write_text content 불일치: {content!r} != {code!r}"
        )

    def test_injected_file_io_does_not_trigger_builtin_open_write(
        self, stub_pipeline_io, monkeypatch, tmp_path,
    ):
        """fake ``file_io`` 주입 시 ``builtins.open(..., 'w')`` 트립와이어가
        사용자 코드 임시 파일 경로로 호출되지 않는다."""
        import builtins
        import analyzer.pipeline as pipeline_mod

        forced_tmpdir = str(tmp_path / "dallo_analyze_no_open")
        os.makedirs(forced_tmpdir, exist_ok=True)
        monkeypatch.setattr(
            pipeline_mod.tempfile,
            "mkdtemp",
            lambda prefix=None: forced_tmpdir,
        )

        expected_path = os.path.join(forced_tmpdir, "x.py")
        write_opens: list[tuple[str, str]] = []
        real_open = builtins.open

        def spy_open(file, mode="r", *args, **kwargs):
            try:
                m = mode if isinstance(mode, str) else ""
                if "w" in m or "a" in m or "x" in m:
                    write_opens.append((str(file), m))
            except Exception:
                pass
            return real_open(file, mode, *args, **kwargs)

        monkeypatch.setattr(builtins, "open", spy_open)

        fake_io = _FakeFileIO()
        pipeline_mod.execute_pipeline(
            job_id="job_fio_no_open",
            code="x = 1\n",
            filename="x.py",
            use_llm=False,
            file_io=fake_io,
        )

        offenders = [(p, m) for p, m in write_opens if p == expected_path]
        assert offenders == [], (
            f"file_io 주입 경로에서 builtins.open 이 사용자 코드 임시 파일에 "
            f"쓰기 모드로 호출됨: {offenders}"
        )

    def test_default_path_uses_get_default_file_io(
        self, stub_pipeline_io, monkeypatch,
    ):
        """``file_io`` 미주입(default=None) 시 ``get_default_file_io()`` 로
        해석된 어댑터의 ``write_text`` 가 호출된다 — 운영 동작 보존."""
        from analyzer import file_io as file_io_mod

        default_instance = file_io_mod.FileIO()
        calls: list[tuple[str, str]] = []
        monkeypatch.setattr(
            default_instance,
            "write_text",
            lambda path, content: calls.append((path, content)),
        )
        monkeypatch.setattr(
            file_io_mod,
            "get_default_file_io",
            lambda: default_instance,
        )

        import analyzer.pipeline as pipeline_mod
        pipeline_mod.execute_pipeline(
            job_id="job_default_fio",
            code="y = 2\n",
            filename="x.py",
            use_llm=False,
            # file_io 미주입 — default None
        )

        assert len(calls) == 1, (
            f"default 경로 write_text 호출 회귀: {len(calls)} 회 "
            f"(기대 1회)"
        )
        path, content = calls[0]
        assert content == "y = 2\n", (
            f"default 경로 write_text content 회귀: {content!r}"
        )
        assert path.endswith(os.sep + "x.py"), (
            f"default 경로 write_text path 회귀: {path}"
        )

    def test_execute_pipeline_body_has_no_direct_open_w_call(self):
        """``execute_pipeline`` 본체 AST 에 ``open(..., 'w')`` 직접 호출이
        남아 있지 않다 — file_io seam 우회 회귀 가드."""
        import ast
        import inspect as _inspect
        from analyzer.pipeline import execute_pipeline

        src = _inspect.getsource(execute_pipeline)
        tree = ast.parse(src)

        offenders: list[int] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if not (isinstance(func, ast.Name) and func.id == "open"):
                continue
            mode_node = None
            if len(node.args) >= 2:
                mode_node = node.args[1]
            else:
                for kw in node.keywords:
                    if kw.arg == "mode":
                        mode_node = kw.value
                        break
            if (
                isinstance(mode_node, ast.Constant)
                and isinstance(mode_node.value, str)
                and "w" in mode_node.value
            ):
                offenders.append(node.lineno)

        assert offenders == [], (
            f"execute_pipeline 본체에 open(..., 'w') 직접 호출이 남아 있다 "
            f"(줄: {offenders}) — file_io seam 우회"
        )

    def test_existing_call_shape_preserved_without_file_io(
        self, stub_pipeline_io,
    ):
        """``file_io`` 인자 없이 기존 호출이 그대로 동작하고 결과 dict 의 키
        셰이프가 보존된다."""
        from analyzer.pipeline import execute_pipeline

        result = execute_pipeline(
            job_id="job_fio_shape",
            code="x = 1\n",
            filename="x.py",
            use_llm=False,
            provider="gemini",
            model="gemini-2.0-flash-lite",
            multi_patch=False,
        )

        assert result.language == "python"
        expected_keys = {
            "session_id", "repo", "pr_number", "commit_sha", "branch",
            "summary", "vulnerabilities", "patches",
            "started_at", "completed_at", "duration_seconds",
        }
        assert expected_keys.issubset(result.result_data.keys()), (
            f"result_data 키 회귀: "
            f"누락={expected_keys - set(result.result_data.keys())}"
        )
        assert result.result_data["session_id"] == "job_fio_shape"
