"""Heuristic fallback activation regression guards (Wave 5-L)

본 wave 는 Wave 5-H3 에서 도입된 순수 (caller 0) heuristic 헬퍼
``analyzer.heuristic_runner.scan_text`` 를 ``analyzer.semgrep_runner.detect_and_run``
오케스트레이션 경로에서 활성화한다. 본 테스트는 활성화 이후의 불변식을
잠근다.

검증 항목:

1. ``.py`` 경로는 Bandit + Semgrep + heuristic 세 결과를 ``merge_results`` 로
   합쳐 반환한다 (외부 도구 호출은 fake 더블로 완전히 차단).
2. 지원 비-Python 경로 (``.js`` / ``.java``) 는 Semgrep + heuristic 두 결과를
   ``merge_results`` 로 합쳐 반환한다 (Bandit 미호출).
3. 미지원 확장자는 기존 ``AnalysisResult(tool="none", error=...)`` 셰이프 그대로,
   heuristic 경로의 파일 읽기도 발생하지 않는다.
4. FileIO 가 예외를 던지면 heuristic 결과는 0건으로 fail-closed 되고
   Bandit / Semgrep 결과는 그대로 보존된다 (전체 분석이 죽지 않는다).
5. Multi-config 튜플 ``('auto', <repo>/config/semgrep/dallo-local.yml)`` 가
   ``SemgrepRunner`` 에 그대로 전달된다 (Wave 5-H4 회귀).
6. AST/source 가드: ``analyzer/semgrep_runner.py`` 의 활성화 경로에 직접
   ``open(`` / ``.read()`` / ``.readlines()`` / ``subprocess.run(`` 같은 직접
   I/O / subprocess 호출이 새로 추가되지 않는다. heuristic 헬퍼
   ``analyzer/heuristic_runner.py`` 의 금지 토큰 셋도 보존된다.
7. heuristic finding 의 shape — ``tool='heuristic'`` / ``confidence='MEDIUM'`` /
   ``rule_id`` / ``severity`` / ``title`` / ``description`` / ``line_number`` /
   ``code_snippet`` / ``cwe_id`` / ``file_path=target_path`` — 가 보존된다.
8. ``.ts`` / ``.tsx`` 같은 quick_scan 이 JavaScript 룰 셋으로 매핑하는
   확장자에서도 heuristic 이 JavaScript 룰을 실제로 적용한다.

본 테스트는 실제 ``semgrep`` / ``bandit`` subprocess / 네트워크 / LLM / Celery /
Redis / DB / GitHub API 호출에 의존하지 않는다. 모든 외부 경계는 fake double
또는 pytest ``monkeypatch`` 로 차단된다.
"""

from __future__ import annotations

import ast
import json
import os
import sys
from typing import Optional

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyzer import semgrep_runner as semgrep_runner_mod
from analyzer.bandit_runner import AnalysisResult, Vulnerability
from analyzer.semgrep_runner import detect_and_run


REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# ============================================================
# 더블 — Bandit / Semgrep / FileIO / merge_results 마커
# ============================================================


class _FakeBanditRunner:
    instances: list["_FakeBanditRunner"] = []

    def __init__(self, *args, **kwargs):
        self.calls: list[str] = []
        type(self).instances.append(self)

    def run(self, target_path: str) -> AnalysisResult:
        self.calls.append(target_path)
        result = AnalysisResult(tool="bandit", target_path=target_path)
        # 가짜 bandit finding 1개를 넣어 merge 후에도 보존되는지 확인.
        result.vulnerabilities.append(
            Vulnerability(
                tool="bandit", rule_id="B999", severity="HIGH",
                confidence="HIGH", title="Bandit fake",
                description="bandit finding marker", file_path=target_path,
                line_number=1, code_snippet="bandit_marker_line",
                cwe_id="CWE-000",
            )
        )
        result.high_count = 1
        result.total_issues = 1
        return result


class _FakeSemgrepRunner:
    instances: list["_FakeSemgrepRunner"] = []

    def __init__(self, config="auto", runner=None, *, file_io=None):
        self.config = config
        self.calls: list[str] = []
        type(self).instances.append(self)

    def run(self, target_path: str, output_path=None) -> AnalysisResult:
        self.calls.append(target_path)
        result = AnalysisResult(tool="semgrep", target_path=target_path)
        result.vulnerabilities.append(
            Vulnerability(
                tool="semgrep", rule_id="SG-FAKE", severity="MEDIUM",
                confidence="HIGH", title="Semgrep fake",
                description="semgrep finding marker", file_path=target_path,
                line_number=2, code_snippet="semgrep_marker_line",
                cwe_id="CWE-111",
            )
        )
        result.medium_count = 1
        result.total_issues = 1
        return result


class _FakeFileIO:
    """``read_text_lines`` 만 fake — 호출 인자만 기록."""

    def __init__(self, lines: list[str]):
        self._lines = list(lines)
        self.read_calls: list[str] = []

    def read_text_lines(self, path: str) -> list[str]:
        self.read_calls.append(path)
        return list(self._lines)


class _RaisingFileIO:
    """``read_text_lines`` 가 항상 예외를 던지는 fake — 실패 경로 fail-closed 검증."""

    def __init__(self, exc: Exception):
        self._exc = exc
        self.read_calls: list[str] = []

    def read_text_lines(self, path: str) -> list[str]:
        self.read_calls.append(path)
        raise self._exc


@pytest.fixture
def patched_runners(monkeypatch):
    """``detect_and_run`` 내부에서 import 되는 ``BanditRunner`` /
    ``SemgrepRunner`` 만 fake 로 교체. ``merge_results`` 는 진짜 모듈을 사용해
    실제 vulnerability 리스트 병합을 검증한다."""
    _FakeBanditRunner.instances = []
    _FakeSemgrepRunner.instances = []

    import analyzer.bandit_runner as bandit_mod
    monkeypatch.setattr(bandit_mod, "BanditRunner", _FakeBanditRunner)
    monkeypatch.setattr(semgrep_runner_mod, "SemgrepRunner", _FakeSemgrepRunner)

    yield {
        "bandits": _FakeBanditRunner.instances,
        "semgreps": _FakeSemgrepRunner.instances,
    }


def _heuristic_vulns(result: AnalysisResult) -> list[Vulnerability]:
    return [v for v in result.vulnerabilities if v.tool == "heuristic"]


# ============================================================
# 1. Python 경로 — Bandit + Semgrep + heuristic 병합
# ============================================================


class TestPythonPathMergesBanditSemgrepAndHeuristic:
    def test_py_target_merges_three_results_with_heuristic_finding(
        self, patched_runners, tmp_path,
    ):
        # 사용자 입력 + os.system 결합 → quick_scan QS-CMD-INJECT 매치.
        code_lines = [
            "import os\n",
            "os.system('echo ' + user_input)\n",
        ]
        fake_io = _FakeFileIO(code_lines)
        py_target = str(tmp_path / "vuln.py")

        result = detect_and_run(py_target, file_io=fake_io)

        # Bandit + Semgrep 정확히 1회씩 호출되었다.
        assert len(patched_runners["bandits"]) == 1
        assert len(patched_runners["semgreps"]) == 1
        assert patched_runners["bandits"][0].calls == [py_target]
        assert patched_runners["semgreps"][0].calls == [py_target]

        # FileIO 가 정확히 한 번 호출되었다 (heuristic 경로의 단일 read).
        assert fake_io.read_calls == [py_target]

        # 결과 셰이프 — merge_results 가 호출되었음을 확인.
        assert result.tool == "merged"
        assert result.target_path == py_target

        # Bandit / Semgrep 마커 finding 보존.
        bandit_markers = [v for v in result.vulnerabilities if v.tool == "bandit"]
        semgrep_markers = [v for v in result.vulnerabilities if v.tool == "semgrep"]
        assert len(bandit_markers) == 1
        assert len(semgrep_markers) == 1

        # heuristic finding 이 최소 한 건 합쳐졌다.
        heuristics = _heuristic_vulns(result)
        assert heuristics, (
            "Python 경로 merge 결과에 heuristic finding 이 포함되어야 한다, "
            f"got tools={[v.tool for v in result.vulnerabilities]}"
        )
        # 룰 ID 는 QS- 접두사 (quick_scan 룰 ID).
        assert any(v.rule_id.startswith("QS-") for v in heuristics)


# ============================================================
# 2. 비-Python 지원 경로 — Semgrep + heuristic 병합 (Bandit 미호출)
# ============================================================


class TestNonPythonSupportedPathMergesSemgrepAndHeuristic:
    def test_js_target_merges_semgrep_and_heuristic_without_bandit(
        self, patched_runners, tmp_path,
    ):
        # JavaScript Math.random — QS-INSECURE-RANDOM (severity LOW) 매치.
        code_lines = [
            "var t = Math.random();\n",
        ]
        fake_io = _FakeFileIO(code_lines)
        js_target = str(tmp_path / "weak_random.js")

        result = detect_and_run(js_target, file_io=fake_io)

        # Bandit 은 호출되지 않는다.
        assert patched_runners["bandits"] == []
        # Semgrep 은 1회 호출.
        assert len(patched_runners["semgreps"]) == 1
        assert patched_runners["semgreps"][0].calls == [js_target]
        # 단일 FileIO read.
        assert fake_io.read_calls == [js_target]

        assert result.tool == "merged"
        assert result.target_path == js_target

        # Semgrep 마커 보존 + heuristic 한 건 이상.
        assert any(v.tool == "semgrep" for v in result.vulnerabilities)
        heuristics = _heuristic_vulns(result)
        assert heuristics, (
            "JS 경로 merge 결과에 heuristic finding 이 포함되어야 한다"
        )
        assert any(v.rule_id == "QS-INSECURE-RANDOM" for v in heuristics)

    def test_java_target_merges_semgrep_and_heuristic_without_bandit(
        self, patched_runners, tmp_path,
    ):
        # Java MessageDigest.getInstance("MD5") — QS-WEAK-HASH 매치.
        code_lines = [
            "MessageDigest md = MessageDigest.getInstance(\"MD5\");\n",
        ]
        fake_io = _FakeFileIO(code_lines)
        java_target = str(tmp_path / "Weak.java")

        result = detect_and_run(java_target, file_io=fake_io)

        assert patched_runners["bandits"] == []
        assert len(patched_runners["semgreps"]) == 1
        assert fake_io.read_calls == [java_target]

        assert result.tool == "merged"
        heuristics = _heuristic_vulns(result)
        assert any(v.rule_id == "QS-WEAK-HASH" for v in heuristics)


# ============================================================
# 3. 미지원 확장자 — heuristic 파일 read 없이 같은 unsupported 셰이프
# ============================================================


class TestUnsupportedExtensionDoesNotInvokeHeuristic:
    def test_unsupported_extension_preserves_none_shape_and_skips_file_io(
        self, patched_runners, tmp_path,
    ):
        fake_io = _FakeFileIO(["data\n"])
        unsupported = str(tmp_path / "weird.xyz")

        result = detect_and_run(unsupported, file_io=fake_io)

        assert patched_runners["bandits"] == []
        assert patched_runners["semgreps"] == []
        # 미지원 확장자에서는 heuristic 경로의 file read 도 발생하지 않는다.
        assert fake_io.read_calls == []

        assert result.tool == "none"
        assert result.target_path == unsupported
        assert result.error is not None
        assert ".xyz" in result.error


# ============================================================
# 4. FileIO 예외 — heuristic 만 0건 fail-closed, Bandit/Semgrep 보존
# ============================================================


class TestFileIoFailureKeepsHeuristicSilentButPreservesOtherResults:
    def test_filenotfound_during_read_falls_back_to_empty_heuristic(
        self, patched_runners, tmp_path,
    ):
        raising_io = _RaisingFileIO(FileNotFoundError("missing"))
        py_target = str(tmp_path / "missing_for_heuristic.py")

        result = detect_and_run(py_target, file_io=raising_io)

        # FileIO 가 한 번 시도되긴 했다 (호출 자체는 발생).
        assert raising_io.read_calls == [py_target]

        # Bandit / Semgrep 은 평소대로 호출되었고, 결과 finding 도 보존된다.
        assert len(patched_runners["bandits"]) == 1
        assert len(patched_runners["semgreps"]) == 1
        assert result.tool == "merged"
        assert any(v.tool == "bandit" for v in result.vulnerabilities)
        assert any(v.tool == "semgrep" for v in result.vulnerabilities)

        # heuristic 은 0건 — fail-closed.
        assert _heuristic_vulns(result) == [], (
            "FileIO 예외 시 heuristic finding 은 0건이어야 한다 (fail-closed), "
            f"got {[v.rule_id for v in _heuristic_vulns(result)]}"
        )

    def test_unicode_decode_error_during_read_falls_back_to_empty_heuristic(
        self, patched_runners, tmp_path,
    ):
        raising_io = _RaisingFileIO(
            UnicodeDecodeError("utf-8", b"\xff\xfe", 0, 1, "invalid start byte")
        )
        target = str(tmp_path / "binary.js")

        result = detect_and_run(target, file_io=raising_io)

        assert raising_io.read_calls == [target]
        # JS 경로 — Bandit 미호출, Semgrep 결과 보존.
        assert patched_runners["bandits"] == []
        assert len(patched_runners["semgreps"]) == 1
        assert any(v.tool == "semgrep" for v in result.vulnerabilities)
        assert _heuristic_vulns(result) == []


# ============================================================
# 5. multi-config 튜플은 SemgrepRunner 에 그대로 전달된다 (Wave 5-H4 회귀)
# ============================================================


class TestSemgrepMultiConfigStillForwarded:
    def test_python_path_still_forwards_auto_plus_local_yaml_tuple(
        self, patched_runners, tmp_path,
    ):
        fake_io = _FakeFileIO(["x = 1\n"])
        py_target = str(tmp_path / "ok.py")

        detect_and_run(py_target, file_io=fake_io)

        semgrep_fake = patched_runners["semgreps"][0]
        cfg = semgrep_fake.config
        cfg_list = list(cfg) if not isinstance(cfg, str) else [cfg]
        assert "auto" in cfg_list
        local_yaml_abs = os.path.abspath(
            os.path.join(REPO_ROOT, "config", "semgrep", "dallo-local.yml")
        )
        assert local_yaml_abs in cfg_list
        assert len(cfg_list) == 2

    def test_js_path_still_forwards_auto_plus_local_yaml_tuple(
        self, patched_runners, tmp_path,
    ):
        fake_io = _FakeFileIO(["var x = 1;\n"])
        js_target = str(tmp_path / "ok.js")

        detect_and_run(js_target, file_io=fake_io)

        semgrep_fake = patched_runners["semgreps"][0]
        cfg = semgrep_fake.config
        cfg_list = list(cfg) if not isinstance(cfg, str) else [cfg]
        local_yaml_abs = os.path.abspath(
            os.path.join(REPO_ROOT, "config", "semgrep", "dallo-local.yml")
        )
        assert "auto" in cfg_list
        assert local_yaml_abs in cfg_list
        assert len(cfg_list) == 2


# ============================================================
# 6. AST / source 가드 — semgrep_runner 활성화 경로에 직접 open / subprocess 없음
# ============================================================


_SEMGREP_RUNNER_SRC = (
    os.path.join(REPO_ROOT, "analyzer", "semgrep_runner.py")
)
_HEURISTIC_RUNNER_SRC = (
    os.path.join(REPO_ROOT, "analyzer", "heuristic_runner.py")
)


def _direct_open_call_count(source: str) -> int:
    """``open(...)`` 직접 호출 노드만 카운트 — ``self._file_io.write_json`` /
    ``io.read_text_lines`` 같은 메서드 호출은 제외."""
    tree = ast.parse(source)
    count = 0
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Name) and func.id == "open":
            count += 1
    return count


def _read_method_call_count(source: str) -> int:
    """``.read()`` 또는 ``.readlines()`` 호출 노드 수."""
    tree = ast.parse(source)
    count = 0
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr in {"read", "readlines"}:
            count += 1
    return count


def _subprocess_run_call_count(source: str) -> int:
    """``subprocess.run`` / ``subprocess.Popen`` / ``subprocess.call`` 호출 노드 수."""
    tree = ast.parse(source)
    count = 0
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if (
            isinstance(func, ast.Attribute)
            and isinstance(func.value, ast.Name)
            and func.value.id == "subprocess"
            and func.attr in {"run", "Popen", "call", "check_output", "check_call"}
        ):
            count += 1
    return count


class TestSemgrepRunnerActivationAvoidsDirectFileIoAndSubprocess:
    def test_semgrep_runner_module_has_no_direct_open_call(self):
        src = open(_SEMGREP_RUNNER_SRC, "r", encoding="utf-8").read()
        # 활성화 경로는 ``analyzer.file_io.FileIO`` 어댑터만 사용한다.
        assert _direct_open_call_count(src) == 0, (
            "analyzer/semgrep_runner.py 에 직접 open(...) 호출이 추가되어선 안 된다 "
            "(FileIO 어댑터 경계 우회 금지)"
        )

    def test_semgrep_runner_module_has_no_direct_read_or_readlines_call(self):
        src = open(_SEMGREP_RUNNER_SRC, "r", encoding="utf-8").read()
        assert _read_method_call_count(src) == 0, (
            "analyzer/semgrep_runner.py 에 직접 .read()/.readlines() 호출이 "
            "추가되어선 안 된다 (FileIO 어댑터 경계 우회 금지)"
        )

    def test_semgrep_runner_module_introduces_no_new_subprocess_call(self):
        src = open(_SEMGREP_RUNNER_SRC, "r", encoding="utf-8").read()
        # 기존 직접 subprocess.run/call/Popen 호출은 0건이어야 한다 (Wave 3-G 이후).
        assert _subprocess_run_call_count(src) == 0, (
            "analyzer/semgrep_runner.py 의 활성화 경로에 직접 subprocess 호출이 "
            "추가되어선 안 된다 (StaticToolCommandRunner 어댑터 우회 금지)"
        )

    def test_heuristic_runner_module_remains_pure_no_io_subprocess(self):
        # Wave 5-H3 의 금지 토큰 가드와 동일한 의도 — 활성화 wave 에서도
        # heuristic 헬퍼 자체는 순수 (I/O / 시간 / 시스템 의존 없음) 로 남아야 한다.
        src = open(_HEURISTIC_RUNNER_SRC, "r", encoding="utf-8").read()
        forbidden = (
            "open(",
            "os.walk",
            "subprocess",
            "requests",
            "time.",
            "datetime",
            "FastAPI",
            "api.server",
            "DALLO_",
            "os.environ",
            "eval(",
            "exec(",
            "pickle.loads",
            "shell=True",
        )
        for token in forbidden:
            assert token not in src, (
                f"analyzer/heuristic_runner.py 에 '{token}' 가 포함되면 안 된다"
            )


# ============================================================
# 7. heuristic finding 의 Vulnerability shape
# ============================================================


class TestHeuristicVulnerabilityShape:
    def test_heuristic_vulnerability_has_tool_and_confidence_and_metadata(
        self, patched_runners, tmp_path,
    ):
        code_lines = ["hashlib.md5(b'x')\n"]
        fake_io = _FakeFileIO(code_lines)
        py_target = str(tmp_path / "md5.py")

        result = detect_and_run(py_target, file_io=fake_io)

        heuristics = _heuristic_vulns(result)
        assert heuristics, "heuristic finding 이 최소 한 건 필요하다"
        v = next(h for h in heuristics if h.rule_id == "QS-WEAK-HASH")
        assert v.tool == "heuristic"
        assert v.confidence == "MEDIUM"
        assert v.severity == "MEDIUM"  # quick_scan WEAK-HASH severity
        assert v.cwe_id == "CWE-328"
        assert v.line_number == 1
        assert v.file_path == py_target
        assert "md5" in v.code_snippet.lower()
        # description 은 quick_scan 의 ``message`` 텍스트를 그대로 전달한다.
        assert v.description.strip() != ""
        # 한국어 메시지 키워드의 일부가 포함되어야 한다.
        assert "MD5" in v.description or "해시" in v.description


# ============================================================
# 8. .ts / .tsx → JavaScript 룰 적용 (quick_scan 의 detect_language 시맨틱)
# ============================================================


class TestTypeScriptUsesJavaScriptQuickScanRules:
    def test_ts_target_uses_javascript_rules_via_quick_scan_detect_language(
        self, patched_runners, tmp_path,
    ):
        # quick_scan QS-INSECURE-RANDOM 의 javascript 패턴 ``Math\.random\s*\(``.
        code_lines = ["const x = Math.random();\n"]
        fake_io = _FakeFileIO(code_lines)
        ts_target = str(tmp_path / "weak_random.ts")

        result = detect_and_run(ts_target, file_io=fake_io)

        # .ts 도 EXTENSION_MAP 에서 지원되므로 Bandit 없이 Semgrep + heuristic.
        assert patched_runners["bandits"] == []
        assert len(patched_runners["semgreps"]) == 1
        heuristics = _heuristic_vulns(result)
        # Semgrep 의 "typescript" 라벨이 아닌 quick_scan "javascript" 시맨틱이
        # 적용되어야 한다 — Math.random 매치는 javascript 룰 셋 안에만 있다.
        assert any(v.rule_id == "QS-INSECURE-RANDOM" for v in heuristics), (
            ".ts 파일에 quick_scan 의 javascript 룰셋이 적용되어야 한다 "
            f"(got {[v.rule_id for v in heuristics]})"
        )


# ============================================================
# 9. detect_and_run signature — file_io 는 keyword-only / default None
# ============================================================


class TestDetectAndRunFileIoSeam:
    def test_file_io_is_keyword_only_with_default_none(self):
        import inspect

        sig = inspect.signature(detect_and_run)
        assert "file_io" in sig.parameters
        param = sig.parameters["file_io"]
        assert param.kind is inspect.Parameter.KEYWORD_ONLY
        assert param.default is None

    def test_default_file_io_path_uses_get_default_file_io(
        self, patched_runners, tmp_path, monkeypatch,
    ):
        """``file_io`` 미주입 시 ``get_default_file_io()`` lazy default 가 사용된다."""
        sentinel_lines = ["hashlib.md5(b'x')\n"]
        sentinel_io = _FakeFileIO(sentinel_lines)
        monkeypatch.setattr(
            semgrep_runner_mod, "get_default_file_io", lambda: sentinel_io,
        )

        py_target = str(tmp_path / "default_io.py")

        result = detect_and_run(py_target)  # file_io 미주입

        assert sentinel_io.read_calls == [py_target]
        heuristics = _heuristic_vulns(result)
        assert any(v.rule_id == "QS-WEAK-HASH" for v in heuristics)


__all__: list[str] = []
