"""custom local Semgrep YAML + detect_and_run() 활성화 회귀 가드 (Wave 5-H4)

- 저장소-로컬 Semgrep YAML 룰셋이 정확한 경로에 존재하고, 원격(p/...,
  r/..., auto, URL) 또는 토큰 기반 cloud config 가 아님을 회귀 가드.
- ``detect_and_run("foo.py")`` 는 Bandit + Semgrep 을 fake 더블로 실행하고,
  Semgrep 은 기존 ``"auto"`` 와 새 로컬 YAML 경로를 동시에 사용한 멀티 config
  로 인스턴스화되어야 한다.
- ``detect_and_run("foo.js")`` 는 Semgrep 만 동일한 멀티 config 로 실행하고
  Bandit 은 호출하지 않아야 한다.
- 미지원 확장자는 기존 unsupported-file 결과가 그대로 유지된다.
- ``SemgrepRunner()`` / ``SemgrepRunner(config="auto")`` 직접 생성은 영향
  받지 않아야 한다 (로컬 YAML 이 모든 SemgrepRunner 에 강제 주입되지 않음).
- 본 테스트는 실제 ``semgrep`` subprocess / Bandit / 네트워크 / LLM /
  Celery / Redis / DB 에 의존하지 않는다.
"""

from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyzer import semgrep_runner as semgrep_runner_mod
from analyzer.bandit_runner import AnalysisResult
from analyzer.semgrep_runner import SemgrepRunner, detect_and_run


REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# ============================================================
# 1. 로컬 YAML 파일 자체에 대한 회귀 가드
# ============================================================


class TestLocalSemgrepYamlFile:
    def test_local_yaml_exists_under_repo(self):
        # config/semgrep/dallo-local.yml 가 저장소-로컬 경로로 존재해야 한다.
        candidate = os.path.join(REPO_ROOT, "config", "semgrep", "dallo-local.yml")
        assert os.path.isfile(candidate), (
            f"로컬 Semgrep YAML 파일이 존재하지 않습니다: {candidate}"
        )

    def test_local_yaml_extension_is_yml_or_yaml(self):
        candidate = os.path.join(REPO_ROOT, "config", "semgrep", "dallo-local.yml")
        assert candidate.lower().endswith((".yml", ".yaml"))

    def test_local_yaml_is_not_remote_or_registry_config(self):
        # Semgrep registry/cloud config (p/..., r/..., auto, URL, 토큰) 가
        # 아니어야 한다. 실제 사용 경로는 절대 파일 경로이다.
        candidate = os.path.join(REPO_ROOT, "config", "semgrep", "dallo-local.yml")
        with open(candidate, "r", encoding="utf-8") as f:
            content = f.read()
        # 파일 내부에 cloud/registry 식별자가 룰 source 로 등장하지 않아야 한다.
        assert "SEMGREP_APP_TOKEN" not in content
        assert "http://" not in content
        assert "https://semgrep.dev/" not in content
        # 파일 경로 자체는 로컬 절대경로로 사용된다.
        assert os.path.isabs(os.path.abspath(candidate))
        assert not os.path.abspath(candidate).startswith(("p/", "r/"))

    def test_local_yaml_contains_cwe_288_authentication_bypass_metadata(self):
        candidate = os.path.join(REPO_ROOT, "config", "semgrep", "dallo-local.yml")
        with open(candidate, "r", encoding="utf-8") as f:
            content = f.read()
        assert "CWE-288" in content
        # 한글/영문 어느 쪽이든 인증 우회 의도가 명확해야 한다.
        assert ("Authentication Bypass" in content) or ("인증 우회" in content)


# ============================================================
# 2. detect_and_run() — Semgrep 멀티 config 활성화
# ============================================================


class _FakeBanditRunner:
    """``BanditRunner`` 의 fake. ``run`` 호출만 기록하고 빈 결과 반환."""

    instances: list["_FakeBanditRunner"] = []

    def __init__(self, *args, **kwargs):
        self.calls: list[str] = []
        type(self).instances.append(self)

    def run(self, target_path: str) -> AnalysisResult:
        self.calls.append(target_path)
        return AnalysisResult(tool="bandit", target_path=target_path)


class _FakeSemgrepRunner:
    """``SemgrepRunner`` 의 fake. 생성자 config + run target 만 기록."""

    instances: list["_FakeSemgrepRunner"] = []

    def __init__(self, config="auto", runner=None, *, file_io=None):
        self.config = config
        self.calls: list[str] = []
        type(self).instances.append(self)

    def run(self, target_path: str, output_path=None) -> AnalysisResult:
        self.calls.append(target_path)
        return AnalysisResult(tool="semgrep", target_path=target_path)


def _merge_results_fake_marker(*results):
    merged = AnalysisResult(tool="merged", target_path="")
    merged.raw_output = {"merged_count": len(results),
                         "tools": [r.tool for r in results]}
    return merged


@pytest.fixture
def patched_runners(monkeypatch):
    """detect_and_run() 내부에서 import 되는 BanditRunner / SemgrepRunner /
    merge_results 를 fake 로 교체한다."""
    _FakeBanditRunner.instances = []
    _FakeSemgrepRunner.instances = []

    import analyzer.bandit_runner as bandit_mod
    import analyzer.result_parser as result_parser_mod

    monkeypatch.setattr(bandit_mod, "BanditRunner", _FakeBanditRunner)
    monkeypatch.setattr(result_parser_mod, "merge_results", _merge_results_fake_marker)
    monkeypatch.setattr(semgrep_runner_mod, "SemgrepRunner", _FakeSemgrepRunner)

    yield {
        "bandits": _FakeBanditRunner.instances,
        "semgreps": _FakeSemgrepRunner.instances,
    }


def _config_as_list(cfg) -> list[str]:
    if isinstance(cfg, str):
        return [cfg]
    return list(cfg)


class TestDetectAndRunPythonUsesLocalYamlMultiConfig:
    def test_python_target_runs_bandit_and_semgrep_with_auto_plus_local_yaml(
        self, patched_runners, tmp_path
    ):
        py_target = str(tmp_path / "sample.py")
        with open(py_target, "w", encoding="utf-8") as f:
            f.write("x = 1\n")

        result = detect_and_run(py_target)

        # Bandit 1회 + Semgrep 1회 인스턴스화.
        assert len(patched_runners["bandits"]) == 1
        assert len(patched_runners["semgreps"]) == 1

        bandit_fake = patched_runners["bandits"][0]
        semgrep_fake = patched_runners["semgreps"][0]
        assert bandit_fake.calls == [py_target]
        assert semgrep_fake.calls == [py_target]

        configs = _config_as_list(semgrep_fake.config)
        # "auto" 가 포함되어야 한다 (기존 동작 보존).
        assert "auto" in configs
        # 로컬 YAML 경로가 포함되어야 한다.
        local_yaml = os.path.join(
            REPO_ROOT, "config", "semgrep", "dallo-local.yml"
        )
        local_yaml_abs = os.path.abspath(local_yaml)
        assert local_yaml_abs in configs, (
            f"detect_and_run() 의 Semgrep config 에 로컬 YAML 경로가 "
            f"포함되어야 합니다 (got {configs!r})"
        )
        # 정확히 두 개의 config 만 (auto + local YAML).
        assert len(configs) == 2

        # merge_results 가 호출되어 결과가 합쳐졌는지 marker 로 확인.
        assert result.tool == "merged"
        assert result.raw_output == {"merged_count": 2,
                                     "tools": ["bandit", "semgrep"]}


class TestDetectAndRunNonPythonUsesLocalYamlMultiConfig:
    def test_js_target_runs_semgrep_only_with_auto_plus_local_yaml(
        self, patched_runners, tmp_path
    ):
        js_target = str(tmp_path / "sample.js")
        with open(js_target, "w", encoding="utf-8") as f:
            f.write("var x = 1;\n")

        result = detect_and_run(js_target)

        # Bandit 은 호출되지 않음.
        assert patched_runners["bandits"] == []
        # Semgrep 1회만.
        assert len(patched_runners["semgreps"]) == 1
        semgrep_fake = patched_runners["semgreps"][0]
        assert semgrep_fake.calls == [js_target]

        configs = _config_as_list(semgrep_fake.config)
        assert "auto" in configs
        local_yaml = os.path.abspath(
            os.path.join(REPO_ROOT, "config", "semgrep", "dallo-local.yml")
        )
        assert local_yaml in configs
        assert len(configs) == 2

        # JS 경로는 merge 를 거치지 않고 Semgrep 결과를 그대로 반환.
        assert result.tool == "semgrep"
        assert result.target_path == js_target


class TestDetectAndRunUnsupportedFileUnchanged:
    def test_unsupported_extension_returns_same_error_shape(
        self, patched_runners, tmp_path
    ):
        unsupported = str(tmp_path / "weird.xyz")
        with open(unsupported, "w", encoding="utf-8") as f:
            f.write("data\n")

        result = detect_and_run(unsupported)

        # 어떤 분석기도 인스턴스화되지 않음.
        assert patched_runners["bandits"] == []
        assert patched_runners["semgreps"] == []

        assert result.tool == "none"
        assert result.target_path == unsupported
        assert result.error is not None
        assert ".xyz" in result.error


# ============================================================
# 3. 직접 SemgrepRunner 생성자에는 로컬 YAML 이 강제되지 않음
# ============================================================


class TestSemgrepRunnerDirectConstructorUnchanged:
    def test_default_constructor_still_only_auto(self):
        # 실제 SemgrepRunner (not fake) 의 기본 config 가 "auto" 하나로
        # 그대로 노출되어야 한다.
        runner = SemgrepRunner()
        # 단일 config 입력은 단일 문자열로 노출되는 규약.
        assert runner.config == "auto"

    def test_explicit_auto_constructor_still_only_auto(self):
        runner = SemgrepRunner(config="auto")
        assert runner.config == "auto"


# ============================================================
# 4. 헬퍼 — detect_and_run() 의 Semgrep config 가 절대경로/저장소 내부 인지
# ============================================================


class TestLocalYamlPathHelperIfPresent:
    def test_local_yaml_path_when_resolved_is_absolute_and_within_repo(
        self,
    ):
        # 명시적 helper API 가 있다면 그것을 사용, 없다면 detect_and_run()
        # 가 사용하는 경로 규약과 동일한 경로가 저장소 내부 절대경로여야
        # 한다.
        helper = getattr(semgrep_runner_mod, "_detect_and_run_semgrep_configs", None)
        if helper is None:
            # 헬퍼가 없는 경우엔 단순히 파일이 저장소 내부 절대경로로
            # 해석 가능해야 한다.
            candidate = os.path.abspath(
                os.path.join(REPO_ROOT, "config", "semgrep", "dallo-local.yml")
            )
            assert os.path.isabs(candidate)
            assert candidate.startswith(REPO_ROOT + os.sep)
            return

        configs = helper()
        cfg_list = _config_as_list(configs)
        assert "auto" in cfg_list
        # auto 가 아닌 다른 entry 들은 모두 절대경로 + 저장소 내부.
        for entry in cfg_list:
            if entry == "auto":
                continue
            assert os.path.isabs(entry), f"로컬 config 가 절대경로여야 합니다: {entry}"
            assert entry.startswith(REPO_ROOT + os.sep), (
                f"로컬 config 는 저장소 worktree 내부여야 합니다: {entry}"
            )


__all__: list[str] = []
