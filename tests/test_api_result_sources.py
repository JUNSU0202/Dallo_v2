"""result_sources 헬퍼 단위 테스트 (tests/test_api_result_sources.py).

Wave 2-O: ``api/result_sources.py`` 의 하드닝 검증.

검증 포인트:
  - ``project_root()`` 가 absolute repo root 를 돌려준다.
  - ``REPORTS_DIR`` 기본값이 ``project_root()/reports`` 의 absolute path 이다
    (cwd 의존 제거).
  - ``load_bandit_report()`` / ``load_full_result()`` 는 파일 부재/JSON 파싱
    실패/dict 가 아닌 valid JSON 모두에 대해 안전한 기본값을 돌려준다.
  - 기존 monkeypatch (``result_sources.REPORTS_DIR = tmp_dir``) 패턴이
    여전히 동작한다.
  - ``result_sources`` 임포트는 ``api.server`` / FastAPI / ``db.service`` /
    ``analyzer`` 같은 무거운 모듈을 끌고 오지 않는다 (HTTP/DB 비의존).
"""

from __future__ import annotations

import ast
import inspect
import json
import os
import sys

import pytest


# ============================================================
# Import surface — result_sources 는 헬퍼 모듈로 가벼워야 한다
# ============================================================

class TestImportSurface:
    FORBIDDEN_TOP_LEVEL = {
        "fastapi",
        "fastapi.params",
        "api.server",
        "db.service",
        "analyzer",
    }

    def _module_source(self) -> str:
        from api import result_sources

        return inspect.getsource(result_sources)

    def test_module_does_not_import_forbidden_modules(self):
        tree = ast.parse(self._module_source())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for n in node.names:
                    assert n.name not in self.FORBIDDEN_TOP_LEVEL, (
                        f"result_sources 에서 {n.name} import 금지"
                    )
            elif isinstance(node, ast.ImportFrom):
                if node.module is None:
                    continue
                top = node.module.split(".")[0]
                # 부분 일치 검사도 함께
                assert node.module not in self.FORBIDDEN_TOP_LEVEL, (
                    f"result_sources 에서 from {node.module} import 금지"
                )
                assert top not in {"fastapi"}, (
                    f"result_sources 에서 from {node.module} import 금지"
                )

    def test_import_does_not_pull_fastapi_or_db_service(self):
        # 새 인터프리터 컨텍스트에서 검증하기 어려우므로, 같은 프로세스 내에서
        # api.server / db.service / analyzer 가 이미 로드되지 않은 상태에서만
        # 의미 있는 검사다. 여기서는 "import 후 sys.modules 에 강제 로드되는
        # 라인이 result_sources 소스에 없는지" 만을 정적 보증한다.
        src = self._module_source()
        for forbidden in ("api.server", "db.service", "analyzer", "fastapi"):
            assert f"import {forbidden}" not in src, (
                f"result_sources 가 {forbidden} 를 직접 import 하면 안 된다"
            )


# ============================================================
# project_root / REPORTS_DIR
# ============================================================

class TestProjectRootAndReportsDir:
    def test_project_root_is_absolute(self):
        from api import result_sources

        root = result_sources.project_root()
        assert os.path.isabs(root)

    def test_project_root_points_to_repo_root(self):
        from api import result_sources

        root = result_sources.project_root()
        # repo root 에는 'api' 와 'tests' 디렉터리가 같이 존재해야 한다.
        assert os.path.isdir(os.path.join(root, "api"))
        assert os.path.isdir(os.path.join(root, "tests"))

    def test_reports_dir_default_is_absolute_under_project_root(self):
        from api import result_sources

        # 기본값(monkeypatch 없음) 이 cwd 에 의존하지 않고 repo root 아래
        # 'reports' 를 가리켜야 한다.
        reports_dir = result_sources.REPORTS_DIR
        assert os.path.isabs(reports_dir), (
            "REPORTS_DIR 기본값은 absolute path 여야 한다 (cwd 의존 제거)"
        )
        expected = os.path.join(result_sources.project_root(), "reports")
        assert os.path.normpath(reports_dir) == os.path.normpath(expected)


# ============================================================
# Wave 3-C — DALLO_REPORTS_DIR env override + cwd 독립성
# ============================================================

def _reload_result_sources():
    """env 변경 후 ``api.result_sources`` 와 ``api.settings`` 를 함께 reload.

    ``from api import settings`` 는 ``api`` 패키지 네임스페이스에 ``settings``
    속성을 박제하므로 ``sys.modules.pop`` 만으로는 새로 환경변수를 반영한
    settings 가 되살아나지 않는다. ``importlib.reload`` 로 두 모듈을
    명시적으로 재실행시켜 새로운 env 값이 반영되게 한다.
    """
    import importlib
    import api
    import api.settings as settings_mod
    import api.result_sources as result_sources_mod

    importlib.reload(settings_mod)
    importlib.reload(result_sources_mod)
    # api.settings 와 api.result_sources 를 새 객체로 다시 바인딩.
    api.settings = sys.modules["api.settings"]
    api.result_sources = sys.modules["api.result_sources"]
    return sys.modules["api.result_sources"]


class TestReportsDirEnvOverride:
    """Wave 3-C: ``DALLO_REPORTS_DIR`` env override 와 cwd 독립성 검증."""

    def test_env_override_absolute_used_as_is(self, monkeypatch, tmp_path):
        target = str(tmp_path / "rep_abs")
        monkeypatch.setenv("DALLO_REPORTS_DIR", target)
        mod = _reload_result_sources()
        assert mod.REPORTS_DIR == target

    def test_env_override_relative_resolved_under_project_root(self, monkeypatch):
        monkeypatch.setenv("DALLO_REPORTS_DIR", "alt_reports")
        mod = _reload_result_sources()
        assert mod.REPORTS_DIR == os.path.join(mod.project_root(), "alt_reports")

    def test_default_reports_dir_independent_of_cwd(self, monkeypatch, tmp_path):
        """다른 cwd 에서 reload 해도 기본 REPORTS_DIR 은 PROJECT_ROOT 기준이다."""
        monkeypatch.delenv("DALLO_REPORTS_DIR", raising=False)
        monkeypatch.chdir(tmp_path)
        mod = _reload_result_sources()
        assert mod.REPORTS_DIR == os.path.join(mod.project_root(), "reports")

    def test_relative_env_reports_dir_independent_of_cwd(self, monkeypatch, tmp_path):
        """상대경로 env 도 cwd 가 아니라 PROJECT_ROOT 에 join 된다."""
        monkeypatch.setenv("DALLO_REPORTS_DIR", "rel_rep")
        monkeypatch.chdir(tmp_path)
        mod = _reload_result_sources()
        assert mod.REPORTS_DIR == os.path.join(mod.project_root(), "rel_rep")
        # cwd 의 상대경로(=tmp_path 안) 와는 다르다
        assert mod.REPORTS_DIR != os.path.join(str(tmp_path), "rel_rep")


# ============================================================
# load_bandit_report
# ============================================================

class TestLoadBanditReport:
    def _empty_shape(self) -> dict:
        return {"results": [], "metrics": {"_totals": {}}}

    def test_missing_file_returns_empty_shape(self, tmp_path, monkeypatch):
        from api import result_sources

        monkeypatch.setattr(result_sources, "REPORTS_DIR", str(tmp_path))
        # bandit_report.json 이 존재하지 않는다.
        assert result_sources.load_bandit_report() == self._empty_shape()

    def test_invalid_json_returns_empty_shape(self, tmp_path, monkeypatch):
        from api import result_sources

        monkeypatch.setattr(result_sources, "REPORTS_DIR", str(tmp_path))
        path = tmp_path / "bandit_report.json"
        path.write_text("{not: valid json", encoding="utf-8")

        # 깨진 JSON 이어도 raise 하지 않고 안전한 셰이프를 돌려준다.
        assert result_sources.load_bandit_report() == self._empty_shape()

    def test_non_dict_json_returns_empty_shape(self, tmp_path, monkeypatch):
        from api import result_sources

        monkeypatch.setattr(result_sources, "REPORTS_DIR", str(tmp_path))
        path = tmp_path / "bandit_report.json"
        path.write_text(json.dumps([1, 2, 3]), encoding="utf-8")

        # valid JSON 이지만 dict 가 아니면 fallback 으로 돌린다.
        assert result_sources.load_bandit_report() == self._empty_shape()

    def test_valid_dict_returned_unchanged(self, tmp_path, monkeypatch):
        from api import result_sources

        monkeypatch.setattr(result_sources, "REPORTS_DIR", str(tmp_path))
        payload = {
            "results": [{"issue_severity": "HIGH"}],
            "metrics": {"_totals": {"loc": 100}},
            "extra": "preserved",
        }
        (tmp_path / "bandit_report.json").write_text(
            json.dumps(payload), encoding="utf-8",
        )

        assert result_sources.load_bandit_report() == payload


# ============================================================
# load_full_result
# ============================================================

class TestLoadFullResult:
    def test_missing_file_returns_empty_dict(self, tmp_path, monkeypatch):
        from api import result_sources

        monkeypatch.setattr(result_sources, "REPORTS_DIR", str(tmp_path))
        assert result_sources.load_full_result() == {}

    def test_invalid_json_returns_empty_dict(self, tmp_path, monkeypatch):
        from api import result_sources

        monkeypatch.setattr(result_sources, "REPORTS_DIR", str(tmp_path))
        (tmp_path / "full_result.json").write_text(
            "{not valid", encoding="utf-8",
        )

        assert result_sources.load_full_result() == {}

    def test_non_dict_json_returns_empty_dict(self, tmp_path, monkeypatch):
        from api import result_sources

        monkeypatch.setattr(result_sources, "REPORTS_DIR", str(tmp_path))
        (tmp_path / "full_result.json").write_text(
            json.dumps(["a", "b"]), encoding="utf-8",
        )

        assert result_sources.load_full_result() == {}

    def test_valid_dict_returned_unchanged(self, tmp_path, monkeypatch):
        from api import result_sources

        monkeypatch.setattr(result_sources, "REPORTS_DIR", str(tmp_path))
        payload = {
            "session_id": "xyz",
            "summary": {"total": 1},
            "vulnerabilities": [{"id": 1}],
        }
        (tmp_path / "full_result.json").write_text(
            json.dumps(payload), encoding="utf-8",
        )

        assert result_sources.load_full_result() == payload


# ============================================================
# 기존 monkeypatch 호환성 — REPORTS_DIR 를 tmp dir 로 바꿔도 동작
# ============================================================

class TestMonkeypatchBackcompat:
    def test_monkeypatching_reports_dir_is_honored(self, tmp_path, monkeypatch):
        """기존 report 라우터 테스트가 사용하는 패턴이 깨지지 않아야 한다."""
        from api import result_sources

        target = tmp_path / "isolated"
        target.mkdir()
        monkeypatch.setattr(result_sources, "REPORTS_DIR", str(target))

        # 두 로더 모두 monkeypatched 디렉터리를 본다 — 부재 → 안전 fallback.
        assert result_sources.load_bandit_report() == {
            "results": [], "metrics": {"_totals": {}},
        }
        assert result_sources.load_full_result() == {}

        # 그 디렉터리에 파일을 쓰고 읽으면 그대로 반환된다.
        (target / "bandit_report.json").write_text(
            json.dumps({"results": [], "metrics": {"_totals": {"loc": 0}}}),
            encoding="utf-8",
        )
        assert result_sources.load_bandit_report() == {
            "results": [], "metrics": {"_totals": {"loc": 0}},
        }
