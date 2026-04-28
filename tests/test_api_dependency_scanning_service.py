"""의존성 스캔 서비스 모듈 단위 테스트 (tests/test_api_dependency_scanning_service.py).

Wave 2-N: ``api/routers/dependencies.py`` 에서 비즈니스 로직을 분리한
``api.services.dependency_scanning`` 서비스의 단위 테스트.

검증 대상:
  - 서비스 모듈은 FastAPI / api.server 를 import 하지 않는다 (lazy import 외).
  - ``scan_dependencies_workflow`` 가 입력에 따라 올바른 분기를 선택한다.
    (requirements_text > package_json_text > project_path > project_root)
  - ``DependencyScanner`` 는 함수 호출 시점에 lazy import 되어, 테스트가
    ``analyzer.dependency_scanner`` 모듈을 monkeypatch 할 수 있다.
  - ``project_path`` 가 ``allowed_root`` 외부일 경우 스캐너가 호출되지 않고,
    기존 응답 셰이프와 동일한 안전 에러 결과 dict 가 반환된다.
"""

from __future__ import annotations

import os

import pytest

from api import result_sources


# ============================================================
# 가짜 DependencyScanner / 결과
# ============================================================

class _FakeScanResult:
    def __init__(self, tool: str, project_path: str = "", error: str | None = None):
        self.tool = tool
        self.project_path = project_path
        self.error = error

    def to_dict(self) -> dict:
        return {
            "tool": self.tool,
            "project_path": self.project_path,
            "summary": {
                "total_packages": 0,
                "total_vulnerabilities": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
            },
            "vulnerabilities": [],
            "packages": [],
            "error": self.error,
        }


class _FakeScanner:
    def __init__(self):
        self.calls = {
            "scan": [],
            "scan_requirements_text": [],
            "scan_package_json_text": [],
        }

    def scan(self, project_path: str):
        self.calls["scan"].append(project_path)
        return [_FakeScanResult(tool="pip-audit", project_path=project_path)]

    def scan_requirements_text(self, text: str):
        self.calls["scan_requirements_text"].append(text)
        return _FakeScanResult(tool="pip-audit", project_path="/tmp/fake-req")

    def scan_package_json_text(self, text: str):
        self.calls["scan_package_json_text"].append(text)
        return _FakeScanResult(tool="npm-audit", project_path="/tmp/fake-pkg")


@pytest.fixture
def fake_scanner(monkeypatch):
    import analyzer.dependency_scanner as ds_module

    instance = _FakeScanner()
    monkeypatch.setattr(ds_module, "DependencyScanner", lambda: instance)
    return instance


# ============================================================
# Import surface
# ============================================================

class TestServiceImportSurface:
    def test_service_module_does_not_import_api_server(self):
        import ast
        import inspect

        from api.services import dependency_scanning as svc

        tree = ast.parse(inspect.getsource(svc))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for n in node.names:
                    assert n.name != "api.server", "api.server 직접 import 금지"
            elif isinstance(node, ast.ImportFrom):
                assert node.module != "api.server", "from api.server import 금지"

    def test_service_module_does_not_import_fastapi(self):
        """서비스는 HTTP 계층(FastAPI) 의존을 가지지 않아야 한다."""
        import ast
        import inspect

        from api.services import dependency_scanning as svc

        tree = ast.parse(inspect.getsource(svc))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for n in node.names:
                    assert not n.name.startswith("fastapi"), "fastapi import 금지"
            elif isinstance(node, ast.ImportFrom):
                assert not (node.module or "").startswith("fastapi"), (
                    "fastapi import 금지"
                )

    def test_service_does_not_import_dependency_scanner_at_top_level(self):
        """``DependencyScanner`` 는 워크플로 호출 시점에만 lazy 하게 import 되어야 한다."""
        import ast
        import inspect

        from api.services import dependency_scanning as svc

        tree = ast.parse(inspect.getsource(svc))
        for node in tree.body:  # 모듈 최상위 import 만 검사
            if isinstance(node, ast.ImportFrom):
                assert node.module != "analyzer.dependency_scanner", (
                    "최상위에서 analyzer.dependency_scanner import 금지"
                )


# ============================================================
# scan_dependencies_workflow — 분기 선택
# ============================================================

class TestWorkflowBranching:
    def _call(self, **kw):
        from api.services.dependency_scanning import scan_dependencies_workflow
        return scan_dependencies_workflow(**kw)

    def test_requirements_text_takes_priority(self, fake_scanner):
        results = self._call(
            requirements_text="flask==2.0.0",
            package_json_text='{"dependencies": {}}',
            project_path="",
        )
        assert isinstance(results, list)
        assert len(results) == 1
        assert fake_scanner.calls["scan_requirements_text"] == ["flask==2.0.0"]
        assert fake_scanner.calls["scan_package_json_text"] == []
        assert fake_scanner.calls["scan"] == []

    def test_package_json_text_when_requirements_empty(self, fake_scanner):
        results = self._call(
            requirements_text="",
            package_json_text='{"dependencies": {"lodash": "4.17.0"}}',
            project_path="",
        )
        assert len(results) == 1
        assert fake_scanner.calls["scan_package_json_text"] == [
            '{"dependencies": {"lodash": "4.17.0"}}'
        ]
        assert fake_scanner.calls["scan"] == []
        assert fake_scanner.calls["scan_requirements_text"] == []

    def test_project_path_inside_allowed_root_is_scanned(self, fake_scanner):
        """project_path 가 allowed_root 내부에 있으면 그대로 스캐너에 전달."""
        allowed = result_sources.project_root()
        # 'api' 디렉토리는 project_root 안에 존재한다.
        target = os.path.join(allowed, "api")
        results = self._call(
            requirements_text="",
            package_json_text="",
            project_path=target,
        )
        assert len(results) == 1
        # scan() 은 정규화된 절대 경로를 받는다.
        assert fake_scanner.calls["scan"] == [os.path.realpath(target)]
        assert fake_scanner.calls["scan_requirements_text"] == []
        assert fake_scanner.calls["scan_package_json_text"] == []

    def test_default_falls_back_to_project_root(self, fake_scanner):
        """모든 입력이 비면 project_root 를 스캔."""
        results = self._call(
            requirements_text="",
            package_json_text="",
            project_path="",
        )
        assert len(results) == 1
        assert fake_scanner.calls["scan"] == [result_sources.project_root()]

    def test_nonexistent_project_path_falls_through_to_root(self, fake_scanner):
        """존재하지 않는 project_path 는 무시되고 project_root 로 폴백."""
        results = self._call(
            requirements_text="",
            package_json_text="",
            project_path="/__definitely_does_not_exist__/x",
        )
        assert len(results) == 1
        assert fake_scanner.calls["scan"] == [result_sources.project_root()]


# ============================================================
# project_path 보안 가드
# ============================================================

class TestProjectPathSafety:
    def _call(self, **kw):
        from api.services.dependency_scanning import scan_dependencies_workflow
        return scan_dependencies_workflow(**kw)

    def test_outside_allowed_root_is_rejected(self, fake_scanner, tmp_path):
        """allowed_root 바깥 디렉토리 경로는 스캐너에 전달되지 않아야 한다."""
        outside = tmp_path / "evil"
        outside.mkdir()

        results = self._call(
            requirements_text="",
            package_json_text="",
            project_path=str(outside),
        )

        # 스캐너의 외부 도구가 실행되어선 안 된다.
        assert fake_scanner.calls["scan"] == []
        assert fake_scanner.calls["scan_requirements_text"] == []
        assert fake_scanner.calls["scan_package_json_text"] == []

    def test_outside_allowed_root_returns_safe_error_result(self, fake_scanner, tmp_path):
        """거부되었더라도 응답 셰이프는 동일하게 유지되어야 한다."""
        outside = tmp_path / "evil"
        outside.mkdir()

        results = self._call(
            requirements_text="",
            package_json_text="",
            project_path=str(outside),
        )

        assert isinstance(results, list)
        assert len(results) == 1
        item = results[0]
        # 스캐너 결과 dict 와 동일한 키 셋
        assert set(item.keys()) >= {
            "tool", "project_path", "summary",
            "vulnerabilities", "packages", "error",
        }
        # 안전한 자리표시자
        assert item["tool"] == "none"
        assert item["project_path"] == ""
        assert item["vulnerabilities"] == []
        assert item["packages"] == []
        # 합계는 0
        for k in ("total_packages", "total_vulnerabilities",
                  "critical", "high", "medium", "low"):
            assert item["summary"][k] == 0
        # 에러는 일반 메시지(경로 자체를 그대로 노출하지 않는다)
        assert item["error"]
        assert "project_path" in item["error"]
        assert str(outside) not in item["error"]

    def test_traversal_attempt_is_rejected(self, fake_scanner, tmp_path):
        """``..`` 를 사용한 트래버설도 거부되어야 한다."""
        allowed = result_sources.project_root()
        traversal = os.path.join(allowed, "..")  # project_root 의 부모
        # 부모 디렉토리는 일반적으로 존재한다.
        assert os.path.exists(traversal)

        results = self._call(
            requirements_text="",
            package_json_text="",
            project_path=traversal,
        )

        assert fake_scanner.calls["scan"] == []
        assert results[0]["tool"] == "none"
        assert results[0]["error"]

    def test_custom_allowed_root_is_respected(self, fake_scanner, tmp_path):
        """allowed_root 인자로 임의 루트를 지정할 수 있다."""
        sandbox = tmp_path / "sandbox"
        sandbox.mkdir()
        sub = sandbox / "proj"
        sub.mkdir()

        results = self._call(
            requirements_text="",
            package_json_text="",
            project_path=str(sub),
            allowed_root=str(sandbox),
        )

        assert len(results) == 1
        assert fake_scanner.calls["scan"] == [os.path.realpath(str(sub))]


__all__: list[str] = []
