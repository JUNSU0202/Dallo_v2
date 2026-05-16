"""Wave 5-G — LLM optimization plumbing 계약 하드닝 TDD 테스트.

검증 대상:
  1. ``api.routers.analyze.LLMOptimizationRequest.model_fields`` /
     ``shared.llm_optimization.LLMOptimizationConfig`` dataclass 필드 /
     ``analyzer.pipeline._LLM_OPTIMIZATION_FIELDS`` 의 세 표면이 *정확히* 동일한
     필드 집합을 가진다 (drift 가드). 미래에 어느 한 쪽만 필드가 추가/이름변경
     /삭제되면 본 테스트가 RED 로 신호한다.
  2. 메모리 폴백 경로의 ``BackgroundTasks.add_task(_run_analysis, ...)`` 가
     positional 이 아닌 keyword 로 forwarding 한다. 시그니처가 미래에 바뀌어도
     wrong-slot 으로 값이 흘러 들어가지 않도록 한다.
  3. 파일 업로드 경로의 ``Thread(target=_run_analysis, ...)`` 가 ``args=()`` 가
     아닌 ``kwargs={...}`` 로 forwarding 하며, optimization slot 은 명시적으로
     ``None`` 으로 전달된다.

원칙:
  - 절대 실제 LLM/Celery/Redis/외부 API 를 호출하지 않는다.
  - shared/schemas.py 변경 금지.
  - Gemini / Google AI Studio 기본값 보존 (provider=gemini, model=gemini-2.0-flash-lite).
  - 본 테스트는 *plumbing 계약* 만 가드하며, 의미론 (필터/정렬/cap) 은 Wave 5-F
    의 기존 테스트가 그대로 가드한다.
"""

from __future__ import annotations

import dataclasses
import io

import pytest
from fastapi.testclient import TestClient

from analyzer.pipeline import _LLM_OPTIMIZATION_FIELDS
from api.routers import analyze as analyze_router
from api.routers.analyze import LLMOptimizationRequest
from api.server import app
from shared.llm_optimization import LLMOptimizationConfig


_AUTH_HEADERS = {"X-API-Key": "test-api-key"}
client = TestClient(app)


# ============================================================
# 1) 세 표면의 필드 집합 drift 가드
# ============================================================


class TestLLMOptimizationFieldDriftGuard:
    """``LLMOptimizationRequest`` (Pydantic) / ``LLMOptimizationConfig``
    (dataclass) / ``_LLM_OPTIMIZATION_FIELDS`` (tuple whitelist) 세 표면이
    동일 필드 집합을 가진다 — 한 쪽의 drift 가 다른 쪽을 silent 하게
    무효화하지 않도록 가드.
    """

    def _request_field_set(self) -> set[str]:
        return set(LLMOptimizationRequest.model_fields.keys())

    def _config_field_set(self) -> set[str]:
        return {f.name for f in dataclasses.fields(LLMOptimizationConfig)}

    def _pipeline_field_set(self) -> set[str]:
        return set(_LLM_OPTIMIZATION_FIELDS)

    def test_request_and_config_field_sets_equal(self):
        req = self._request_field_set()
        cfg = self._config_field_set()
        assert req == cfg, (
            f"LLMOptimizationRequest / LLMOptimizationConfig drift: "
            f"req only={req - cfg}, cfg only={cfg - req}"
        )

    def test_config_and_pipeline_whitelist_equal(self):
        cfg = self._config_field_set()
        pipe = self._pipeline_field_set()
        assert cfg == pipe, (
            f"LLMOptimizationConfig / _LLM_OPTIMIZATION_FIELDS drift: "
            f"cfg only={cfg - pipe}, pipe only={pipe - cfg}"
        )

    def test_request_and_pipeline_whitelist_equal(self):
        req = self._request_field_set()
        pipe = self._pipeline_field_set()
        assert req == pipe, (
            f"LLMOptimizationRequest / _LLM_OPTIMIZATION_FIELDS drift: "
            f"req only={req - pipe}, pipe only={pipe - req}"
        )

    def test_all_three_layers_share_expected_eight_fields(self):
        """필드 집합은 Wave 5-F 가 동결한 8 개 — 의도적 변경은 본 테스트의
        의도적 갱신을 강제한다 (silent expansion 차단)."""
        expected = {
            "enabled", "cve_scope", "cwe_scope", "rule_scope",
            "max_targets", "max_context_chars", "batch_enabled", "batch_size",
        }
        assert self._request_field_set() == expected
        assert self._config_field_set() == expected
        assert self._pipeline_field_set() == expected


# ============================================================
# 2) 메모리 폴백 — _run_analysis 가 kwargs 로 dispatch 되는지
# ============================================================


class TestMemoryRouteKeywordForwarding:
    """메모리 폴백 경로에서 ``background_tasks.add_task(_run_analysis, ...)``
    가 keyword 로 forwarding 되는지 검증. positional 로 우연한 slot 침범이
    일어나지 않음을 가드한다.
    """

    def test_memory_dispatch_uses_kwargs_for_llm_optimization(self, monkeypatch):
        captured: list[dict] = []

        def _spy(*args, **kwargs):
            captured.append({"args": args, "kwargs": kwargs})

        monkeypatch.setattr(analyze_router, "_USE_CELERY", False)
        monkeypatch.setattr(analyze_router, "_run_analysis", _spy)
        monkeypatch.setattr(analyze_router, "analysis_jobs", {})

        payload = {
            "code": "x=1\n", "filename": "x.py", "use_llm": False,
            "llm_optimization": {
                "enabled": True, "cwe_scope": ["SQLI"],
                "max_targets": 2, "max_context_chars": 800,
            },
        }
        r = client.post("/api/analyze", json=payload, headers=_AUTH_HEADERS)
        assert r.status_code == 200, r.text
        assert len(captured) == 1
        call = captured[0]

        # positional args 가 비어 있어야 한다 — 모든 값이 kwargs 로 전달
        assert call["args"] == (), (
            f"메모리 폴백 dispatch 가 positional args 를 사용함: {call['args']!r}"
        )
        # kwargs 에 모든 forwarding 필드가 있어야 한다
        expected_keys = {
            "job_id", "code", "filename",
            "use_llm", "provider", "model",
            "multi_patch", "llm_optimization",
        }
        assert expected_keys <= set(call["kwargs"].keys()), (
            f"kwargs 에 누락된 필드: {expected_keys - set(call['kwargs'].keys())}"
        )

        # optimization slot 은 kwargs 로만 전달되어야 한다
        forwarded = call["kwargs"]["llm_optimization"]
        assert forwarded is not None, "kwargs.llm_optimization 누락"
        # pydantic 모델 또는 dict 모두 허용 — 단 본 라우터는 인스턴스 그대로 전달한다
        assert hasattr(forwarded, "cwe_scope") or isinstance(forwarded, dict), (
            f"forwarded llm_optimization 타입 회귀: {type(forwarded)!r}"
        )

        # positional args 어디에도 optimization-like 객체가 새어 들어가지 않는다
        offenders = [
            a for a in call["args"]
            if (isinstance(a, dict) and "cwe_scope" in a)
            or hasattr(a, "cwe_scope")
        ]
        assert offenders == [], (
            f"positional args 로 optimization 이 새어 들어옴: {offenders}"
        )

    def test_memory_dispatch_uses_kwargs_when_optimization_omitted(
        self, monkeypatch,
    ):
        """payload 에 ``llm_optimization`` 이 없을 때도 모든 값은 kwargs 로
        전달되어야 하며, ``llm_optimization`` 은 ``None`` 으로 명시 전달된다.
        """
        captured: list[dict] = []

        def _spy(*args, **kwargs):
            captured.append({"args": args, "kwargs": kwargs})

        monkeypatch.setattr(analyze_router, "_USE_CELERY", False)
        monkeypatch.setattr(analyze_router, "_run_analysis", _spy)
        monkeypatch.setattr(analyze_router, "analysis_jobs", {})

        r = client.post(
            "/api/analyze",
            json={"code": "x=1\n", "filename": "x.py", "use_llm": False},
            headers=_AUTH_HEADERS,
        )
        assert r.status_code == 200, r.text
        assert len(captured) == 1
        call = captured[0]

        assert call["args"] == (), (
            f"omit 시에도 positional args 가 비어야 함: {call['args']!r}"
        )
        assert call["kwargs"].get("llm_optimization") is None, (
            f"omit 시 kwargs.llm_optimization 이 None 이 아님: "
            f"{call['kwargs'].get('llm_optimization')!r}"
        )

    def test_memory_dispatch_preserves_gemini_defaults(self, monkeypatch):
        """기본 provider/model 이 kwargs 로 그대로 전달되는지 — Wave 5-A §6
        Reject 정책 (gateway / claude-sonnet-4-6 미도입) 보존 가드."""
        captured: list[dict] = []

        def _spy(*args, **kwargs):
            captured.append({"args": args, "kwargs": kwargs})

        monkeypatch.setattr(analyze_router, "_USE_CELERY", False)
        monkeypatch.setattr(analyze_router, "_run_analysis", _spy)
        monkeypatch.setattr(analyze_router, "analysis_jobs", {})

        r = client.post(
            "/api/analyze",
            json={"code": "x=1\n", "filename": "x.py", "use_llm": False},
            headers=_AUTH_HEADERS,
        )
        assert r.status_code == 200
        assert len(captured) == 1
        kw = captured[0]["kwargs"]
        assert kw["provider"] == "gemini"
        assert kw["model"] == "gemini-2.0-flash-lite"


# ============================================================
# 3) 파일 업로드 — Thread(target=..., kwargs={...}) dispatch
# ============================================================


class TestFileUploadKeywordForwarding:
    """``/api/analyze/file`` 가 ``Thread(target=_run_analysis, kwargs={...})``
    형태로 모든 값을 keyword 로 dispatch 하는지 검증. positional ``args=(...)``
    형태는 미래의 slot 침범에 취약하므로 차단한다.
    """

    def test_upload_thread_uses_kwargs_only(self, monkeypatch):
        thread_calls: list[dict] = []

        class _FakeThread:
            def __init__(self, target=None, args=(), kwargs=None):
                self._target = target
                self._args = args
                self._kwargs = kwargs or {}
                thread_calls.append(
                    {
                        "target": target,
                        "args": tuple(args),
                        "kwargs": dict(kwargs or {}),
                    }
                )

            def start(self):
                # _run_analysis 는 monkeypatch 된 no-op 이지만, 안전을 위해
                # 본 Fake Thread 는 의도적으로 호출하지 않는다 — 메모리에
                # 기록만 한다.
                return None

        monkeypatch.setattr(analyze_router, "_run_analysis", lambda *a, **k: None)
        monkeypatch.setattr(analyze_router, "Thread", _FakeThread)
        monkeypatch.setattr(analyze_router, "analysis_jobs", {})

        files = {"file": ("upload.py", io.BytesIO(b"a=1\n"), "text/x-python")}
        r = client.post(
            "/api/analyze/file",
            headers=_AUTH_HEADERS,
            files=files,
            data={"use_llm": "false"},
        )
        assert r.status_code == 200, r.text
        data = r.json()
        assert set(data.keys()) == {"job_id", "status"}
        job_id = data["job_id"]

        # Thread 는 정확히 한 번 생성되어야 한다
        assert len(thread_calls) == 1
        call = thread_calls[0]
        # target 은 라우터의 _run_analysis (monkeypatch 된 no-op) 을 가리킨다
        assert call["target"] is analyze_router._run_analysis

        # positional args 는 비어 있어야 한다 (모든 값은 kwargs 로 전달)
        assert call["args"] == (), (
            f"파일 업로드 Thread 가 positional args 를 사용함: {call['args']!r}"
        )

        # kwargs 에 forwarding 필드 모두 존재
        kw = call["kwargs"]
        expected_keys = {
            "job_id", "code", "filename",
            "use_llm", "provider", "model",
            "multi_patch", "llm_optimization",
        }
        assert expected_keys <= set(kw.keys()), (
            f"upload Thread kwargs 에 누락된 필드: {expected_keys - set(kw.keys())}"
        )
        # 값 검증 — 기본값/입력값이 정확히 슬롯에 들어 있어야 한다
        assert kw["job_id"] == job_id
        assert kw["code"] == "a=1\n"
        assert kw["filename"] == "upload.py"
        assert kw["use_llm"] is False
        assert kw["provider"] == "gemini"
        assert kw["model"] == "gemini-2.0-flash-lite"
        assert kw["multi_patch"] is False
        assert kw["llm_optimization"] is None

        # positional args 에 optimization 이 새어 들어가지 않는다
        offenders = [
            a for a in call["args"]
            if (isinstance(a, dict) and "cwe_scope" in a)
            or hasattr(a, "cwe_scope")
        ]
        assert offenders == [], (
            f"upload Thread positional args 로 optimization 이 새어 들어옴: {offenders}"
        )
