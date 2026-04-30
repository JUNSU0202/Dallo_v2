"""analysis_jobs_store 서비스 단위 테스트 (tests/test_api_analysis_jobs_store_service.py).

Wave 3-D: ``api.routers.analyze.analysis_jobs`` 메모리 폴백의 무한 증가
위험을 줄이기 위해 분리한 ``api.services.analysis_jobs_store`` 의 정리
헬퍼 (TTL / 캡 / fail-safe / 설정 주입) 동작을 보장한다.

검증 대상:
  - 모듈은 FastAPI / api.server 를 import 하지 않는다.
  - TTL 만료된 잡만 제거한다 (활성/신규 잡은 보존).
  - 캡 초과 시 ``created_at`` 기준 가장 오래된 잡부터 제거한다.
  - 누락/말썽있는 ``created_at`` 은 라우터를 깨뜨리지 않는다 (TTL 패스에서
    제거하지 않고, 캡 패스에서는 가장 새것으로 취급되어 보호된다).
  - ``exclude_ids`` 로 보호 대상을 명시할 수 있다 (방금 만든 잡 / 조회 중인 잡).
  - ``now`` / ``ttl_seconds`` / ``max_size`` 가 인자로 주입 가능하다 (결정적 테스트).
  - 환경변수 ``DALLO_ANALYSIS_JOBS_MAX`` / ``DALLO_ANALYSIS_JOBS_TTL_SECONDS``
    가 호출 시점에 다시 읽힌다 (이름 박제 금지).
"""

from __future__ import annotations

import ast
import inspect
from datetime import datetime, timedelta


# ============================================================
# Import surface
# ============================================================


class TestServiceImportSurface:
    def _module_source(self) -> str:
        from api.services import analysis_jobs_store as svc

        return inspect.getsource(svc)

    def test_module_does_not_import_api_server(self):
        tree = ast.parse(self._module_source())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for n in node.names:
                    assert n.name != "api.server", "api.server 직접 import 금지"
            elif isinstance(node, ast.ImportFrom):
                assert node.module != "api.server", "from api.server import 금지"

    def test_module_does_not_import_fastapi(self):
        tree = ast.parse(self._module_source())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for n in node.names:
                    assert not n.name.startswith("fastapi"), "fastapi import 금지"
            elif isinstance(node, ast.ImportFrom):
                assert not (node.module or "").startswith("fastapi"), (
                    "fastapi from-import 금지"
                )

    def test_public_surface(self):
        from api.services import analysis_jobs_store as svc

        for name in (
            "DEFAULT_MAX_JOBS",
            "DEFAULT_TTL_SECONDS",
            "get_default_max_jobs",
            "get_default_ttl_seconds",
            "cleanup",
        ):
            assert hasattr(svc, name), f"공개 표면 누락: {name}"


# ============================================================
# 헬퍼
# ============================================================


def _meta(job_id: str, created_at) -> dict:
    """잡 메타 픽스처 — created_at 만 핵심이라 최소 셰이프."""
    if isinstance(created_at, datetime):
        created_at_str = created_at.isoformat()
    else:
        created_at_str = created_at
    return {
        "job_id": job_id,
        "status": "queued",
        "step": "...",
        "created_at": created_at_str,
        "result": None,
        "error": None,
    }


# ============================================================
# TTL 동작
# ============================================================


class TestCleanupTTL:
    def test_expired_jobs_removed(self):
        from api.services.analysis_jobs_store import cleanup

        now = datetime(2026, 4, 30, 12, 0, 0)
        jobs = {
            "old": _meta("old", now - timedelta(seconds=7200)),  # 2h ago
            "fresh": _meta("fresh", now - timedelta(seconds=10)),  # 10s ago
        }

        removed = cleanup(jobs, max_size=1000, ttl_seconds=3600, now=now)

        assert removed == 1
        assert "old" not in jobs
        assert "fresh" in jobs

    def test_fresh_jobs_preserved(self):
        from api.services.analysis_jobs_store import cleanup

        now = datetime(2026, 4, 30, 12, 0, 0)
        jobs = {
            "j1": _meta("j1", now - timedelta(seconds=10)),
            "j2": _meta("j2", now - timedelta(seconds=60)),
            "j3": _meta("j3", now),  # exactly now
        }

        removed = cleanup(jobs, max_size=1000, ttl_seconds=3600, now=now)

        assert removed == 0
        assert set(jobs.keys()) == {"j1", "j2", "j3"}

    def test_ttl_disabled_when_zero(self):
        """ttl_seconds=0 이면 TTL 패스 비활성 (예전 잡도 살아남는다)."""
        from api.services.analysis_jobs_store import cleanup

        now = datetime(2026, 4, 30, 12, 0, 0)
        jobs = {"ancient": _meta("ancient", datetime(2000, 1, 1))}

        removed = cleanup(jobs, max_size=1000, ttl_seconds=0, now=now)

        assert removed == 0
        assert "ancient" in jobs

    def test_exclude_ids_protects_expired_job(self):
        """exclude_ids 에 든 잡은 TTL 만료여도 제거되지 않는다."""
        from api.services.analysis_jobs_store import cleanup

        now = datetime(2026, 4, 30, 12, 0, 0)
        jobs = {
            "protected": _meta("protected", now - timedelta(seconds=99999)),
            "old2": _meta("old2", now - timedelta(seconds=99999)),
        }

        removed = cleanup(
            jobs, max_size=1000, ttl_seconds=3600, now=now,
            exclude_ids=("protected",),
        )

        assert removed == 1
        assert "protected" in jobs
        assert "old2" not in jobs


# ============================================================
# 캡 (max_size) 동작
# ============================================================


class TestCleanupCap:
    def test_cap_prunes_oldest_first(self):
        from api.services.analysis_jobs_store import cleanup

        now = datetime(2026, 4, 30, 12, 0, 0)
        # 5개의 잡, 모두 TTL 만료 안 됨
        jobs = {
            f"j{i}": _meta(f"j{i}", now - timedelta(seconds=i * 10))
            for i in range(5)
        }
        # j0 = 가장 새것, j4 = 가장 오래됨

        removed = cleanup(jobs, max_size=2, ttl_seconds=3600, now=now)

        # 5개 중 3개가 제거되어야 한다 (가장 오래된 3개)
        assert removed == 3
        assert len(jobs) == 2
        # 가장 새 두 개는 살아남아야 한다
        assert "j0" in jobs
        assert "j1" in jobs
        # 오래된 세 개는 제거되어야 한다
        assert "j2" not in jobs
        assert "j3" not in jobs
        assert "j4" not in jobs

    def test_cap_does_nothing_below_threshold(self):
        from api.services.analysis_jobs_store import cleanup

        now = datetime(2026, 4, 30, 12, 0, 0)
        jobs = {
            "j1": _meta("j1", now - timedelta(seconds=10)),
            "j2": _meta("j2", now - timedelta(seconds=20)),
        }

        removed = cleanup(jobs, max_size=10, ttl_seconds=3600, now=now)

        assert removed == 0
        assert len(jobs) == 2

    def test_cap_disabled_when_zero(self):
        """max_size=0 이면 캡 패스 비활성."""
        from api.services.analysis_jobs_store import cleanup

        now = datetime(2026, 4, 30, 12, 0, 0)
        jobs = {
            f"j{i}": _meta(f"j{i}", now - timedelta(seconds=i))
            for i in range(50)
        }

        removed = cleanup(jobs, max_size=0, ttl_seconds=0, now=now)

        assert removed == 0
        assert len(jobs) == 50

    def test_exclude_ids_protects_from_cap(self):
        """exclude_ids 에 든 잡은 캡 패스에서도 제거되지 않는다."""
        from api.services.analysis_jobs_store import cleanup

        now = datetime(2026, 4, 30, 12, 0, 0)
        # j0 가 가장 오래된 잡(보호 대상). 그래도 보호된다.
        jobs = {
            f"j{i}": _meta(f"j{i}", now - timedelta(seconds=(10 - i) * 10))
            for i in range(5)
        }

        removed = cleanup(
            jobs, max_size=1, ttl_seconds=3600, now=now,
            exclude_ids=("j0",),
        )

        assert "j0" in jobs, "exclude 된 잡이 캡 패스에서 제거됨"
        # 5 → 1 + protected 1 = 2 entries left? No: max_size=1 means we want
        # at most 1 prunable entry, but protected entries don't count towards
        # the cap budget. We just shouldn't touch j0. Implementation prunes
        # `len(jobs) - max_size = 4` from prunable list of 4. So 4 removed,
        # 1 (j0) left.
        assert len(jobs) == 1
        assert removed == 4


# ============================================================
# Fail-safe — 누락/말썽있는 created_at
# ============================================================


class TestCleanupMalformedTimestamps:
    def test_missing_created_at_does_not_crash(self):
        from api.services.analysis_jobs_store import cleanup

        now = datetime(2026, 4, 30, 12, 0, 0)
        jobs = {
            "no_ts": {"job_id": "no_ts", "status": "queued"},  # no created_at
            "good": _meta("good", now - timedelta(seconds=10)),
        }

        removed = cleanup(jobs, max_size=1000, ttl_seconds=3600, now=now)

        # 누락된 ts 는 TTL 로 제거하지 않는다
        assert removed == 0
        assert "no_ts" in jobs
        assert "good" in jobs

    def test_malformed_created_at_does_not_crash(self):
        from api.services.analysis_jobs_store import cleanup

        now = datetime(2026, 4, 30, 12, 0, 0)
        jobs = {
            "bad1": _meta("bad1", "not-an-iso-string"),
            "bad2": _meta("bad2", "2026-13-99"),
            "bad3": _meta("bad3", ""),
            "bad4": _meta("bad4", None),
            "good": _meta("good", now - timedelta(seconds=10)),
        }

        # Should not raise
        removed = cleanup(jobs, max_size=1000, ttl_seconds=3600, now=now)

        assert removed == 0
        for k in ("bad1", "bad2", "bad3", "bad4", "good"):
            assert k in jobs

    def test_non_dict_meta_does_not_crash(self):
        """잡 메타가 dict 가 아닌 이상한 값이어도 cleanup 이 죽지 않는다."""
        from api.services.analysis_jobs_store import cleanup

        now = datetime(2026, 4, 30, 12, 0, 0)
        jobs = {"weird": "not-a-dict", "good": _meta("good", now)}

        removed = cleanup(jobs, max_size=1000, ttl_seconds=3600, now=now)

        # 비정상 메타는 TTL 로 제거되지 않는다 (created_at 파싱 실패)
        assert removed == 0
        assert "weird" in jobs

    def test_malformed_treated_as_newest_for_cap(self):
        """캡 초과 시 created_at 파싱 실패한 잡은 가장 새것 취급(= 보존된다)."""
        from api.services.analysis_jobs_store import cleanup

        now = datetime(2026, 4, 30, 12, 0, 0)
        jobs = {
            "bad": _meta("bad", "garbage"),
            "old": _meta("old", now - timedelta(seconds=30)),
            "new": _meta("new", now - timedelta(seconds=5)),
        }

        removed = cleanup(jobs, max_size=2, ttl_seconds=3600, now=now)

        assert removed == 1
        # 'old' 가 가장 오래된 파싱 가능 잡이므로 제거됨
        assert "old" not in jobs
        assert "bad" in jobs
        assert "new" in jobs


# ============================================================
# 환경변수 / 기본값 — 호출 시점에 다시 읽기
# ============================================================


class TestEnvDrivenDefaults:
    def test_env_max_overrides_default(self, monkeypatch):
        from api.services import analysis_jobs_store as svc

        monkeypatch.setenv("DALLO_ANALYSIS_JOBS_MAX", "7")
        assert svc.get_default_max_jobs() == 7

    def test_env_ttl_overrides_default(self, monkeypatch):
        from api.services import analysis_jobs_store as svc

        monkeypatch.setenv("DALLO_ANALYSIS_JOBS_TTL_SECONDS", "120")
        assert svc.get_default_ttl_seconds() == 120

    def test_invalid_env_falls_back_to_default(self, monkeypatch):
        from api.services import analysis_jobs_store as svc

        monkeypatch.setenv("DALLO_ANALYSIS_JOBS_MAX", "not-a-number")
        assert svc.get_default_max_jobs() == svc.DEFAULT_MAX_JOBS

        monkeypatch.setenv("DALLO_ANALYSIS_JOBS_TTL_SECONDS", "abc")
        assert svc.get_default_ttl_seconds() == svc.DEFAULT_TTL_SECONDS

    def test_negative_env_falls_back_to_default(self, monkeypatch):
        from api.services import analysis_jobs_store as svc

        monkeypatch.setenv("DALLO_ANALYSIS_JOBS_MAX", "-3")
        assert svc.get_default_max_jobs() == svc.DEFAULT_MAX_JOBS

    def test_cleanup_uses_env_defaults_when_args_omitted(self, monkeypatch):
        """``max_size`` / ``ttl_seconds`` 인자를 안 주면 env-driven 기본값 사용."""
        from api.services.analysis_jobs_store import cleanup

        monkeypatch.setenv("DALLO_ANALYSIS_JOBS_MAX", "2")
        monkeypatch.setenv("DALLO_ANALYSIS_JOBS_TTL_SECONDS", "3600")

        now = datetime(2026, 4, 30, 12, 0, 0)
        jobs = {
            f"j{i}": _meta(f"j{i}", now - timedelta(seconds=i))
            for i in range(5)
        }
        removed = cleanup(jobs, now=now)

        # 5 → 2 (env 기본 max=2)
        assert len(jobs) == 2
        assert removed == 3


# ============================================================
# 인자 검증 — 시계/캡/TTL 주입 가능
# ============================================================


class TestCleanupInjectableArgs:
    def test_now_is_injectable(self):
        """``now`` 를 주입하면 wall-clock 변동에 무관하게 결정적으로 동작."""
        from api.services.analysis_jobs_store import cleanup

        fixed_now = datetime(2026, 4, 30, 0, 0, 0)
        jobs = {
            "j1": _meta("j1", fixed_now - timedelta(seconds=5000)),
            "j2": _meta("j2", fixed_now - timedelta(seconds=10)),
        }
        cleanup(jobs, max_size=1000, ttl_seconds=3600, now=fixed_now)
        assert "j1" not in jobs
        assert "j2" in jobs

    def test_returns_removed_count(self):
        from api.services.analysis_jobs_store import cleanup

        now = datetime(2026, 4, 30, 12, 0, 0)
        jobs = {
            f"j{i}": _meta(f"j{i}", now - timedelta(seconds=10000))
            for i in range(3)
        }
        removed = cleanup(jobs, max_size=1000, ttl_seconds=3600, now=now)
        assert removed == 3

    def test_empty_jobs_safe(self):
        from api.services.analysis_jobs_store import cleanup

        jobs: dict = {}
        removed = cleanup(jobs, max_size=10, ttl_seconds=60)
        assert removed == 0
        assert jobs == {}
