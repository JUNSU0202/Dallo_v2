"""Quick scan elapsed clock seam test (Wave 4-Y).

``api/routers/quick_scan.py`` 의 두 엔드포인트 (``POST /api/quick-scan``,
``POST /api/quick-scan-project``) 는 모두 elapsed_ms 측정을 위해
``start = time.time()`` / ``elapsed_ms = round((time.time() - start) * 1000, 1)``
형태로 직접 ``time.time()`` 을 두 번 호출했다. 이는 wall-clock 의존이라
``elapsed_ms`` 의 회귀 가드를 결정적으로 작성하기 어렵게 만든다.

본 Wave 는 모듈 레벨 ``_clock`` callable + ``set_clock`` / ``reset_clock``
헬퍼를 도입해, 두 엔드포인트가 동일한 seam(``_clock()``) 만 통과하도록
정리한다. ``_clock`` 의 기본 reference 는 여전히 ``time.time`` 이므로 운영
동작/응답 shape/인증 의존성/공개 URL/quick scan finding shape 는 모두 보존된다.

본 테스트는:

- fake clock 을 ``set_clock()`` 으로 주입했을 때 두 엔드포인트의
  ``elapsed_ms`` 가 결정적으로 고정되는지 검증한다 (각각 123.4 / 250.0).
- ``reset_clock()`` 이후 default 경로가 정상 동작하고 ``elapsed_ms`` 가
  여전히 숫자이며 응답 키 셋이 보존됨을 확인한다.
- AST 기반 guard: 두 endpoint 함수 body 에 직접 ``time.time()`` 호출이
  남아있지 않음을 정적으로 검증한다 (seam 우회 회귀 차단).
- 인증/응답 shape 보존: 기존 ``/api/quick-scan`` / ``/api/quick-scan-project``
  응답 키 셋과 ``scan_type='quick'`` 동결.

테스트 격리:
- fake clock 은 매 테스트 종료 시 ``reset_clock()`` 로 복귀 (autouse fixture).
- 실제 ``time.sleep`` / 외부 scanner / network 호출 없음.
"""

from __future__ import annotations

import ast
import inspect
import os
import sys
import textwrap

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# 인증 통과용 — TestClient import 이전에 설정해야 함.
os.environ.setdefault("DALLO_API_KEYS", "test-api-key")
os.environ.setdefault("DALLO_ENCRYPTION_KEY", "test-key")

from fastapi.testclient import TestClient

from api.routers import quick_scan as quick_scan_module
from api.server import app

_AUTH_HEADERS = {"X-API-Key": "test-api-key"}
client = TestClient(app)


# ============================================================
# Fixture — fake clock 누설 방지
# ============================================================

@pytest.fixture(autouse=True)
def _restore_quick_scan_clock_after_test():
    yield
    quick_scan_module.reset_clock()


# ============================================================
# Helpers — 단조 증가 fake clock
# ============================================================

def _ticking_clock(ticks):
    """주어진 시퀀스를 순서대로 반환하는 fake clock 을 만든다."""
    it = iter(ticks)

    def _clock():
        return next(it)

    return _clock


# ============================================================
# Test 1 — fake clock 으로 /api/quick-scan elapsed_ms 가 123.4 로 고정
# ============================================================

def test_quick_scan_elapsed_ms_is_deterministic_under_fake_clock():
    # start=1000.0, end=1000.1234 → 0.1234s → 123.4 ms
    quick_scan_module.set_clock(_ticking_clock([1000.0, 1000.1234]))

    payload = {
        "code": "import hashlib\nhashlib.md5(b'x')\n",
        "language": "python",
    }
    r = client.post("/api/quick-scan", json=payload, headers=_AUTH_HEADERS)

    assert r.status_code == 200
    data = r.json()
    assert data["elapsed_ms"] == 123.4, (
        f"fake clock 주입 시 elapsed_ms 가 123.4 여야 한다, got {data['elapsed_ms']}"
    )
    # 응답 shape 보존
    assert set(data.keys()) == {"findings", "count", "elapsed_ms", "scan_type"}
    assert data["scan_type"] == "quick"


# ============================================================
# Test 2 — fake clock 으로 /api/quick-scan-project elapsed_ms 가 250.0 으로 고정
# ============================================================

def test_quick_scan_project_elapsed_ms_is_deterministic_under_fake_clock():
    # start=2000.0, end=2000.25 → 0.25s → 250.0 ms
    quick_scan_module.set_clock(_ticking_clock([2000.0, 2000.25]))

    payload = {
        "files": [
            {"path": "a.py", "code": "import hashlib\nhashlib.md5(b'x')\n"},
            {"path": "b.js", "code": "Math.random();\n"},
        ]
    }
    r = client.post("/api/quick-scan-project", json=payload, headers=_AUTH_HEADERS)

    assert r.status_code == 200
    data = r.json()
    assert data["elapsed_ms"] == 250.0, (
        f"fake clock 주입 시 elapsed_ms 가 250.0 이어야 한다, got {data['elapsed_ms']}"
    )
    # 응답 shape 보존
    assert set(data.keys()) == {
        "files", "total_files", "total_findings", "summary", "elapsed_ms",
    }
    assert data["total_files"] == 2


# ============================================================
# Test 3 — reset_clock() 후 default 경로가 동작하고 응답 shape 보존
# ============================================================

def test_default_clock_path_after_reset_preserves_response_shape():
    quick_scan_module.set_clock(_ticking_clock([0.0, 0.5]))
    quick_scan_module.reset_clock()

    payload = {
        "code": "import hashlib\nhashlib.md5(b'x')\n",
        "language": "python",
    }
    r = client.post("/api/quick-scan", json=payload, headers=_AUTH_HEADERS)

    assert r.status_code == 200
    data = r.json()
    # 응답 shape (Wave 2-C 이래로 동결)
    assert set(data.keys()) == {"findings", "count", "elapsed_ms", "scan_type"}
    assert data["scan_type"] == "quick"
    assert isinstance(data["elapsed_ms"], (int, float))
    assert data["elapsed_ms"] >= 0.0
    # MD5 weak hash 룰이 살아 있는지(quick scan finding shape 동결)
    assert isinstance(data["findings"], list)
    assert data["count"] == len(data["findings"])
    assert any(f.get("rule_id") == "QS-WEAK-HASH" for f in data["findings"])
    for f in data["findings"]:
        assert {"rule_id", "title", "severity", "cwe", "line", "code", "message"} <= set(f.keys())


# ============================================================
# Test 4 — AST guard: 두 endpoint body 에 직접 time.time() 호출이 없다.
# ============================================================

def _calls_time_time_directly(src: str) -> bool:
    """함수 소스에 ``time.time()`` (Attribute call) 이 등장하는지 검사."""
    tree = ast.parse(textwrap.dedent(src))
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            f = node.func
            if (
                isinstance(f, ast.Attribute)
                and f.attr == "time"
                and isinstance(f.value, ast.Name)
                and f.value.id == "time"
            ):
                return True
    return False


def test_quick_scan_endpoint_body_has_no_direct_time_time_call():
    src = inspect.getsource(quick_scan_module.quick_scan)
    assert not _calls_time_time_directly(src), (
        "quick_scan endpoint 본문에 직접 time.time() 호출이 남아있다. "
        "_clock() seam 을 사용해야 한다."
    )


def test_quick_scan_project_endpoint_body_has_no_direct_time_time_call():
    src = inspect.getsource(quick_scan_module.quick_scan_project)
    assert not _calls_time_time_directly(src), (
        "quick_scan_project endpoint 본문에 직접 time.time() 호출이 남아있다. "
        "_clock() seam 을 사용해야 한다."
    )


# ============================================================
# Test 5 — 인증 미제공 시 401/403 (인증 의존성 보존)
# ============================================================

def test_quick_scan_still_requires_auth():
    r = client.post("/api/quick-scan", json={"code": "", "language": "python"})
    assert r.status_code in (401, 403)


def test_quick_scan_project_still_requires_auth():
    r = client.post("/api/quick-scan-project", json={"files": []})
    assert r.status_code in (401, 403)


# ============================================================
# Test 6 — set_clock / reset_clock seam 자체의 셰이프
# ============================================================

def test_clock_seam_helpers_exist_and_are_callable():
    assert callable(getattr(quick_scan_module, "_clock", None)), (
        "_clock seam 이 module 레벨에 존재해야 한다"
    )
    assert callable(getattr(quick_scan_module, "set_clock", None)), (
        "set_clock 헬퍼가 존재해야 한다"
    )
    assert callable(getattr(quick_scan_module, "reset_clock", None)), (
        "reset_clock 헬퍼가 존재해야 한다"
    )


def test_reset_clock_restores_time_time_default():
    import time as _time

    quick_scan_module.set_clock(lambda: 99999.0)
    assert quick_scan_module._clock() == 99999.0

    quick_scan_module.reset_clock()
    assert quick_scan_module._clock is _time.time, (
        "reset_clock() 이후 _clock 은 time.time 으로 복귀해야 한다"
    )
