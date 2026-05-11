"""LLMCache memory-fallback clock seam test (Wave 4-W).

``agent/cache.py::LLMCache`` 의 메모리 fallback 경로는 expiry 비교
(``time.time() < entry["expires"]``) 와 expires 기록
(``time.time() + self._ttl``) 두 군데에서 ``time.time()`` 을 직접
호출한다. Redis 가 사용 불가능한 환경에서는 이 두 호출이 캐시 만료
판정을 비결정적으로 만들어, "TTL 직전 / 직후" 경계 동작을 단위
테스트로 동결하기 어렵게 한다.

본 Wave 는 ``LLMCache.__init__`` 에 keyword-only ``clock`` 인자를
뚫어, 메모리 fallback 의 두 호출만 ``self._clock()`` 로 우회시킨다.
Redis 경로(``setex``)/TTL/응답 shape/``get()``·``set()`` 시그니처/메트릭
키는 모두 보존된다.

본 테스트는:
- fake clock 으로 메모리 fallback 의 만료 직전 hit / 만료 직후 miss
  를 결정적으로 검증한다.
- ``set()`` 이 ``expires = fake_now + ttl`` 을 기록함을 직접 확인한다.
- 기본 생성자 ``LLMCache(ttl=60)`` 가 legacy default clock 으로
  ``time.time`` 을 그대로 사용함을 확인한다 (회귀 방지).
- ``clock`` 인자가 keyword-only 임을 ``inspect.signature`` 로 동결한다.
- AST guard: ``LLMCache.get`` / ``LLMCache.set`` 본문에 직접
  ``time.time()`` 호출이 남아있지 않음을 검증한다.
- 외부 LLM / Redis / 네트워크 / 시크릿 등 어떤 외부 시스템에도
  접근하지 않는다.
"""

from __future__ import annotations

import ast
import inspect
import os
import sys
import textwrap
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent.cache import LLMCache


# ============================================================
# Helper — Redis 강제 미사용 (메모리 fallback 으로 강제)
# ============================================================

def _force_memory(cache: LLMCache) -> LLMCache:
    cache._redis = None
    return cache


# ============================================================
# Test 1 — fake clock 으로 메모리 fallback expiry 가 결정적이다.
# ============================================================

def test_memory_fallback_uses_injected_clock_for_expiry_boundary():
    ticks = [1000.0]

    def fake_clock() -> float:
        return ticks[0]

    cache = _force_memory(LLMCache(ttl=10, clock=fake_clock))
    cache.set("code", "B608", "ctx", {"fixed": "safe"})

    # 같은 시각 — hit
    assert cache.get("code", "B608", "ctx") == {"fixed": "safe"}

    # 만료 직전 — 여전히 hit
    ticks[0] = 1009.999
    assert cache.get("code", "B608", "ctx") == {"fixed": "safe"}

    # 만료 시각 (>=) — miss
    ticks[0] = 1010.0
    assert cache.get("code", "B608", "ctx") is None


# ============================================================
# Test 2 — set() 이 expires = fake_now + ttl 을 기록한다.
# ============================================================

def test_set_records_expires_as_fake_now_plus_ttl():
    fixed_now = 12345.0
    ttl = 60

    cache = _force_memory(LLMCache(ttl=ttl, clock=lambda: fixed_now))
    cache.set("c", "r", "ctx", {"v": 1})

    # 메모리 캐시에 단일 엔트리만 존재해야 함
    assert len(cache._memory_cache) == 1
    entry = next(iter(cache._memory_cache.values()))
    assert entry["data"] == {"v": 1}
    assert entry["expires"] == fixed_now + ttl


# ============================================================
# Test 3 — 기본 생성자(legacy)는 time.time 을 default clock 으로 쓴다.
# ============================================================

def test_default_constructor_uses_time_time_as_clock():
    cache = LLMCache(ttl=60)
    assert cache._clock is time.time


# ============================================================
# Test 4 — clock 은 keyword-only 인자다.
# ============================================================

def test_clock_argument_is_keyword_only():
    sig = inspect.signature(LLMCache.__init__)
    params = sig.parameters
    assert "clock" in params, "LLMCache.__init__ 에 clock 인자가 있어야 한다"
    assert params["clock"].kind is inspect.Parameter.KEYWORD_ONLY, (
        "clock 인자는 keyword-only 이어야 한다"
    )

    # 위치 인자로 넘기면 TypeError 가 나야 한다
    with pytest.raises(TypeError):
        LLMCache(60, lambda: 0.0)  # type: ignore[misc]


# ============================================================
# Test 5 — AST guard: LLMCache.get / set 본문에 직접 time.time() 호출이 없다.
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


def test_llm_cache_get_body_has_no_direct_time_time_call():
    src = inspect.getsource(LLMCache.get)
    assert not _calls_time_time_directly(src), (
        "LLMCache.get 본문에 직접 time.time() 호출이 남아있다. "
        "self._clock() seam 을 사용해야 한다."
    )


def test_llm_cache_set_body_has_no_direct_time_time_call():
    src = inspect.getsource(LLMCache.set)
    assert not _calls_time_time_directly(src), (
        "LLMCache.set 본문에 직접 time.time() 호출이 남아있다. "
        "self._clock() seam 을 사용해야 한다."
    )


# ============================================================
# Test 6 — clock 어노테이션 셰이프 (Callable[[], float] 류)
# ============================================================

def test_clock_parameter_is_optional_callable():
    sig = inspect.signature(LLMCache.__init__)
    clock_param = sig.parameters["clock"]
    # 기본값은 None (Optional)
    assert clock_param.default is None
