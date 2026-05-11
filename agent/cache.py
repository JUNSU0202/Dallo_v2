"""
LLM 응답 캐싱 모듈 (agent/cache.py)

동일 파일/취약점/문맥에 대한 LLM 호출을 캐싱하여 비용을 절감합니다.
Redis 사용 가능 시 Redis, 아니면 메모리 dict fallback.

캐시 키: sha256(file_content + rule_id + context_snippet)
"""

import hashlib
import json
import logging
import time
from typing import Callable, Optional

logger = logging.getLogger(__name__)

# 캐시 메트릭
_metrics = {"hits": 0, "misses": 0, "saves": 0}

# 기본 TTL: 7일 (초)
DEFAULT_TTL = 7 * 24 * 3600


def _make_cache_key(file_content: str, rule_id: str, context: str) -> str:
    """캐시 키를 생성합니다."""
    raw = f"{file_content}::{rule_id}::{context}"
    return f"dallo:llm_cache:{hashlib.sha256(raw.encode()).hexdigest()}"


class LLMCache:
    """LLM 응답 캐시 (Redis 우선, 메모리 fallback)"""

    def __init__(
        self,
        ttl: int = DEFAULT_TTL,
        *,
        clock: Optional[Callable[[], float]] = None,
    ):
        self._ttl = ttl
        self._clock: Callable[[], float] = time.time if clock is None else clock
        self._redis = None
        self._memory_cache: dict = {}

        try:
            import redis as redis_lib
            self._redis_error_cls = redis_lib.RedisError
            import os
            url = os.environ.get("CELERY_BROKER_URL", "redis://localhost:6379/0")
            # 캐시는 DB 2 사용 (broker=0, backend=1)
            url = url.rsplit("/", 1)[0] + "/2"
            self._redis = redis_lib.from_url(url, socket_connect_timeout=2)
            self._redis.ping()
            logger.info("[CACHE] Redis 캐시 연결됨")
        except ImportError:
            self._redis = None
            self._redis_error_cls = Exception
            logger.info("[CACHE] redis 패키지 미설치 — 메모리 캐시 모드")
        except Exception as e:
            self._redis = None
            self._redis_error_cls = Exception
            logger.info(f"[CACHE] Redis 연결 실패 — 메모리 캐시 모드 ({type(e).__name__})")

    def get(self, file_content: str, rule_id: str, context: str) -> Optional[dict]:
        """캐시에서 LLM 응답을 조회합니다."""
        key = _make_cache_key(file_content, rule_id, context)

        if self._redis:
            try:
                data = self._redis.get(key)
                if data:
                    _metrics["hits"] += 1
                    return json.loads(data)
            except self._redis_error_cls as e:
                logger.debug(f"[CACHE] Redis get 실패: {type(e).__name__}")
        else:
            entry = self._memory_cache.get(key)
            if entry and self._clock() < entry["expires"]:
                _metrics["hits"] += 1
                return entry["data"]
            elif entry:
                del self._memory_cache[key]

        _metrics["misses"] += 1
        return None

    def set(self, file_content: str, rule_id: str, context: str, response: dict):
        """LLM 응답을 캐시에 저장합니다."""
        key = _make_cache_key(file_content, rule_id, context)
        serialized = json.dumps(response, ensure_ascii=False)

        if self._redis:
            try:
                self._redis.setex(key, self._ttl, serialized)
                _metrics["saves"] += 1
                return
            except self._redis_error_cls as e:
                logger.debug(f"[CACHE] Redis set 실패: {type(e).__name__}")

        self._memory_cache[key] = {
            "data": response,
            "expires": self._clock() + self._ttl,
        }
        _metrics["saves"] += 1

    @staticmethod
    def get_metrics() -> dict:
        """캐시 히트/미스 메트릭을 반환합니다."""
        total = _metrics["hits"] + _metrics["misses"]
        hit_rate = (_metrics["hits"] / total * 100) if total > 0 else 0
        return {
            **_metrics,
            "total": total,
            "hit_rate_pct": round(hit_rate, 1),
        }
