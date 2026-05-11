"""
API 인증 테스트 (tests/test_auth.py)

- API Key 미설정 시 인증 통과 (개발 환경)
- 유효 키로 통과
- 무효 키로 401
- 키 누락 시 401
- 타이밍 공격 방지 (상수 시간 비교 사용 확인)
"""

import os
import asyncio
import pytest
from unittest.mock import patch


def _run(coro):
    """async 함수를 동기로 실행하는 헬퍼"""
    return asyncio.run(coro)


class TestVerifyApiKey:
    """API Key 검증 로직 테스트"""

    def test_no_keys_configured_allows_access(self):
        """DALLO_API_KEYS 미설정 시 인증 없이 통과 (개발 환경)"""
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("DALLO_API_KEYS", None)
            from api.auth import verify_api_key
            result = _run(verify_api_key(api_key="any-key"))
            assert result == "no-auth-configured"

    def test_valid_key_passes(self):
        """유효 키로 통과"""
        with patch.dict(os.environ, {"DALLO_API_KEYS": "key-alpha,key-beta"}):
            from api.auth import verify_api_key
            result = _run(verify_api_key(api_key="key-alpha"))
            assert result == "key-alpha"

    def test_invalid_key_returns_401(self):
        """무효 키로 401 반환"""
        with patch.dict(os.environ, {"DALLO_API_KEYS": "valid-key"}):
            from api.auth import verify_api_key
            from fastapi import HTTPException
            with pytest.raises(HTTPException) as exc_info:
                _run(verify_api_key(api_key="wrong-key"))
            assert exc_info.value.status_code == 401

    def test_missing_key_returns_401(self):
        """키 누락 시 401 반환"""
        with patch.dict(os.environ, {"DALLO_API_KEYS": "valid-key"}):
            from api.auth import verify_api_key
            from fastapi import HTTPException
            with pytest.raises(HTTPException) as exc_info:
                _run(verify_api_key(api_key=None))
            assert exc_info.value.status_code == 401

    def test_constant_time_compare(self):
        """상수 시간 비교 함수 동작 확인"""
        from api.auth import _constant_time_compare
        assert _constant_time_compare("abc", "abc") is True
        assert _constant_time_compare("abc", "def") is False
        assert _constant_time_compare("", "") is True

    def test_multiple_keys_support(self):
        """다중 키 지원 확인"""
        with patch.dict(os.environ, {"DALLO_API_KEYS": "key1, key2, key3"}):
            from api.auth import verify_api_key
            assert _run(verify_api_key(api_key="key2")) == "key2"
            assert _run(verify_api_key(api_key="key3")) == "key3"
