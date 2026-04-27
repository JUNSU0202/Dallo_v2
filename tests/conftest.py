"""
공유 테스트 픽스처 / 환경 기본값 (tests/conftest.py)

목적
----
- 테스트 실행 전에 안전한 기본 환경변수를 주입하여, 개별 테스트 파일이 직접
  os.environ 에 토큰성 값을 하드코딩하지 않아도 되게 한다.
- 운영 환경(또는 CI 에서 명시적으로 설정한 값)을 절대 덮어쓰지 않도록
  ``os.environ.setdefault`` 만 사용한다.
- 기존 테스트의 동작을 깨뜨리지 않는다. 특히 일부 테스트
  (예: tests/test_encryption.py)는 의도적으로 환경변수를 비우고 fail-fast 동작을
  검증하는데, 그 테스트들은 값을 pop 한 뒤 원본을 복원하는 로직을 가지고 있어
  여기서 기본값을 주입해도 문제 없이 통과한다.

sys.path 보일러플레이트 정리에 대한 주의
---------------------------------------
- pytest.ini 의 ``pythonpath = .`` 로 프로젝트 루트가 자동으로 모듈 검색
  경로에 들어가므로 각 테스트 파일 상단의
  ``sys.path.insert(0, os.path.dirname(...))`` 라인은 사실상 중복이다.
- 다만 일부 파일은 직접 ``python tests/test_*.py`` 로 실행되는 것을 가정해
  남겨둔 흔적일 수 있고, 또 일괄 제거는 Wave 1-A 의 "behavior 보존" 원칙을
  넘어서는 광범위한 변경이 된다. 따라서 이번 작업에서는 ``pythonpath`` 만
  도입하고 sys.path.insert 라인은 그대로 둔다. (후속 Wave 에서 정리.)
"""

from __future__ import annotations

import os

import pytest


# 테스트용 기본값. 진짜 시크릿이 아니며, 어떤 운영 자원에도 접근하지 않는다.
# 운영/CI 가 이미 값을 주입한 경우엔 setdefault 가 무시한다.
_TEST_DEFAULT_ENCRYPTION_KEY = "test-key"
_TEST_DEFAULT_API_KEY = "test-api-key"


def _apply_safe_test_env_defaults() -> None:
    """필수 환경변수 미설정 시 안전한 테스트용 기본값을 주입한다."""
    os.environ.setdefault("DALLO_ENCRYPTION_KEY", _TEST_DEFAULT_ENCRYPTION_KEY)
    os.environ.setdefault("DALLO_API_KEYS", _TEST_DEFAULT_API_KEY)


# 컬렉션 단계(픽스처 실행 이전)부터 모듈 임포트 시 환경변수가 필요한 코드가
# 있을 수 있으므로 모듈 로드 시점에 즉시 적용한다.
_apply_safe_test_env_defaults()


@pytest.fixture(scope="session", autouse=True)
def _ensure_safe_test_env() -> None:
    """세션 전체에 걸쳐 안전 기본값이 살아있는지 한 번 더 확인."""
    _apply_safe_test_env_defaults()


@pytest.fixture
def encryption_key() -> str:
    """현재 활성화된 DALLO_ENCRYPTION_KEY 값을 픽스처로 노출."""
    return os.environ["DALLO_ENCRYPTION_KEY"]


@pytest.fixture
def api_key() -> str:
    """현재 활성화된 DALLO_API_KEYS 의 첫 번째 키를 픽스처로 노출."""
    return os.environ["DALLO_API_KEYS"].split(",")[0].strip()
