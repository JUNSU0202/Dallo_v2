"""
테스트 인프라 자체 점검 (Wave 1-A)

pytest.ini 의 pythonpath 설정과 conftest.py 의 안전 기본값이 실제로
동작하는지 최소한으로 검증한다. 어떤 도메인 로직도 테스트하지 않으며,
오직 테스트 인프라(설정 파일 + conftest)에 대한 회귀 방지를 목적으로 한다.
"""

from __future__ import annotations

import os
import sys


def test_pythonpath_allows_top_level_import_without_sys_path_hack():
    """sys.path.insert 없이도 프로젝트 루트 패키지 임포트가 가능해야 한다."""
    # 모듈이 정상 임포트되면 pythonpath 설정이 적용된 것.
    import shared.encryption  # noqa: F401  (임포트 성공이 곧 검증)
    import api.auth  # noqa: F401


def test_safe_env_defaults_are_present():
    """conftest 가 필수 환경변수에 안전 기본값을 주입했는지 확인."""
    assert os.environ.get("DALLO_ENCRYPTION_KEY"), (
        "conftest 가 DALLO_ENCRYPTION_KEY 기본값을 주입해야 한다"
    )
    assert os.environ.get("DALLO_API_KEYS"), (
        "conftest 가 DALLO_API_KEYS 기본값을 주입해야 한다"
    )


def test_encryption_key_fixture(encryption_key):
    assert encryption_key == os.environ["DALLO_ENCRYPTION_KEY"]


def test_api_key_fixture(api_key):
    assert api_key
    assert api_key in os.environ["DALLO_API_KEYS"]


def test_pytest_ini_registered_markers_do_not_warn(pytestconfig):
    """pytest.ini 에 등록된 커스텀 마커가 인식되어야 한다."""
    markers = {
        line.split(":", 1)[0]
        for line in pytestconfig.getini("markers")
    }
    assert "integration" in markers
    assert "slow" in markers


def test_project_root_on_sys_path():
    """pythonpath=. 가 적용되어 프로젝트 루트가 sys.path 에 들어있어야 한다."""
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    # 정규화된 경로 비교 (심볼릭 링크/상대 경로 변형 대비)
    normalized = {os.path.realpath(p) for p in sys.path if p}
    assert os.path.realpath(project_root) in normalized
