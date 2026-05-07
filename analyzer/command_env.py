"""``analyzer.command_env`` 호환성 shim (Wave 4-J).

Wave 4-E 가 도입한 자식 프로세스 env sanitizer ``build_child_env`` 의 구현은
Wave 4-J 부터 ``shared/command_env.py`` 로 이동되었다 (analyzer/validator 양쪽에서
평등하게 의존할 수 있는 중립 boundary 확립).

본 모듈은 기존 ``from analyzer.command_env import build_child_env`` 를 사용하던
외부 caller 와의 호환성을 위해 동일 이름의 함수 객체를 그대로 re-export 한다.
새 코드는 가능하면 ``shared.command_env`` 에서 직접 import 한다.
"""

from __future__ import annotations

from shared.command_env import build_child_env

__all__ = ["build_child_env"]
