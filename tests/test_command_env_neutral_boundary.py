"""Wave 4-J neutral ``command_env`` boundary regression tests.

목적
----
Wave 4-E 가 도입한 ``build_child_env`` sanitizer 는 자식 프로세스 env 를 정화하는
공유 boundary helper 임에도, 구현이 ``analyzer/command_env.py`` 에 위치해 있어
validator 계층(``validator/syntax_checker.py``, ``validator/test_runner.py``) 이
analyzer 모듈을 import 해야 하는 의존 방향 위반이 있었다 (Wave 4-I 시점).

Wave 4-J 는 다음을 보장한다:

- 구현이 ``shared/command_env.py`` 로 이동되어 분석기/검증기/통합 어떤 계층
  에서도 평등하게 import 할 수 있다.
- ``analyzer.command_env`` 는 ``shared.command_env.build_child_env`` 를 그대로
  re-export 하는 호환성 shim 으로만 남는다 (외부 caller 호환성).
- validator 계층은 analyzer 를 더 이상 import 하지 않는다 (의존 역전 해소).
- ``shared.command_env`` 는 analyzer / validator 어느 쪽도 import 하지 않는다
  (양쪽 모두에서 안전하게 의존할 수 있는 중립 boundary).
- 동작/정책/시그니처는 Wave 4-I 와 동일하다 (sanitize 결과 dict 가 동일).

본 테스트는 어떠한 실제 외부 도구도 호출하지 않으며, secret 값은 짧은 더미
``"x"`` 만 사용한다.
"""

from __future__ import annotations

import pathlib


def test_shared_command_env_build_child_env_importable():
    """``shared.command_env.build_child_env`` 가 직접 import 가능해야 한다."""
    from shared.command_env import build_child_env  # noqa: F401

    assert callable(build_child_env)


def test_analyzer_command_env_shim_reexports_shared_function():
    """``analyzer.command_env.build_child_env`` 는 shared 의 함수 객체와
    동일해야 한다 (compat shim identity)."""
    from analyzer.command_env import build_child_env as analyzer_fn
    from shared.command_env import build_child_env as shared_fn

    assert analyzer_fn is shared_fn, (
        "analyzer.command_env shim 은 shared.command_env.build_child_env 를 "
        "그대로 re-export 해야 한다 (caller 호환성)."
    )


def _read(path: pathlib.Path) -> str:
    return path.read_text(encoding="utf-8")


_REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent


def test_validator_syntax_checker_does_not_import_analyzer_command_env():
    src = _read(_REPO_ROOT / "validator" / "syntax_checker.py")
    assert "from analyzer.command_env" not in src
    assert "import analyzer.command_env" not in src
    assert "from shared.command_env import build_child_env" in src


def test_validator_test_runner_does_not_import_analyzer_command_env():
    src = _read(_REPO_ROOT / "validator" / "test_runner.py")
    assert "from analyzer.command_env" not in src
    assert "import analyzer.command_env" not in src
    assert "from shared.command_env import build_child_env" in src


def test_shared_command_env_does_not_import_analyzer_or_validator():
    """shared 모듈은 application layer 를 import 해서는 안 된다 (의존 방향 안쪽)."""
    src = _read(_REPO_ROOT / "shared" / "command_env.py")
    assert "import analyzer" not in src
    assert "from analyzer" not in src
    assert "import validator" not in src
    assert "from validator" not in src


def test_behavior_preserved_secret_deny_via_shared_path():
    from shared.command_env import build_child_env

    base = {
        "PATH": "/usr/bin",
        "ANTHROPIC_API_KEY": "x",
        "GITHUB_TOKEN": "x",
        "AWS_SECRET_ACCESS_KEY": "x",
        "DATABASE_URL": "x",
    }
    env = build_child_env(base_env=base)
    assert env == {"PATH": "/usr/bin"}


def test_behavior_preserved_extras_capability_grant_via_shared_path():
    from shared.command_env import build_child_env

    base = {"PATH": "/usr/bin", "SONAR_TOKEN": "x-parent"}
    env = build_child_env(extras={"SONAR_TOKEN": "y"}, base_env=base)
    assert env["SONAR_TOKEN"] == "y"
    assert env["PATH"] == "/usr/bin"


__all__: list[str] = []
