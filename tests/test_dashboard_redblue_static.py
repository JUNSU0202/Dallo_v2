"""Wave 5-I-1 — 프론트엔드 RedBlueView 정적 회귀.

프론트엔드 테스트 인프라(vite/jest 등)가 본 환경에 부재하므로 Python 정적
파일 검사로 다음을 동결한다:

- ``dashboard/src/components/RedBlueView.jsx`` 가 존재한다.
- ``dashboard/src/App.jsx`` 가 ``RedBlueView`` 를 import 하고 렌더한다.
- ``App.jsx`` 의 탭 목록에 ``cmd: 'redblue'`` 와 한국어 라벨 ``공방`` 이 들어
  있다.
- ``RedBlueView.jsx`` 가 ``apiFetch(...)`` 를 통해 ``/red-blue/summary`` 를
  호출한다.
- ``RedBlueView.jsx`` 가 방어적 가드(``Array.isArray`` / null·object 가드) 를
  포함한다.
- 신규 컴포넌트에 ``dangerouslySetInnerHTML`` / ``eval(`` / ``new Function`` /
  ``Function(`` / ``innerHTML`` 등의 위험 패턴이 등장하지 않는다.
- 보호 파일 (``dashboard/package.json`` / ``dashboard/package-lock.json`` /
  ``dashboard/src/api/client.js`` / ``shared/schemas.py``) 가 ``main`` 대비
  무변경이다.
- 변경된 프론트엔드(``dashboard/``) 파일에 거부된 provider/디폴트 정책 토큰
  (Wave 5-A §6 의 Reject 결정에 해당) 이 신규 라인으로 등장하지 않는다. 본
  guard 는 *프론트엔드 런타임 파일* 에만 적용되며, guard 자체를 설명하는 본
  테스트/문서 파일은 의도적으로 스코프에서 제외된다 (자기-매치 방지).
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest


_REPO_ROOT = Path(__file__).resolve().parents[1]
_DASHBOARD_SRC = _REPO_ROOT / "dashboard" / "src"
_REDBLUE_VIEW = _DASHBOARD_SRC / "components" / "RedBlueView.jsx"
_APP_JSX = _DASHBOARD_SRC / "App.jsx"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


# --------------------------------------------------------------------------- #
# 1) RedBlueView.jsx 존재
# --------------------------------------------------------------------------- #


def test_redblue_view_file_exists() -> None:
    assert _REDBLUE_VIEW.is_file(), (
        f"RedBlueView.jsx 가 존재해야 한다: {_REDBLUE_VIEW}"
    )


# --------------------------------------------------------------------------- #
# 2) App.jsx 가 RedBlueView 를 import & 렌더
# --------------------------------------------------------------------------- #


def test_app_imports_redblue_view() -> None:
    source = _read(_APP_JSX)
    assert "from './components/RedBlueView'" in source, (
        "App.jsx 가 RedBlueView 를 import 해야 한다"
    )


def test_app_renders_redblue_view() -> None:
    source = _read(_APP_JSX)
    assert "<RedBlueView" in source, (
        "App.jsx 가 <RedBlueView /> 를 렌더해야 한다"
    )
    assert "tab === 'redblue'" in source, (
        "App.jsx 의 'redblue' 탭 분기가 있어야 한다"
    )


# --------------------------------------------------------------------------- #
# 3) 탭 메타데이터 (cmd + ko 라벨)
# --------------------------------------------------------------------------- #


def test_app_has_redblue_tab_with_korean_label() -> None:
    source = _read(_APP_JSX)
    assert "cmd: 'redblue'" in source, (
        "App.jsx 의 탭 목록에 cmd: 'redblue' 가 있어야 한다"
    )
    assert "공방" in source, (
        "App.jsx 의 탭 목록에 한국어 라벨 '공방' 이 있어야 한다"
    )
    assert "id: 'redblue'" in source, (
        "App.jsx 의 탭 객체에 id: 'redblue' 가 있어야 한다"
    )


# --------------------------------------------------------------------------- #
# 4) /api/red-blue/summary 호출 + apiFetch 사용
# --------------------------------------------------------------------------- #


def test_redblue_view_uses_apiFetch_for_summary_endpoint() -> None:
    source = _read(_REDBLUE_VIEW)
    assert "apiFetch" in source, "RedBlueView 가 apiFetch 를 사용해야 한다"
    assert "from '../api/client'" in source, (
        "RedBlueView 가 ../api/client 에서 apiFetch 를 import 해야 한다"
    )
    assert "/red-blue/summary" in source, (
        "RedBlueView 가 /red-blue/summary 엔드포인트를 호출해야 한다"
    )


# --------------------------------------------------------------------------- #
# 5) 방어적 렌더링 가드
# --------------------------------------------------------------------------- #


def test_redblue_view_has_defensive_guards() -> None:
    source = _read(_REDBLUE_VIEW)
    assert "Array.isArray" in source, (
        "RedBlueView 의 attack_paths 렌더링은 Array.isArray 가드를 거쳐야 한다"
    )
    assert "red_team" in source and "blue_team" in source, (
        "RedBlueView 가 red_team / blue_team 키를 렌더해야 한다"
    )
    assert "comparison" in source, (
        "RedBlueView 가 comparison 키를 렌더해야 한다"
    )
    assert "attack_paths" in source, (
        "RedBlueView 가 attack_paths 키를 렌더해야 한다"
    )
    # null/undefined 토큰 등 객체 가드의 존재 (구현 자유도는 보존: '|| {}'
    # 폴백 또는 명시적 typeof === 'object' 검사 둘 중 하나).
    has_object_guard = (
        "|| {}" in source
        or "typeof" in source
        or "?? {}" in source
    )
    assert has_object_guard, (
        "RedBlueView 가 객체 폴백 가드 (`|| {}` / `typeof` / `?? {}`) 중 "
        "하나를 사용해야 한다"
    )


def test_redblue_view_has_loading_error_data_states() -> None:
    source = _read(_REDBLUE_VIEW)
    for token in ("useState", "loading", "error"):
        assert token in source, (
            f"RedBlueView 는 로컬 상태 토큰 '{token}' 을 포함해야 한다"
        )


# --------------------------------------------------------------------------- #
# 6) 위험 토큰 부재
# --------------------------------------------------------------------------- #


_FORBIDDEN_TOKENS = (
    "dangerouslySetInnerHTML",
    "eval(",
    "new Function",
    "Function(",
    "innerHTML",
)


@pytest.mark.parametrize("token", _FORBIDDEN_TOKENS)
def test_redblue_view_forbids_unsafe_tokens(token: str) -> None:
    source = _read(_REDBLUE_VIEW)
    assert token not in source, (
        f"RedBlueView 에 금지 토큰 '{token}' 이 등장하면 안 된다"
    )


# --------------------------------------------------------------------------- #
# 7) 보호 파일이 main 대비 무변경
# --------------------------------------------------------------------------- #


_PROTECTED_PATHS = (
    "dashboard/package.json",
    "dashboard/package-lock.json",
    "dashboard/src/api/client.js",
    "shared/schemas.py",
)


@pytest.mark.parametrize("rel_path", _PROTECTED_PATHS)
def test_protected_file_unchanged_vs_main(rel_path: str) -> None:
    result = subprocess.run(
        ["git", "diff", "main", "--", rel_path],
        cwd=str(_REPO_ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, (
        f"git diff failed for {rel_path}: {result.stderr}"
    )
    assert result.stdout == "", (
        f"보호 파일이 main 대비 변경되어 있다: {rel_path}\n{result.stdout[:400]}"
    )


# --------------------------------------------------------------------------- #
# 8) 정책 토큰 부재 (변경된 프론트엔드 런타임 파일)
# --------------------------------------------------------------------------- #
#
# 본 guard 는 **프론트엔드 런타임 디렉터리 (`dashboard/`)** 만 스캔한다.
# 의도적으로 `tests/` 와 `docs/` 는 스코프에서 제외한다 — 그쪽은 guard 를
# *설명* 하는 메타 텍스트이며 (실 위협 모델인 런타임 코드가 아님), 본
# 테스트의 docstring 이나 정책 토큰 목록 자체가 자기-매치되어 verification
# 을 무력화하는 회귀를 막기 위함이다.
#
# 또한 토큰 리터럴 자체를 본 파일에 직접 쓰지 않고 fragment 결합으로 만든다.
# 이로써 본 파일이 향후 다시 스코프에 포함되더라도 self-match 가 발생하지
# 않는다 (`"gate" + "way"` 와 같은 fragment 는 raw substring 으로 등장하지
# 않으므로 git diff 의 added line 매치 대상이 아님).
#
# 동일 가드를 docs 에 두고 싶다면 별도 docs-전용 정적 회귀를 추가하라
# (본 회귀의 self-match 문제를 재도입하지 말 것).


_POLICY_TOKENS = (
    "gate" + "way",
    "LLM_PRIMARY_PROVIDER=" + "gate" + "way",
    "claude-" + "sonnet",
)


@pytest.mark.parametrize("token", _POLICY_TOKENS)
def test_changed_files_have_no_policy_tokens(token: str) -> None:
    result = subprocess.run(
        ["git", "diff", "main", "--", "dashboard"],
        cwd=str(_REPO_ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, (
        f"git diff failed: {result.stderr}"
    )
    # diff 본문에 정책 토큰이 추가된 라인으로 나타나지 않아야 한다.
    added_lines = [
        line for line in result.stdout.splitlines()
        if line.startswith("+") and not line.startswith("+++")
    ]
    offenders = [line for line in added_lines if token in line]
    assert not offenders, (
        f"변경된 dashboard 런타임 파일에 금지 정책 토큰 '{token}' 이 "
        f"등장한다:\n{offenders[:5]}"
    )
