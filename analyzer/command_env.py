"""자식 프로세스 환경변수 sanitizer (Wave 4-E).

DevSecOps 분석기에서 외부 정적 분석 도구(``sonar-scanner`` 등)를 호출할 때,
부모 프로세스의 환경변수가 무차별적으로 child 로 상속되면 ``ANTHROPIC_API_KEY``
``GITHUB_TOKEN`` ``AWS_SECRET_ACCESS_KEY`` 같은 시크릿이 외부 도구의 로그/덤프/
원격 텔레메트리 경로로 흘러들 위험이 있다 (특히 AI/vibe-coding 컨텍스트에서
부모 셸에 다양한 토큰이 export 되어 있을 가능성이 높다).

본 모듈은 ``build_child_env`` 헬퍼 하나만 제공한다:

- 보수적인 **allowlist** 로 시작 (PATH/HOME/LANG/LC_*/JAVA_HOME 등 도구 동작에
  필수인 것들만 통과).
- allowlist 통과 후에도 이름 패턴 기반 **deny filter** 로 시크릿스러운 키
  (TOKEN/KEY/SECRET/PASSWORD/CREDENTIAL/API_KEY 포함, 명시적인 well-known 시크릿
  변수명) 를 한 번 더 제거.
- 호출자가 명시적으로 자식에 주입해야 하는 값 (예: ``SONAR_TOKEN``) 은 ``extras``
  로 받아 마지막에 적용 → deny filter 를 우회한다 (의도된 capability grant).
- 단, ``extras`` 의 값이 빈 문자열이면 키를 추가하지 않는다 (호출자가 빈 값을
  넘기는 실수를 무해화).
- 값 자체는 절대 로깅/출력하지 않는다.

stdlib 만 사용하며, 호출자 별로 allowlist/deny pattern 을 확장할 수 있다.
"""

from __future__ import annotations

import os
from typing import Iterable, Mapping, Optional


# ---------------------------------------------------------------------------
# 기본 allowlist — 외부 정적 분석 도구 (sonar-scanner / java / python venv) 가
# 정상 동작하기 위해 필요한 최소 변수들. 토큰성 키는 절대 포함하지 않는다.
# ---------------------------------------------------------------------------

_DEFAULT_ALLOWLIST_EXACT: frozenset[str] = frozenset(
    {
        # 기본 셸/파일시스템
        "PATH",
        "HOME",
        "USER",
        "LOGNAME",
        "SHELL",
        "TERM",
        "TMPDIR",
        "TEMP",
        "TMP",
        # 로케일 / 시간대
        "LANG",
        "LANGUAGE",
        "LC_ALL",
        "TZ",
        # Python 런타임 / venv
        "VIRTUAL_ENV",
        "PYENV_ROOT",
        "PYENV_VERSION",
        "PYTHONPATH",
        "PYTHONUTF8",
        "PYTHONDONTWRITEBYTECODE",
        "PYTHONIOENCODING",
        # JVM (sonar-scanner 는 JVM 기반)
        "JAVA_HOME",
        "JAVA_OPTS",
        # SonarScanner 설정 (토큰 아님)
        "SONAR_SCANNER_OPTS",
        "SONAR_USER_HOME",
        # 프록시 (대/소문자 두 형태 모두)
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "NO_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "no_proxy",
        "all_proxy",
        # CI 컨텍스트 — GITHUB_TOKEN 은 의도적으로 포함하지 않는다.
        "CI",
        "GITHUB_ACTIONS",
    }
)

# 접두사 매칭으로 통과시키는 변수군. ``LC_ALL`` 외의 ``LC_COLLATE`` 등 로케일
# 보조 변수까지 일관되게 보존하기 위해 ``LC_`` 만 허용한다.
_DEFAULT_ALLOWLIST_PREFIXES: tuple[str, ...] = ("LC_",)


# ---------------------------------------------------------------------------
# 기본 deny pattern — allowlist 를 통과했더라도 이름이 시크릿스러우면 제거.
# substring 기반 단순 매칭으로 두어, 새 변수명이 나타나도 자동 차단된다.
# ---------------------------------------------------------------------------

_DEFAULT_DENY_SUBSTRINGS: tuple[str, ...] = (
    "TOKEN",
    "SECRET",
    "PASSWORD",
    "PASS",
    "CREDENTIAL",
    "API_KEY",
    "APIKEY",
    # 단독 "KEY" 는 광범위하지만 allowlist 가 1차 게이트라 false positive 위험이
    # 낮다 (allowlist 에 ``_KEY`` 를 포함하는 변수명은 없다).
    "KEY",
    # Wave 4-H: npm ``_authToken`` / ``_auth`` / 사설 레지스트리 ``*_AUTH`` 등
    # ``TOKEN``/``PASSWORD`` 토큰을 포함하지 않는 auth-like 이름을 한 번 더
    # 거른다. 기본 allowlist 에는 ``AUTH`` 부분문자열을 포함한 키가 없어
    # false positive 위험이 낮다.
    "AUTH",
)

# 명시적으로 알려진 시크릿 변수명. substring 매칭에 걸리지 않을 수 있는
# 케이스를 보강한다 (예: ``DATABASE_URL``, ``SLACK_WEBHOOK_URL``, ``SENTRY_DSN``).
_DEFAULT_DENY_EXACT: frozenset[str] = frozenset(
    {
        "ANTHROPIC_API_KEY",
        "OPENAI_API_KEY",
        "GROQ_API_KEY",
        "HF_TOKEN",
        "GITHUB_TOKEN",
        "GH_TOKEN",
        "GITLAB_TOKEN",
        "NPM_TOKEN",
        "PYPI_TOKEN",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AZURE_CLIENT_SECRET",
        "GOOGLE_APPLICATION_CREDENTIALS",
        "DOCKER_AUTH_CONFIG",
        "DOCKER_PASSWORD",
        "SLACK_WEBHOOK_URL",
        "DATABASE_URL",
        "DB_PASSWORD",
        "SENTRY_DSN",
        "SONAR_TOKEN",
    }
)


def _is_allowed(name: str, allow_exact: frozenset[str], allow_prefixes: tuple[str, ...]) -> bool:
    if name in allow_exact:
        return True
    for prefix in allow_prefixes:
        if name.startswith(prefix):
            return True
    return False


def _is_denied(
    name: str,
    deny_exact: frozenset[str],
    deny_substrings: tuple[str, ...],
) -> bool:
    if name in deny_exact:
        return True
    upper = name.upper()
    for token in deny_substrings:
        if token in upper:
            return True
    return False


def build_child_env(
    extras: Optional[Mapping[str, str]] = None,
    *,
    base_env: Optional[Mapping[str, str]] = None,
    allowlist: Optional[Iterable[str]] = None,
    deny_name_patterns: Optional[Iterable[str]] = None,
) -> dict[str, str]:
    """자식 프로세스에 넘길 sanitized env dict 를 만든다.

    Args:
        extras: 명시적으로 자식에 주입할 키/값 (예: ``{"SONAR_TOKEN": tok}``).
            마지막 단계에 적용되므로 deny filter 를 우회한다 (의도된 capability
            grant). 값이 빈 문자열인 키는 무시된다.
        base_env: 기준이 될 부모 환경. 미지정 시 ``os.environ``.
        allowlist: 호출자별 추가 allowlist (exact name). 기본 allowlist 와
            합집합으로 동작한다.
        deny_name_patterns: 호출자별 추가 deny substring. 기본 deny substring 과
            합집합으로 동작한다.

    Returns:
        sanitized env dict. 시크릿성 키는 ``extras`` 로 명시한 것 외에는 포함되지
        않는다. 값은 절대 로깅하지 않으며, 본 함수도 어떠한 입출력도 하지 않는다.
    """

    parent = os.environ if base_env is None else base_env

    allow_exact = _DEFAULT_ALLOWLIST_EXACT
    if allowlist is not None:
        allow_exact = frozenset(allow_exact | frozenset(allowlist))

    deny_substrings = _DEFAULT_DENY_SUBSTRINGS
    if deny_name_patterns is not None:
        deny_substrings = tuple(set(deny_substrings) | set(deny_name_patterns))

    sanitized: dict[str, str] = {}
    for key, value in parent.items():
        if not _is_allowed(key, allow_exact, _DEFAULT_ALLOWLIST_PREFIXES):
            continue
        if _is_denied(key, _DEFAULT_DENY_EXACT, deny_substrings):
            continue
        sanitized[key] = value

    if extras:
        for key, value in extras.items():
            if value == "":
                # 빈 값 capability grant 는 무해화 — 호출자가 token="" 일 때
                # 의도치 않게 빈 SONAR_TOKEN 을 child 에 주입하지 않게 한다.
                continue
            sanitized[key] = value

    return sanitized


__all__ = ["build_child_env"]
