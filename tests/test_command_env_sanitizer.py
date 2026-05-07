"""``shared.command_env.build_child_env`` 단위 테스트 (Wave 4-E 도입,
Wave 4-J 에서 ``shared/`` 로 중립화).

목적
----
부모 프로세스의 환경변수가 외부 정적 분석 도구(``sonar-scanner`` 등)에 무차별
적으로 상속되면 ``ANTHROPIC_API_KEY`` / ``GITHUB_TOKEN`` /
``AWS_SECRET_ACCESS_KEY`` 같은 시크릿이 흘러 들어갈 위험이 있다. 본 테스트는
sanitizer 가:

- scanner/JVM 동작에 필요한 보수적 allowlist (PATH/HOME/LANG/LC_*/JAVA_HOME 등)
  만 통과시키고,
- allowlist 통과 후에도 시크릿스러운 이름을 deny filter 로 한 번 더 거르며,
- 호출자가 의도적으로 넘긴 ``extras`` (예: ``SONAR_TOKEN``) 만 capability grant
  로 마지막에 주입하고 (빈 값은 무시),
- 절대로 값을 로깅하지 않는 (read-only 변환) 동작을

회귀 검증한다. 토큰성 placeholder 는 secret-scan 노이즈를 피하기 위해 ``"x"``
``"y"`` 같이 짧고 무해한 더미 값만 사용한다.
"""

from __future__ import annotations

from shared.command_env import build_child_env


# ============================================================
# 기본 allowlist — 도구 동작에 필요한 변수들은 통과
# ============================================================


class TestAllowlistPreservation:
    def test_path_home_lang_preserved(self):
        base = {
            "PATH": "/usr/bin:/bin",
            "HOME": "/tmp/home",
            "USER": "u",
            "LOGNAME": "u",
            "SHELL": "/bin/bash",
            "TERM": "xterm",
            "LANG": "en_US.UTF-8",
        }
        env = build_child_env(base_env=base)

        assert env["PATH"] == "/usr/bin:/bin"
        assert env["HOME"] == "/tmp/home"
        assert env["USER"] == "u"
        assert env["LOGNAME"] == "u"
        assert env["SHELL"] == "/bin/bash"
        assert env["TERM"] == "xterm"
        assert env["LANG"] == "en_US.UTF-8"

    def test_lc_prefix_preserved(self):
        """``LC_ALL`` 외의 ``LC_COLLATE`` 등 로케일 보조 변수도 prefix 매칭으로 통과."""
        base = {
            "LC_ALL": "C",
            "LC_COLLATE": "C",
            "LC_CTYPE": "en_US.UTF-8",
            "LC_TIME": "en_US.UTF-8",
        }
        env = build_child_env(base_env=base)

        assert env["LC_ALL"] == "C"
        assert env["LC_COLLATE"] == "C"
        assert env["LC_CTYPE"] == "en_US.UTF-8"
        assert env["LC_TIME"] == "en_US.UTF-8"

    def test_python_runtime_preserved(self):
        base = {
            "VIRTUAL_ENV": "/tmp/venv",
            "PYTHONPATH": "/tmp/src",
            "PYTHONUTF8": "1",
            "PYENV_ROOT": "/tmp/pyenv",
        }
        env = build_child_env(base_env=base)

        assert env["VIRTUAL_ENV"] == "/tmp/venv"
        assert env["PYTHONPATH"] == "/tmp/src"
        assert env["PYTHONUTF8"] == "1"
        assert env["PYENV_ROOT"] == "/tmp/pyenv"

    def test_jvm_and_sonar_scanner_opts_preserved(self):
        base = {
            "JAVA_HOME": "/usr/lib/jvm/default",
            "JAVA_OPTS": "-Xmx512m",
            "SONAR_SCANNER_OPTS": "-Xmx512m",
            "SONAR_USER_HOME": "/tmp/sonar",
        }
        env = build_child_env(base_env=base)

        assert env["JAVA_HOME"] == "/usr/lib/jvm/default"
        assert env["JAVA_OPTS"] == "-Xmx512m"
        assert env["SONAR_SCANNER_OPTS"] == "-Xmx512m"
        assert env["SONAR_USER_HOME"] == "/tmp/sonar"

    def test_proxy_variables_both_cases_preserved(self):
        base = {
            "HTTP_PROXY": "http://proxy:3128",
            "HTTPS_PROXY": "http://proxy:3128",
            "NO_PROXY": "localhost,127.0.0.1",
            "ALL_PROXY": "socks5://proxy:1080",
            "http_proxy": "http://proxy:3128",
            "https_proxy": "http://proxy:3128",
            "no_proxy": "localhost,127.0.0.1",
            "all_proxy": "socks5://proxy:1080",
        }
        env = build_child_env(base_env=base)
        for key in base:
            assert env[key] == base[key], f"{key} 가 sanitized env 에 보존되지 않음"

    def test_github_actions_preserved_but_github_token_stripped(self):
        base = {
            "GITHUB_ACTIONS": "true",
            "GITHUB_TOKEN": "x",
            "CI": "true",
        }
        env = build_child_env(base_env=base)

        assert env["GITHUB_ACTIONS"] == "true"
        assert env["CI"] == "true"
        assert "GITHUB_TOKEN" not in env, (
            "GITHUB_TOKEN 은 ambient 상속 금지 — extras 로 명시 grant 해야 함"
        )

    def test_unknown_variable_dropped(self):
        """allowlist 에 없는 변수는 시크릿이 아니어도 통과시키지 않는다 (보수적 기본값)."""
        base = {"PATH": "/usr/bin", "RANDOM_USER_VAR": "anything"}
        env = build_child_env(base_env=base)

        assert env["PATH"] == "/usr/bin"
        assert "RANDOM_USER_VAR" not in env


# ============================================================
# Deny filter — 시크릿 이름은 allowlist 통과 여부와 무관하게 제거
# ============================================================


class TestDenyFilterStripsSecrets:
    def test_well_known_secret_names_stripped(self):
        base = {
            "PATH": "/usr/bin",
            "ANTHROPIC_API_KEY": "x",
            "OPENAI_API_KEY": "x",
            "GITHUB_TOKEN": "x",
            "GH_TOKEN": "x",
            "AWS_SECRET_ACCESS_KEY": "x",
            "AWS_ACCESS_KEY_ID": "x",
            "AWS_SESSION_TOKEN": "x",
            "NPM_TOKEN": "x",
            "PYPI_TOKEN": "x",
            "DATABASE_URL": "x",
            "DB_PASSWORD": "x",
            "SLACK_WEBHOOK_URL": "x",
            "SENTRY_DSN": "x",
            "GOOGLE_APPLICATION_CREDENTIALS": "/tmp/creds.json",
            "DOCKER_PASSWORD": "x",
            "AZURE_CLIENT_SECRET": "x",
        }
        env = build_child_env(base_env=base)

        assert env == {"PATH": "/usr/bin"}, (
            f"시크릿성 키가 sanitized env 에 남아있음: {sorted(set(env) - {'PATH'})}"
        )

    def test_substring_pattern_strips_unknown_secret_like_names(self):
        """allowlist 에 없는 시크릿 substring 변수는 사전 등록 없이도 차단된다."""
        base = {
            "PATH": "/usr/bin",
            "MY_CUSTOM_TOKEN": "x",
            "TEAM_API_KEY": "x",
            "VENDOR_PASSWORD": "x",
            "BUILD_SECRET": "x",
            "USER_CREDENTIAL": "x",
        }
        env = build_child_env(base_env=base)

        assert env == {"PATH": "/usr/bin"}

    def test_auth_substring_strips_npm_authtoken_and_private_auth_vars(self):
        """Wave 4-H: ``AUTH`` substring 으로 npm ``_authToken`` / 사설 ``*_AUTH``
        같이 ``TOKEN``/``PASSWORD`` 토큰을 포함하지 않는 auth-like 이름도 차단."""
        base = {
            "PATH": "/usr/bin",
            "NPM_AUTHTOKEN": "x",
            "VENDOR_AUTH": "x",
            "PRIVATE_REGISTRY_AUTH": "x",
        }
        # 호출자 allowlist 로 명시 통과를 시도해도 deny filter 로 막혀야 한다.
        env = build_child_env(
            base_env=base,
            allowlist=["NPM_AUTHTOKEN", "VENDOR_AUTH", "PRIVATE_REGISTRY_AUTH"],
        )
        assert env == {"PATH": "/usr/bin"}

    def test_sonar_token_in_base_env_is_stripped(self):
        """``SONAR_TOKEN`` 은 base env 에 있어도 통과시키지 않는다 (extras 전용)."""
        base = {"PATH": "/usr/bin", "SONAR_TOKEN": "x-parent"}
        env = build_child_env(base_env=base)

        assert "SONAR_TOKEN" not in env

    def test_caller_can_extend_deny_pattern(self):
        base = {"PATH": "/usr/bin", "JAVA_HOME": "/usr/lib/jvm/default"}
        env = build_child_env(
            base_env=base,
            deny_name_patterns=["JAVA_HOME"],
        )
        assert env == {"PATH": "/usr/bin"}


# ============================================================
# Extras — capability grant 가 deny filter 를 우회하지만 빈 값은 무시
# ============================================================


class TestExtrasCapabilityGrant:
    def test_extras_sonar_token_included(self):
        base = {"PATH": "/usr/bin"}
        env = build_child_env(extras={"SONAR_TOKEN": "x"}, base_env=base)

        assert env["SONAR_TOKEN"] == "x"
        assert env["PATH"] == "/usr/bin"

    def test_extras_empty_string_not_included(self):
        """``extras={"SONAR_TOKEN": ""}`` 면 키를 추가하지 않는다."""
        base = {"PATH": "/usr/bin"}
        env = build_child_env(extras={"SONAR_TOKEN": ""}, base_env=base)

        assert "SONAR_TOKEN" not in env
        assert env["PATH"] == "/usr/bin"

    def test_extras_overrides_base_env_value(self):
        """extras 는 마지막에 적용되어 base 의 동명 변수를 덮어쓴다."""
        base = {"PATH": "/usr/bin", "JAVA_HOME": "/old"}
        env = build_child_env(
            extras={"JAVA_HOME": "/new"}, base_env=base,
        )
        assert env["JAVA_HOME"] == "/new"

    def test_extras_without_base_secret_still_includes_token(self):
        """parent env 에 SONAR_TOKEN 이 없어도, extras 에 있으면 포함된다."""
        env = build_child_env(extras={"SONAR_TOKEN": "x"}, base_env={"PATH": "/usr/bin"})
        assert env["SONAR_TOKEN"] == "x"

    def test_parent_sonar_token_blocked_but_extras_token_passes(self):
        """parent env 의 SONAR_TOKEN 은 차단되고, extras 의 SONAR_TOKEN 만 통과."""
        base = {"PATH": "/usr/bin", "SONAR_TOKEN": "x-parent"}
        env = build_child_env(extras={"SONAR_TOKEN": "y-explicit"}, base_env=base)
        assert env["SONAR_TOKEN"] == "y-explicit"


# ============================================================
# 추가 allowlist 확장 / base_env 기본값 / read-only 보장
# ============================================================


class TestAllowlistExtensionAndDefaults:
    def test_caller_can_extend_allowlist(self):
        base = {"PATH": "/usr/bin", "MY_TOOL_VAR": "value"}
        env = build_child_env(
            base_env=base,
            allowlist=["MY_TOOL_VAR"],
        )
        assert env["MY_TOOL_VAR"] == "value"
        assert env["PATH"] == "/usr/bin"

    def test_extended_allowlist_does_not_bypass_deny_filter(self):
        """allowlist 를 확장해도 deny filter 는 여전히 적용되어야 한다."""
        base = {"MY_SECRET_TOKEN": "x"}
        env = build_child_env(
            base_env=base,
            allowlist=["MY_SECRET_TOKEN"],
        )
        assert "MY_SECRET_TOKEN" not in env, (
            "allowlist 확장으로도 시크릿 substring 차단을 우회해서는 안 됨"
        )

    def test_default_base_env_uses_os_environ(self, monkeypatch):
        monkeypatch.setenv("PATH", "/tmp/fake-bin")
        monkeypatch.setenv("ANTHROPIC_API_KEY", "x")
        env = build_child_env()
        assert env.get("PATH") == "/tmp/fake-bin"
        assert "ANTHROPIC_API_KEY" not in env

    def test_returns_new_dict_does_not_mutate_base(self):
        base = {"PATH": "/usr/bin", "ANTHROPIC_API_KEY": "x"}
        env = build_child_env(extras={"SONAR_TOKEN": "y"}, base_env=base)
        # base 는 그대로
        assert "ANTHROPIC_API_KEY" in base
        assert "SONAR_TOKEN" not in base
        # 결과는 별개 dict
        assert env is not base


__all__: list[str] = []
