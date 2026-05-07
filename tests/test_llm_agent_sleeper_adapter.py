"""LLMAgent retry sleeper seam test (Wave 4-M)

``DalloAgent`` 의 retry sleep 경계를 생성자 주입형 ``sleeper`` seam 으로
분리한 동작을 회귀 검증한다.

- ``DalloAgent`` 는 생성자에 keyword-only ``sleeper`` 더블을 주입받으면
  실제 ``time.sleep`` 호출 없이 rate-limit 재시도 경로를 통과해야 한다.
- 기본값은 ``time.sleep`` 이며 기존 호출자의 시그니처 호환은 유지된다.
- ``generate_patch`` / ``generate_multi_patches`` 본문에는 ``time.sleep(...)``
  직접 호출이 없어야 하고, 주입된 ``self._sleeper`` 만 사용해야 한다
  (생성자 default 참조 ``time.sleep`` 자체는 attribute 참조이므로 허용).
- 키 로테이션(``rotate_key`` → True)이 성공한 경우 sleeper 는 호출되지
  않는다. 키가 1개뿐이라 ``rotate_key`` 가 False 를 반환할 때만 sleeper 가
  ``_extract_retry_delay`` 의 결과로 호출된다.
- 본 테스트는 외부 LLM/네트워크/실제 sleep 에 의존하지 않는다.
"""

from __future__ import annotations

import ast
import inspect
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent import llm_agent as llm_agent_mod
from agent.llm_agent import DalloAgent
from shared.schemas import PatchStatus, VulnerabilityReport


# ============================================================
# AST helper — 직접 ``time.sleep(...)`` Call 만 검출 (attribute 참조는 무시)
# ============================================================


def _direct_attr_calls(tree: ast.AST, base: str, attr: str) -> list[int]:
    """``base.attr(...)`` 형식의 Call 노드 라인번호 리스트.

    ``self._sleeper = time.sleep`` 같은 attribute 참조(Call 아님)는 잡히지
    않는다. 이는 생성자 default 가 모듈 함수를 가리키는 정상 경로를 검사
    대상에서 제외하기 위한 의도된 동작이다.
    """
    lines: list[int] = []
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == attr
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == base
        ):
            lines.append(node.lineno)
    return lines


def _function_node(tree: ast.AST, name: str) -> ast.FunctionDef:
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    raise AssertionError(f"function {name!r} not found in module AST")


# ============================================================
# 더블 — Provider / Sleeper
# ============================================================


class _FakeProvider:
    """주입 가능한 가짜 LLM 프로바이더.

    ``responses`` 는 호출마다 순차적으로 소비된다. 항목이 ``Exception``
    인스턴스면 그대로 raise, 문자열이면 응답으로 반환한다. 큐가 비면
    파싱 가능한 기본 SUCCESS 응답을 반환한다.
    """

    def __init__(self, responses=None, rotate_returns: bool = False):
        self.model = "fake-model"
        self.temperature = 0.0
        self._responses = list(responses or [])
        self._rotate_returns = rotate_returns
        self.rotate_calls = 0
        self.calls: list[tuple[str, str]] = []

    def call(self, prompt: str, system: str = "") -> str:
        self.calls.append((prompt, system))
        if not self._responses:
            return (
                "### 수정된 코드\n```\nfixed = 1\n```\n"
                "### 수정 근거\nok\n"
            )
        item = self._responses.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item

    def rotate_key(self) -> bool:
        self.rotate_calls += 1
        return self._rotate_returns


class _RecordingSleeper:
    """sleep 인자를 기록만 하는 가짜 sleeper — 실제 sleep 하지 않는다."""

    def __init__(self) -> None:
        self.calls: list[float] = []

    def __call__(self, seconds: float) -> None:
        self.calls.append(seconds)


def _make_vuln() -> VulnerabilityReport:
    return VulnerabilityReport(
        id="vuln-001",
        tool="bandit",
        rule_id="B608",
        severity="HIGH",
        confidence="HIGH",
        title="t",
        description="d",
        file_path="x.py",
        line_number=1,
        code_snippet='q = f"SELECT * FROM u WHERE id={uid}"',
        function_code='def f(uid):\n    q = f"SELECT * FROM u WHERE id={uid}"\n    return q\n',
        cwe_id="CWE-89",
    )


def _make_agent(
    monkeypatch,
    provider: _FakeProvider,
    *,
    sleeper=None,
    max_retries: int = 2,
) -> DalloAgent:
    """``get_provider`` 를 monkeypatch 하여 fake provider 를 주입한 DalloAgent.

    이렇게 하면 실제 ``GeminiProvider`` (그리고 ``google.genai``) 의존성
    없이 ``DalloAgent`` 인스턴스를 만들 수 있다. 그 후 retry 경로의
    ``self._provider`` 호출은 모두 fake provider 로 향한다.
    """

    def _fake_get_provider(**kwargs):
        return provider

    monkeypatch.setattr(llm_agent_mod, "get_provider", _fake_get_provider)
    kwargs = {"api_key": "ignored", "max_retries": max_retries}
    if sleeper is not None:
        kwargs["sleeper"] = sleeper
    return DalloAgent(**kwargs)


# ============================================================
# 모듈 표면 검사 — 직접 time.sleep 호출 금지 (Wave 4-M)
# ============================================================


class TestLLMAgentModuleSurface:
    def test_generate_patch_no_direct_time_sleep(self):
        """``generate_patch`` 본문에 ``time.sleep(...)`` 직접 호출 금지.

        Wave 4-M: retry sleep 은 생성자 주입된 ``self._sleeper`` 를 통해서
        만 일어나야 한다.
        """
        tree = ast.parse(inspect.getsource(llm_agent_mod))
        cls = next(
            n for n in ast.walk(tree)
            if isinstance(n, ast.ClassDef) and n.name == "DalloAgent"
        )
        fn = _function_node(cls, "generate_patch")
        assert _direct_attr_calls(fn, "time", "sleep") == [], (
            "generate_patch 는 time.sleep() 을 직접 호출하면 안 됨"
            " (주입된 self._sleeper 사용)"
        )

    def test_generate_multi_patches_no_direct_time_sleep(self):
        """``generate_multi_patches`` 본문에 ``time.sleep(...)`` 직접 호출 금지."""
        tree = ast.parse(inspect.getsource(llm_agent_mod))
        cls = next(
            n for n in ast.walk(tree)
            if isinstance(n, ast.ClassDef) and n.name == "DalloAgent"
        )
        fn = _function_node(cls, "generate_multi_patches")
        assert _direct_attr_calls(fn, "time", "sleep") == [], (
            "generate_multi_patches 는 time.sleep() 을 직접 호출하면 안 됨"
            " (주입된 self._sleeper 사용)"
        )

    def test_module_still_imports_time_for_default_sleeper(self):
        """기본 sleeper 가 모듈 함수 ``time.sleep`` 을 참조할 수 있어야 한다."""
        assert hasattr(llm_agent_mod, "time")
        assert callable(llm_agent_mod.time.sleep)


# ============================================================
# 백워드 호환성 — 기존 키워드만으로 인스턴스화 + 기본 sleeper
# ============================================================


class TestBackwardCompatibility:
    def test_default_sleeper_is_time_sleep(self, monkeypatch):
        provider = _FakeProvider()
        agent = _make_agent(monkeypatch, provider)
        # 기본은 time.sleep 그 자체.
        import time as _time

        assert agent._sleeper is _time.sleep

    def test_existing_kwargs_still_accepted(self, monkeypatch):
        """기존 호출자 시그니처(positional 키워드 6개)가 깨지지 않아야 한다."""
        provider = _FakeProvider()
        monkeypatch.setattr(
            llm_agent_mod, "get_provider", lambda **kw: provider
        )
        agent = DalloAgent(
            api_key="k",
            api_keys=None,
            model=None,
            provider="gemini",
            max_retries=3,
            temperature=0.5,
        )
        assert agent.max_retries == 3
        assert agent._provider is provider
        # sleeper 기본값이 채워져야 한다.
        assert callable(agent._sleeper)

    def test_sleeper_is_keyword_only(self, monkeypatch):
        """``sleeper`` 는 keyword-only 라서 positional 로 넘기면 TypeError."""
        provider = _FakeProvider()
        monkeypatch.setattr(
            llm_agent_mod, "get_provider", lambda **kw: provider
        )
        recorder = _RecordingSleeper()
        # positional 7번째 인자로는 받지 않는다.
        with pytest.raises(TypeError):
            DalloAgent("k", None, None, "gemini", 2, 0.2, recorder)


# ============================================================
# 시그니처 검사 — Wave 4-M sleeper 매개변수가 노출되어야 한다
# ============================================================


class TestConstructorSignature:
    def test_sleeper_param_is_keyword_only_and_optional(self):
        sig = inspect.signature(DalloAgent.__init__)
        assert "sleeper" in sig.parameters
        param = sig.parameters["sleeper"]
        assert param.kind == inspect.Parameter.KEYWORD_ONLY
        assert param.default is None


# ============================================================
# 주입된 sleeper 동작 — generate_patch 경로
# ============================================================


class TestGeneratePatchSleeperInjection:
    def test_rate_limit_with_no_rotation_uses_injected_sleeper(self, monkeypatch):
        """429 + rotate_key=False → 주입된 sleeper 가 ``_extract_retry_delay`` 값으로 호출."""
        # 첫 호출: 429 + retry-in-hint, 두번째 호출: SUCCESS.
        err = Exception("429: rate limit exceeded — retry in 5 seconds")
        provider = _FakeProvider(responses=[err], rotate_returns=False)
        sleeper = _RecordingSleeper()

        # 실제 time.sleep 이 호출되면 즉시 실패하도록 boom 으로 패치.
        def _boom(*a, **kw):
            raise AssertionError("실제 time.sleep 이 호출되면 안 됩니다")

        monkeypatch.setattr(llm_agent_mod.time, "sleep", _boom)

        agent = _make_agent(monkeypatch, provider, sleeper=sleeper)
        patch = agent.generate_patch(_make_vuln())

        # 두 번째 시도에서 success → GENERATED.
        assert patch.status == PatchStatus.GENERATED
        # rotate_key 는 시도되었지만 False 였다.
        assert provider.rotate_calls == 1
        # ``retry in 5`` + 2 buffer = 7 초로 sleeper 가 정확히 1회 호출.
        assert sleeper.calls == [7]

    def test_rate_limit_default_delay_when_no_hint(self, monkeypatch):
        """retry-in 힌트가 없으면 default 30초로 sleep 한다."""
        err = Exception("429 quota exceeded")
        provider = _FakeProvider(responses=[err], rotate_returns=False)
        sleeper = _RecordingSleeper()
        monkeypatch.setattr(
            llm_agent_mod.time, "sleep",
            lambda *a, **kw: (_ for _ in ()).throw(
                AssertionError("실제 sleep 금지")
            ),
        )

        agent = _make_agent(monkeypatch, provider, sleeper=sleeper)
        patch = agent.generate_patch(_make_vuln())

        assert patch.status == PatchStatus.GENERATED
        assert sleeper.calls == [30]

    def test_rotate_key_success_skips_sleeper(self, monkeypatch):
        """``rotate_key`` 가 True 를 반환하면 sleeper 는 호출되지 않는다."""
        err = Exception("429 quota exceeded")
        provider = _FakeProvider(responses=[err], rotate_returns=True)
        sleeper = _RecordingSleeper()

        agent = _make_agent(monkeypatch, provider, sleeper=sleeper)
        patch = agent.generate_patch(_make_vuln())

        assert patch.status == PatchStatus.GENERATED
        assert provider.rotate_calls == 1
        # 키가 전환되었으므로 대기는 발생하지 않아야 한다.
        assert sleeper.calls == []

    def test_non_rate_limit_error_does_not_sleep(self, monkeypatch):
        """rate-limit 이 아닌 일반 에러는 sleeper 를 트리거하지 않는다."""
        err = Exception("connection reset")
        provider = _FakeProvider(responses=[err], rotate_returns=False)
        sleeper = _RecordingSleeper()

        agent = _make_agent(monkeypatch, provider, sleeper=sleeper)
        patch = agent.generate_patch(_make_vuln())

        assert patch.status == PatchStatus.GENERATED
        assert provider.rotate_calls == 0
        assert sleeper.calls == []

    def test_first_attempt_success_no_sleep(self, monkeypatch):
        provider = _FakeProvider()  # 항상 성공
        sleeper = _RecordingSleeper()

        agent = _make_agent(monkeypatch, provider, sleeper=sleeper)
        patch = agent.generate_patch(_make_vuln())

        assert patch.status == PatchStatus.GENERATED
        assert sleeper.calls == []
        assert len(provider.calls) == 1

    def test_exhausted_retries_returns_failed_without_real_sleep(self, monkeypatch):
        """모든 재시도가 rate-limit 으로 실패해도 실제 sleep 은 일어나지 않는다."""

        def _boom(*a, **kw):
            raise AssertionError("실제 time.sleep 이 호출되면 안 됩니다")

        monkeypatch.setattr(llm_agent_mod.time, "sleep", _boom)

        # max_retries=2 → 총 3회 시도, 모두 429 실패.
        errs = [Exception("429 quota exceeded"),
                Exception("429 quota exceeded"),
                Exception("429 quota exceeded")]
        provider = _FakeProvider(responses=errs, rotate_returns=False)
        sleeper = _RecordingSleeper()

        agent = _make_agent(monkeypatch, provider, sleeper=sleeper, max_retries=2)
        patch = agent.generate_patch(_make_vuln())

        assert patch.status == PatchStatus.FAILED
        # 마지막 시도에서도 sleeper 가 호출된다(현재 동작 보존).
        assert sleeper.calls == [30, 30, 30]


# ============================================================
# 주입된 sleeper 동작 — generate_multi_patches 경로
# ============================================================


class TestGenerateMultiPatchesSleeperInjection:
    def test_rate_limit_uses_injected_sleeper(self, monkeypatch):
        """multi 경로의 429 → 주입된 sleeper 가 호출되어야 한다."""

        def _boom(*a, **kw):
            raise AssertionError("실제 time.sleep 이 호출되면 안 됩니다")

        monkeypatch.setattr(llm_agent_mod.time, "sleep", _boom)

        # 첫 시도: 429, 두 번째 시도: 3개 옵션 응답.
        multi_response = (
            "### 옵션 1: Minimal Fix\n"
            "```\nminimal\n```\n설명: m\n"
            "### 옵션 2: Recommended Fix\n"
            "```\nrecommended\n```\n설명: r\n"
            "### 옵션 3: Structural Fix\n"
            "```\nstructural\n```\n설명: s\n"
        )
        err = Exception("429 quota exceeded — retry in 3 seconds")
        provider = _FakeProvider(
            responses=[err, multi_response],
            rotate_returns=False,
        )
        sleeper = _RecordingSleeper()

        agent = _make_agent(monkeypatch, provider, sleeper=sleeper)
        patches = agent.generate_multi_patches(_make_vuln())

        assert len(patches) == 3
        assert all(p.status == PatchStatus.GENERATED for p in patches)
        # ``retry in 3`` + 2 buffer = 5
        assert sleeper.calls == [5]

    def test_multi_rotate_key_success_skips_sleeper(self, monkeypatch):
        multi_response = (
            "### 옵션 1: Minimal Fix\n"
            "```\nminimal\n```\n설명: m\n"
            "### 옵션 2: Recommended Fix\n"
            "```\nrecommended\n```\n설명: r\n"
            "### 옵션 3: Structural Fix\n"
            "```\nstructural\n```\n설명: s\n"
        )
        err = Exception("429 quota exceeded")
        provider = _FakeProvider(
            responses=[err, multi_response],
            rotate_returns=True,
        )
        sleeper = _RecordingSleeper()

        agent = _make_agent(monkeypatch, provider, sleeper=sleeper)
        patches = agent.generate_multi_patches(_make_vuln())

        assert len(patches) == 3
        assert provider.rotate_calls == 1
        assert sleeper.calls == []


__all__: list[str] = []
