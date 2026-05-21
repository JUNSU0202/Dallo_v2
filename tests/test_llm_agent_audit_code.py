"""DalloAgent.audit_code defensive normalization tests.

검증 대상:
- ``DalloAgent.audit_code()`` 시그니처 / kwargs 호환 (``max_chars`` default 4000).
- ``_build_audit_prompt`` 가 파일명/언어/코드를 프롬프트에 포함시키며, 코드는
  ``max_chars`` 로 안전하게 트리밍된다.
- ``_provider.call(prompt, system=SYSTEM_PROMPT)`` 한 번만 호출.
- 응답 파싱 — fenced JSON / bare JSON / non-JSON 모두 안전하게 처리.
- 정규화 규칙:
    * status invalid → 'suspicious' if findings else 'clean'
    * findings non-list → []
    * non-dict finding → skip
    * 누락된 문자열 필드 → ""
    * line_number → int (invalid → 0)
    * severity → uppercase
    * non-JSON 응답 → status='reviewed', findings=[], summary 는 안전한 fallback
      (응답 raw 텍스트 / 입력 코드의 시크릿을 echo 하지 않는다)

원칙:
- 실제 LLM/네트워크 호출 0. ``get_provider`` monkeypatch + fake provider 사용.
- 본 모듈은 기존 ``DalloAgent`` 의 다른 동작에 영향을 주지 않는다.
"""

from __future__ import annotations

import inspect
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent import llm_agent as llm_agent_mod
from agent.llm_agent import DalloAgent
from agent.providers.base import SYSTEM_PROMPT


# ============================================================
# 더블 — FakeProvider (LLM 호출 없이 audit_code 검증)
# ============================================================


class _FakeProvider:
    """Captures prompts, returns scripted responses (or default JSON)."""

    def __init__(self, responses=None):
        self.model = "fake-model"
        self.temperature = 0.0
        self._responses = list(responses or [])
        self.calls: list[tuple[str, str]] = []

    def call(self, prompt: str, system: str = "") -> str:
        self.calls.append((prompt, system))
        if not self._responses:
            return '{"status":"clean","summary":"","findings":[]}'
        item = self._responses.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item

    def rotate_key(self) -> bool:
        return False


def _make_agent(
    monkeypatch, *, responses=None,
) -> tuple[DalloAgent, _FakeProvider]:
    provider = _FakeProvider(responses=responses)
    monkeypatch.setattr(llm_agent_mod, "get_provider", lambda **kw: provider)
    agent = DalloAgent(api_key="ignored")
    return agent, provider


# ============================================================
# 1) Signature / API surface
# ============================================================


class TestAuditCodeSignature:
    def test_audit_code_method_exists(self):
        assert hasattr(DalloAgent, "audit_code")
        assert callable(DalloAgent.audit_code)

    def test_audit_code_has_max_chars_default_4000(self):
        sig = inspect.signature(DalloAgent.audit_code)
        assert "max_chars" in sig.parameters
        assert sig.parameters["max_chars"].default == 4000

    def test_audit_code_required_params(self):
        sig = inspect.signature(DalloAgent.audit_code)
        # self + code + filename + language + max_chars
        assert "code" in sig.parameters
        assert "filename" in sig.parameters
        assert "language" in sig.parameters


# ============================================================
# 2) Provider integration — single call + system prompt + content
# ============================================================


class TestAuditCodeProviderCall:
    def test_invokes_provider_call_with_system_prompt(self, monkeypatch):
        agent, provider = _make_agent(monkeypatch)
        agent.audit_code("x = 1", "x.py", "python")
        assert len(provider.calls) == 1
        _, system = provider.calls[0]
        assert system == SYSTEM_PROMPT

    def test_prompt_includes_filename_language_and_code(self, monkeypatch):
        agent, provider = _make_agent(monkeypatch)
        agent.audit_code(
            "def foo():\n    return 42", "tools/foo.py", "Python",
        )
        prompt = provider.calls[0][0]
        assert "tools/foo.py" in prompt
        assert "Python" in prompt or "python" in prompt.lower()
        assert "def foo()" in prompt
        assert "return 42" in prompt

    def test_returns_dict(self, monkeypatch):
        agent, _ = _make_agent(monkeypatch)
        result = agent.audit_code("x=1", "x.py", "python")
        assert isinstance(result, dict)


# ============================================================
# 3) Trim to max_chars (safe truncation)
# ============================================================


class TestAuditCodeTrimming:
    def test_trims_long_code_to_max_chars(self, monkeypatch):
        agent, provider = _make_agent(monkeypatch)
        long_code = "a" * 6000
        agent.audit_code(long_code, "big.py", "python", max_chars=100)
        prompt = provider.calls[0][0]
        # 전체 6000자가 그대로 들어가면 안 된다
        assert "a" * 6000 not in prompt
        # 100자까지는 들어가 있어야 한다 (정확한 cut-off 는 구현 자유, 100자는 최소 보장)
        assert "a" * 100 in prompt

    def test_short_code_under_limit_is_not_trimmed(self, monkeypatch):
        agent, provider = _make_agent(monkeypatch)
        short = "a" * 50
        agent.audit_code(short, "small.py", "python", max_chars=100)
        prompt = provider.calls[0][0]
        assert short in prompt

    def test_default_max_chars_does_not_blow_up_on_huge_input(self, monkeypatch):
        agent, _ = _make_agent(monkeypatch)
        huge = "z" * 50_000
        # 단순히 예외 없이 dict 를 반환해야 한다
        result = agent.audit_code(huge, "huge.py", "python")
        assert isinstance(result, dict)


# ============================================================
# 4) Normalization — status
# ============================================================


class TestAuditCodeNormalizeStatus:
    def test_valid_status_clean_preserved(self, monkeypatch):
        agent, _ = _make_agent(
            monkeypatch,
            responses=['{"status":"clean","summary":"ok","findings":[]}'],
        )
        result = agent.audit_code("x=1", "x.py", "python")
        assert result["status"] == "clean"

    def test_valid_status_suspicious_preserved(self, monkeypatch):
        agent, _ = _make_agent(
            monkeypatch,
            responses=[
                '{"status":"suspicious","summary":"","findings":[]}'
            ],
        )
        result = agent.audit_code("x=1", "x.py", "python")
        assert result["status"] == "suspicious"

    def test_valid_status_reviewed_preserved(self, monkeypatch):
        agent, _ = _make_agent(
            monkeypatch,
            responses=['{"status":"reviewed","summary":"","findings":[]}'],
        )
        result = agent.audit_code("x=1", "x.py", "python")
        assert result["status"] == "reviewed"

    def test_invalid_status_with_findings_becomes_suspicious(self, monkeypatch):
        agent, _ = _make_agent(
            monkeypatch,
            responses=[
                '{"status":"NOT_REAL","summary":"","findings":[{"title":"x"}]}'
            ],
        )
        result = agent.audit_code("x=1", "x.py", "python")
        assert result["status"] == "suspicious"
        assert len(result["findings"]) == 1

    def test_invalid_status_without_findings_becomes_clean(self, monkeypatch):
        agent, _ = _make_agent(
            monkeypatch,
            responses=['{"status":"NOT_REAL","summary":"","findings":[]}'],
        )
        result = agent.audit_code("x=1", "x.py", "python")
        assert result["status"] == "clean"

    def test_missing_status_with_findings_becomes_suspicious(self, monkeypatch):
        agent, _ = _make_agent(
            monkeypatch,
            responses=['{"summary":"","findings":[{"title":"x"}]}'],
        )
        result = agent.audit_code("x=1", "x.py", "python")
        assert result["status"] == "suspicious"

    def test_missing_status_without_findings_becomes_clean(self, monkeypatch):
        agent, _ = _make_agent(
            monkeypatch,
            responses=['{"summary":"","findings":[]}'],
        )
        result = agent.audit_code("x=1", "x.py", "python")
        assert result["status"] == "clean"


# ============================================================
# 5) Normalization — findings list shape
# ============================================================


class TestAuditCodeNormalizeFindings:
    def test_findings_not_list_becomes_empty_list(self, monkeypatch):
        agent, _ = _make_agent(
            monkeypatch,
            responses=[
                '{"status":"clean","summary":"","findings":"oops"}'
            ],
        )
        result = agent.audit_code("x=1", "x.py", "python")
        assert result["findings"] == []

    def test_findings_dict_value_becomes_empty_list(self, monkeypatch):
        agent, _ = _make_agent(
            monkeypatch,
            responses=[
                '{"status":"clean","summary":"","findings":{"a":1}}'
            ],
        )
        result = agent.audit_code("x=1", "x.py", "python")
        assert result["findings"] == []

    def test_non_dict_findings_are_skipped(self, monkeypatch):
        agent, _ = _make_agent(
            monkeypatch,
            responses=[
                '{"status":"suspicious","summary":"",'
                '"findings":["str-item",{"title":"keep"},42,null]}'
            ],
        )
        result = agent.audit_code("x=1", "x.py", "python")
        assert len(result["findings"]) == 1
        assert result["findings"][0]["title"] == "keep"

    def test_missing_string_fields_default_to_empty(self, monkeypatch):
        agent, _ = _make_agent(
            monkeypatch,
            responses=[
                '{"status":"suspicious","summary":"",'
                '"findings":[{}]}'
            ],
        )
        result = agent.audit_code("x=1", "x.py", "python")
        f = result["findings"][0]
        for key in (
            "title", "cwe_id", "severity", "evidence", "reason", "recommendation",
        ):
            assert key in f
            assert f[key] == ""

    def test_finding_has_line_number_field(self, monkeypatch):
        agent, _ = _make_agent(
            monkeypatch,
            responses=[
                '{"status":"suspicious","summary":"","findings":[{}]}'
            ],
        )
        result = agent.audit_code("x=1", "x.py", "python")
        f = result["findings"][0]
        assert "line_number" in f
        assert f["line_number"] == 0


# ============================================================
# 6) Normalization — field-level rules
# ============================================================


class TestAuditCodeFieldNormalization:
    def test_severity_uppercased(self, monkeypatch):
        agent, _ = _make_agent(
            monkeypatch,
            responses=[
                '{"status":"suspicious","summary":"",'
                '"findings":[{"severity":"medium"}]}'
            ],
        )
        result = agent.audit_code("x=1", "x.py", "python")
        assert result["findings"][0]["severity"] == "MEDIUM"

    def test_severity_already_upper_preserved(self, monkeypatch):
        agent, _ = _make_agent(
            monkeypatch,
            responses=[
                '{"status":"suspicious","summary":"",'
                '"findings":[{"severity":"HIGH"}]}'
            ],
        )
        result = agent.audit_code("x=1", "x.py", "python")
        assert result["findings"][0]["severity"] == "HIGH"

    def test_severity_non_string_becomes_empty(self, monkeypatch):
        agent, _ = _make_agent(
            monkeypatch,
            responses=[
                '{"status":"suspicious","summary":"",'
                '"findings":[{"severity":42}]}'
            ],
        )
        result = agent.audit_code("x=1", "x.py", "python")
        assert result["findings"][0]["severity"] == ""

    def test_line_number_string_digit_cast_to_int(self, monkeypatch):
        agent, _ = _make_agent(
            monkeypatch,
            responses=[
                '{"status":"suspicious","summary":"",'
                '"findings":[{"line_number":"42"}]}'
            ],
        )
        result = agent.audit_code("x=1", "x.py", "python")
        assert result["findings"][0]["line_number"] == 42

    def test_line_number_int_preserved(self, monkeypatch):
        agent, _ = _make_agent(
            monkeypatch,
            responses=[
                '{"status":"suspicious","summary":"",'
                '"findings":[{"line_number":7}]}'
            ],
        )
        result = agent.audit_code("x=1", "x.py", "python")
        assert result["findings"][0]["line_number"] == 7

    def test_line_number_invalid_string_becomes_zero(self, monkeypatch):
        agent, _ = _make_agent(
            monkeypatch,
            responses=[
                '{"status":"suspicious","summary":"",'
                '"findings":[{"line_number":"abc"}]}'
            ],
        )
        result = agent.audit_code("x=1", "x.py", "python")
        assert result["findings"][0]["line_number"] == 0

    def test_line_number_none_becomes_zero(self, monkeypatch):
        agent, _ = _make_agent(
            monkeypatch,
            responses=[
                '{"status":"suspicious","summary":"",'
                '"findings":[{"line_number":null}]}'
            ],
        )
        result = agent.audit_code("x=1", "x.py", "python")
        assert result["findings"][0]["line_number"] == 0


# ============================================================
# 7) Parsing strategies — fenced JSON / bare JSON / non-JSON
# ============================================================


class TestAuditCodeParsing:
    def test_fenced_json_block_parsed(self, monkeypatch):
        agent, _ = _make_agent(
            monkeypatch,
            responses=[
                "감사 결과:\n```json\n"
                '{"status":"clean","summary":"all good","findings":[]}\n'
                "```\n끝.",
            ],
        )
        result = agent.audit_code("x=1", "x.py", "python")
        assert result["status"] == "clean"
        assert result["summary"] == "all good"

    def test_fenced_block_without_json_tag_parsed(self, monkeypatch):
        agent, _ = _make_agent(
            monkeypatch,
            responses=[
                "```\n"
                '{"status":"suspicious","summary":"s","findings":[]}\n'
                "```",
            ],
        )
        result = agent.audit_code("x=1", "x.py", "python")
        assert result["status"] == "suspicious"

    def test_bare_json_parsed(self, monkeypatch):
        agent, _ = _make_agent(
            monkeypatch,
            responses=[
                '{"status":"clean","summary":"ok","findings":[]}'
            ],
        )
        result = agent.audit_code("x=1", "x.py", "python")
        assert result["status"] == "clean"
        assert result["summary"] == "ok"

    def test_non_json_falls_back_to_reviewed(self, monkeypatch):
        agent, _ = _make_agent(
            monkeypatch,
            responses=["this is not JSON at all, just plain text"],
        )
        result = agent.audit_code("x=1", "x.py", "python")
        assert result["status"] == "reviewed"
        assert result["findings"] == []
        assert isinstance(result["summary"], str)
        # summary 가 비어 있을 수도 있고 안내 메시지일 수도 있지만 dict 이어야 한다

    def test_empty_response_falls_back_to_reviewed(self, monkeypatch):
        agent, _ = _make_agent(monkeypatch, responses=[""])
        result = agent.audit_code("x=1", "x.py", "python")
        assert result["status"] == "reviewed"
        assert result["findings"] == []


# ============================================================
# 8) Safe fallback summary — must not leak secrets
# ============================================================


class TestAuditCodeSafeFallbackSummary:
    def test_fallback_summary_does_not_echo_raw_response(self, monkeypatch):
        """non-JSON 응답이 들어와도 fallback summary 에 raw 응답 텍스트(특히
        시크릿) 가 그대로 들어가서는 안 된다."""
        secret_blob = "sk-PROVIDER_RAW_SECRET-12345"
        agent, _ = _make_agent(
            monkeypatch,
            responses=[f"junk-not-json {secret_blob} blah"],
        )
        result = agent.audit_code("x=1", "x.py", "python")
        assert result["status"] == "reviewed"
        # raw 응답의 시크릿 토큰을 echo 하면 안 된다
        assert secret_blob not in result["summary"]

    def test_fallback_summary_does_not_echo_input_code(self, monkeypatch):
        """non-JSON 응답으로 fallback 했을 때 summary 가 입력 코드의 시크릿을
        echo 해서도 안 된다."""
        secret_in_code = "sk-INPUT_SECRET_TOKEN-9876"
        code_with_secret = f'API_KEY = "{secret_in_code}"\n'
        agent, _ = _make_agent(
            monkeypatch,
            responses=["definitely not json"],
        )
        result = agent.audit_code(code_with_secret, "x.py", "python")
        assert result["status"] == "reviewed"
        assert secret_in_code not in result["summary"]


# ============================================================
# 9) Return shape — top-level keys and types
# ============================================================


class TestAuditCodeReturnShape:
    def test_top_level_keys_present(self, monkeypatch):
        agent, _ = _make_agent(monkeypatch)
        result = agent.audit_code("x=1", "x.py", "python")
        assert {"status", "summary", "findings"} <= set(result.keys())
        assert isinstance(result["status"], str)
        assert isinstance(result["summary"], str)
        assert isinstance(result["findings"], list)

    def test_finding_has_all_seven_keys(self, monkeypatch):
        agent, _ = _make_agent(
            monkeypatch,
            responses=[
                '{"status":"suspicious","summary":"","findings":[{}]}'
            ],
        )
        result = agent.audit_code("x=1", "x.py", "python")
        expected = {
            "title", "cwe_id", "severity", "line_number",
            "evidence", "reason", "recommendation",
        }
        assert expected <= set(result["findings"][0].keys())


__all__: list[str] = []
