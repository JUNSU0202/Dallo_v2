"""보안 재검증기 어댑터 시(seam) 단위 테스트.

Wave 4-L: ``validator/security_checker.py`` 의 Bandit/Semgrep 외부 도구
호출을 fakeable runner 어댑터로 격리한다.

- ``SecurityChecker(bandit_runner=..., semgrep_runner=...)`` 키워드 인자로
  더블을 주입하면 실제 ``BanditRunner`` / ``SemgrepRunner`` 인스턴스가
  생성되지 않아야 한다 (즉 실제 ``bandit`` / ``semgrep`` subprocess 호출
  경로가 막힌다).
- 인자 미전달 시 기본 동작은 보존되며, runner 객체는 *호출 시* 만들어지고
  import 시점에 부수효과를 일으키지 않는다.
- 상태 매핑(passed → VERIFIED, 새 취약점 → FAILED), ``removed_count`` /
  ``introduced_count`` 산정, 빈/누락 ``fixed_code`` 동작, 기존 fail-open
  스캔 실패 동작(``tool_used="error"`` + ``passed=True``) 을 그대로 유지한다.
- ``security_checker.py`` 본문에 ``shell=True`` / ``os.system`` /
  ``os.popen`` / ``eval`` / ``exec`` / ``pickle.loads`` 가 추가되지
  않았는지 AST 정적 가드로 회귀 방지한다.
"""

from __future__ import annotations

import ast
import inspect
import sys
from types import SimpleNamespace
from typing import Optional

import pytest

from validator.security_checker import SecurityChecker, SecurityCheckResult
from shared.schemas import PatchStatus, PatchSuggestion


# ============================================================
# AST/static guard — security_checker 본문 위험 패턴 도입 금지
# ============================================================


def _walk_calls(tree: ast.AST):
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            yield node


class TestSecurityCheckerSourceStaticGuards:
    """``validator/security_checker.py`` 본문 정적 가드."""

    def _module_source(self) -> tuple[str, ast.AST]:
        from validator import security_checker as mod

        src = inspect.getsource(mod)
        return src, ast.parse(src)

    def test_no_shell_true(self):
        _src, tree = self._module_source()
        for call in _walk_calls(tree):
            for kw in call.keywords:
                if (
                    kw.arg == "shell"
                    and isinstance(kw.value, ast.Constant)
                    and kw.value.value is True
                ):
                    pytest.fail("shell=True 사용 금지")

    def test_no_os_system_or_popen(self):
        src, _tree = self._module_source()
        assert "os.system(" not in src
        assert "os.popen(" not in src

    def test_no_eval_or_exec_calls(self):
        _src, tree = self._module_source()
        for call in _walk_calls(tree):
            if isinstance(call.func, ast.Name):
                assert call.func.id not in {"eval", "exec"}, (
                    "eval/exec 호출 금지"
                )

    def test_no_unsafe_pickle(self):
        src, _tree = self._module_source()
        assert "pickle.loads" not in src
        assert "pickle.load(" not in src

    def test_no_subprocess_run_directly(self):
        """보안 체커 본문에는 ``subprocess.run`` 직접 호출이 등장해선 안 된다.

        실제 외부 도구 호출은 주입된 ``BanditRunner`` / ``SemgrepRunner``
        어댑터(혹은 그 내부의 ``StaticToolCommandRunner``) 로 위임되어야 한다.
        """
        _src, tree = self._module_source()
        for call in _walk_calls(tree):
            func = call.func
            if (
                isinstance(func, ast.Attribute)
                and func.attr == "run"
                and isinstance(func.value, ast.Name)
                and func.value.id == "subprocess"
            ):
                pytest.fail("security_checker 본문에 subprocess.run 직접 호출 금지")


# ============================================================
# Fakes — BanditRunner / SemgrepRunner 더블
# ============================================================


def _vuln(
    rule_id: str,
    title: str,
    severity: str = "MEDIUM",
    description: str = "",
    line: int = 1,
    cwe: Optional[str] = None,
) -> SimpleNamespace:
    """``analyzer.bandit_runner.Vulnerability`` 와 동일 속성 표면을 가진 더블.

    ``security_checker`` 가 실제로 읽는 속성은 다음과 같다:
    ``rule_id`` / ``severity`` / ``title`` / ``description`` /
    ``line_number`` / ``cwe_id``.
    """
    return SimpleNamespace(
        rule_id=rule_id,
        title=title,
        severity=severity,
        description=description,
        line_number=line,
        cwe_id=cwe,
    )


class _FakeAnalysisRunner:
    """Fake BanditRunner / SemgrepRunner.

    ``run(file_path)`` 호출 시 ``SimpleNamespace(vulnerabilities=[...])``
    를 반환한다. 파일 경로의 ``fixed_`` / ``original_`` 접두사로 어떤
    리스트를 돌려줄지 선택한다 (``security_checker._run_security_scan``
    이 ``fixed_{filename}`` / ``original_{filename}`` 로 임시 파일을 쓰는
    동작에 맞춤).
    """

    def __init__(
        self,
        fixed_vulns: Optional[list] = None,
        original_vulns: Optional[list] = None,
        raise_exc: Optional[BaseException] = None,
    ):
        self.calls: list[str] = []
        self.fixed_vulns = list(fixed_vulns or [])
        self.original_vulns = list(original_vulns or [])
        self.raise_exc = raise_exc

    def run(self, file_path: str):
        self.calls.append(file_path)
        if self.raise_exc is not None:
            raise self.raise_exc
        base = file_path.rsplit("/", 1)[-1]
        if base.startswith("fixed_"):
            return SimpleNamespace(vulnerabilities=list(self.fixed_vulns))
        if base.startswith("original_"):
            return SimpleNamespace(vulnerabilities=list(self.original_vulns))
        return SimpleNamespace(vulnerabilities=[])


def _make_patch(
    fixed_code: str = "x = 1\n",
    status: str = PatchStatus.GENERATED,
    vuln_id: str = "v1",
) -> PatchSuggestion:
    return PatchSuggestion(
        vulnerability_id=vuln_id,
        fixed_code=fixed_code,
        explanation="원본 설명",
        status=status,
    )


def _block_real_runners(monkeypatch) -> None:
    """실제 ``BanditRunner`` / ``SemgrepRunner`` 인스턴스화 금지 트립와이어."""
    import analyzer.bandit_runner as br_mod
    import analyzer.semgrep_runner as sr_mod

    def _boom_bandit(*a, **kw):
        raise AssertionError(
            "실제 BanditRunner 가 생성되면 안 됩니다 (fake 미주입 의심)"
        )

    def _boom_semgrep(*a, **kw):
        raise AssertionError(
            "실제 SemgrepRunner 가 생성되면 안 됩니다 (fake 미주입 의심)"
        )

    monkeypatch.setattr(br_mod, "BanditRunner", _boom_bandit)
    monkeypatch.setattr(sr_mod, "SemgrepRunner", _boom_semgrep)


# ============================================================
# Constructor / DI seam
# ============================================================


class TestSecurityCheckerConstructorSeam:
    def test_default_constructor_works(self):
        """기존 ``SecurityChecker()`` 호출 형태가 깨지지 않는다."""
        checker = SecurityChecker()
        assert isinstance(checker, SecurityChecker)

    def test_default_constructor_does_not_eagerly_build_runners(
        self, monkeypatch
    ):
        """기본 생성자는 import/생성 시점에 실제 runner 를 만들지 않는다.

        ``SecurityChecker()`` 자체는 외부 도구를 침범하지 않아야 하며,
        실제 ``BanditRunner()`` / ``SemgrepRunner(config="auto")`` 호출은
        ``check()`` 시점까지 지연되어야 한다.
        """
        _block_real_runners(monkeypatch)
        # 인스턴스화 자체가 BanditRunner/SemgrepRunner 를 호출하지 않아야 함.
        SecurityChecker()

    def test_init_accepts_keyword_only_runner_kwargs(self):
        """``bandit_runner`` / ``semgrep_runner`` 는 키워드 인자로 받는다."""
        bandit = _FakeAnalysisRunner()
        semgrep = _FakeAnalysisRunner()
        checker = SecurityChecker(
            bandit_runner=bandit, semgrep_runner=semgrep
        )
        assert isinstance(checker, SecurityChecker)


# ============================================================
# 주입된 fake runner 사용 — 실 subprocess / 실 BanditRunner 미사용
# ============================================================


class TestInjectedRunnersUsed:
    def test_fakes_are_used_and_real_runners_not_constructed(
        self, monkeypatch
    ):
        _block_real_runners(monkeypatch)

        bandit = _FakeAnalysisRunner()
        semgrep = _FakeAnalysisRunner()
        checker = SecurityChecker(
            bandit_runner=bandit, semgrep_runner=semgrep
        )

        out = checker.check(
            _make_patch(),
            language="python",
            filename="app.py",
            original_code="",
        )

        # 안전 코드 + 빈 original_code → fixed 만 스캔
        # bandit (확장자 .py 일 때만) + semgrep 모두 호출됨
        assert len(bandit.calls) == 1
        assert len(semgrep.calls) == 1
        # 모든 호출은 fixed_ 경로여야 함 (original_code 가 비어있으므로)
        for call in bandit.calls + semgrep.calls:
            assert "fixed_" in call.rsplit("/", 1)[-1]
        # 새 취약점 없으면 VERIFIED
        assert out.status == PatchStatus.VERIFIED
        assert out.security_revalidation is not None
        assert out.security_revalidation["tool_used"] == "bandit+semgrep"

    def test_fakes_are_used_with_original_code_path(self, monkeypatch):
        _block_real_runners(monkeypatch)

        bandit = _FakeAnalysisRunner()
        semgrep = _FakeAnalysisRunner()
        checker = SecurityChecker(
            bandit_runner=bandit, semgrep_runner=semgrep
        )

        checker.check(
            _make_patch(),
            language="python",
            filename="app.py",
            original_code="orig = 1\n",
        )

        # original_code 가 있을 때 fixed + original 두 번씩 호출
        assert len(bandit.calls) == 2
        assert len(semgrep.calls) == 2
        bases = {p.rsplit("/", 1)[-1] for p in bandit.calls}
        assert any(b.startswith("fixed_") for b in bases)
        assert any(b.startswith("original_") for b in bases)


# ============================================================
# 상태 매핑 / 가드 분기 / 카운팅 로직 보존
# ============================================================


class TestStatusMappingPreserved:
    def test_safe_fixed_code_status_verified(self, monkeypatch):
        _block_real_runners(monkeypatch)

        checker = SecurityChecker(
            bandit_runner=_FakeAnalysisRunner(),
            semgrep_runner=_FakeAnalysisRunner(),
        )

        out = checker.check(
            _make_patch(),
            language="python",
            filename="app.py",
            original_code="",
        )

        assert out.status == PatchStatus.VERIFIED
        rev = out.security_revalidation
        assert rev["passed"] is True
        assert rev["introduced_count"] == 0
        assert rev["new_vulnerabilities"] == []
        assert rev["fixed_vuln_count"] == 0
        assert rev["original_vuln_count"] == 0
        assert "보안 재검증 통과" in out.explanation

    def test_new_vulnerability_marks_failed(self, monkeypatch):
        _block_real_runners(monkeypatch)

        bandit = _FakeAnalysisRunner(
            fixed_vulns=[
                _vuln("B102", "exec_used", severity="HIGH")
            ],
            original_vulns=[],
        )
        semgrep = _FakeAnalysisRunner()
        checker = SecurityChecker(
            bandit_runner=bandit, semgrep_runner=semgrep
        )

        out = checker.check(
            _make_patch(),
            language="python",
            filename="app.py",
            original_code="orig = 1\n",
        )

        assert out.status == PatchStatus.FAILED
        rev = out.security_revalidation
        assert rev["passed"] is False
        assert rev["introduced_count"] == 1
        assert rev["new_vulnerabilities"][0]["rule_id"] == "B102"
        assert "보안 재검증 실패" in out.explanation


class TestEmptyOrFailedFixedCodeShortCircuit:
    def test_empty_fixed_code_returns_patch_unchanged(self, monkeypatch):
        _block_real_runners(monkeypatch)

        bandit = _FakeAnalysisRunner()
        semgrep = _FakeAnalysisRunner()
        checker = SecurityChecker(
            bandit_runner=bandit, semgrep_runner=semgrep
        )

        patch = _make_patch(fixed_code="")
        out = checker.check(patch, language="python", filename="app.py")

        # check() 가 그대로 반환하므로 어떤 runner 도 호출되지 않아야 함
        assert out is patch
        assert bandit.calls == []
        assert semgrep.calls == []
        assert out.security_revalidation is None
        # status 도 변경되지 않음
        assert out.status == PatchStatus.GENERATED

    def test_whitespace_only_fixed_code_returns_patch_unchanged(
        self, monkeypatch
    ):
        _block_real_runners(monkeypatch)

        bandit = _FakeAnalysisRunner()
        semgrep = _FakeAnalysisRunner()
        checker = SecurityChecker(
            bandit_runner=bandit, semgrep_runner=semgrep
        )

        patch = _make_patch(fixed_code="   \n\t  ")
        out = checker.check(patch, language="python", filename="app.py")

        assert out is patch
        assert bandit.calls == []
        assert semgrep.calls == []

    def test_failed_status_short_circuits_scan(self, monkeypatch):
        _block_real_runners(monkeypatch)

        bandit = _FakeAnalysisRunner()
        semgrep = _FakeAnalysisRunner()
        checker = SecurityChecker(
            bandit_runner=bandit, semgrep_runner=semgrep
        )

        patch = _make_patch(status=PatchStatus.FAILED)
        out = checker.check(patch, language="python", filename="app.py")

        assert out is patch
        assert out.status == PatchStatus.FAILED
        assert bandit.calls == []
        assert semgrep.calls == []


class TestRemovedAndIntroducedCounts:
    def test_removed_count_when_fix_resolves_vulns(self, monkeypatch):
        _block_real_runners(monkeypatch)

        bandit = _FakeAnalysisRunner(
            fixed_vulns=[],
            original_vulns=[
                _vuln("B608", "sql injection"),
                _vuln("B102", "exec_used"),
            ],
        )
        semgrep = _FakeAnalysisRunner()
        checker = SecurityChecker(
            bandit_runner=bandit, semgrep_runner=semgrep
        )

        out = checker.check(
            _make_patch(),
            language="python",
            filename="app.py",
            original_code="orig = 1\n",
        )

        rev = out.security_revalidation
        assert rev["original_vuln_count"] == 2
        assert rev["fixed_vuln_count"] == 0
        assert rev["removed_count"] == 2
        assert rev["introduced_count"] == 0
        assert out.status == PatchStatus.VERIFIED

    def test_introduced_count_when_fix_adds_new_rule(self, monkeypatch):
        _block_real_runners(monkeypatch)

        # original 에는 B608 만 있었고, fixed 에는 B608 + B102 가 있다.
        bandit = _FakeAnalysisRunner(
            fixed_vulns=[
                _vuln("B608", "sql injection"),
                _vuln("B102", "exec_used"),
            ],
            original_vulns=[
                _vuln("B608", "sql injection"),
            ],
        )
        semgrep = _FakeAnalysisRunner()
        checker = SecurityChecker(
            bandit_runner=bandit, semgrep_runner=semgrep
        )

        out = checker.check(
            _make_patch(),
            language="python",
            filename="app.py",
            original_code="orig = 1\n",
        )

        rev = out.security_revalidation
        assert rev["original_vuln_count"] == 1
        assert rev["fixed_vuln_count"] == 2
        # removed_count = max(0, 1 - 2) = 0
        assert rev["removed_count"] == 0
        assert rev["introduced_count"] == 1
        assert out.status == PatchStatus.FAILED


class TestToolUsedMapping:
    def test_python_uses_bandit_plus_semgrep(self, monkeypatch):
        _block_real_runners(monkeypatch)

        bandit = _FakeAnalysisRunner()
        semgrep = _FakeAnalysisRunner()
        checker = SecurityChecker(
            bandit_runner=bandit, semgrep_runner=semgrep
        )

        out = checker.check(
            _make_patch(),
            language="python",
            filename="app.py",
            original_code="",
        )

        assert out.security_revalidation["tool_used"] == "bandit+semgrep"
        assert len(bandit.calls) == 1
        assert len(semgrep.calls) == 1

    def test_non_python_uses_semgrep_only(self, monkeypatch):
        _block_real_runners(monkeypatch)

        bandit = _FakeAnalysisRunner()
        semgrep = _FakeAnalysisRunner()
        checker = SecurityChecker(
            bandit_runner=bandit, semgrep_runner=semgrep
        )

        out = checker.check(
            _make_patch(fixed_code="System.out.println(1);\n"),
            language="java",
            filename="App.java",
            original_code="",
        )

        assert out.security_revalidation["tool_used"] == "semgrep"
        # Java → Bandit 미호출
        assert bandit.calls == []
        assert len(semgrep.calls) == 1


# ============================================================
# Fail-open 동작 보존
# ============================================================


class TestFailOpenPreserved:
    def test_inner_runner_exception_swallowed_no_new_vulns(
        self, monkeypatch
    ):
        """``BanditRunner.run`` 이 예외를 던져도 ``_run_bandit`` 의 기존
        try/except 가 빈 리스트로 치환한다 (semgrep 결과만으로 판정)."""
        _block_real_runners(monkeypatch)

        bandit = _FakeAnalysisRunner(raise_exc=RuntimeError("bandit boom"))
        semgrep = _FakeAnalysisRunner()
        checker = SecurityChecker(
            bandit_runner=bandit, semgrep_runner=semgrep
        )

        out = checker.check(
            _make_patch(),
            language="python",
            filename="app.py",
            original_code="",
        )

        rev = out.security_revalidation
        assert rev["passed"] is True
        assert rev["new_vulnerabilities"] == []
        # bandit 은 호출은 시도되지만 결과는 무시
        assert len(bandit.calls) == 1
        assert len(semgrep.calls) == 1
        # tool_used 는 정상 매핑 유지 (outer error 분기와 다름)
        assert rev["tool_used"] == "bandit+semgrep"
        assert out.status == PatchStatus.VERIFIED

    def test_outer_scan_failure_returns_tool_used_error(
        self, monkeypatch
    ):
        """``_run_security_scan`` 의 outer try 내부에서 예외가 발생하면
        fail-open (``passed=True``, ``tool_used="error"``) 결과가
        보존되어야 한다."""
        _block_real_runners(monkeypatch)

        bandit = _FakeAnalysisRunner()
        semgrep = _FakeAnalysisRunner()
        checker = SecurityChecker(
            bandit_runner=bandit, semgrep_runner=semgrep
        )

        # 내부 try 안에 들어간 후 ``_scan_file`` 이 예외를 던지면 outer
        # try/except 가 잡아 fail-open 분기로 진입한다.
        def _boom_scan(self, file_path, ext):
            raise OSError("simulated scan failure")

        monkeypatch.setattr(SecurityChecker, "_scan_file", _boom_scan)

        out = checker.check(
            _make_patch(),
            language="python",
            filename="app.py",
            original_code="",
        )

        rev = out.security_revalidation
        assert rev["passed"] is True
        assert rev["tool_used"] == "error"
        assert rev["error"]
        # passed=True 이므로 status 매핑은 VERIFIED 분기로 진입
        assert out.status == PatchStatus.VERIFIED


# ============================================================
# 하위 호환: 기존 호출 패턴 보존
# ============================================================


class TestBackwardCompatibility:
    def test_check_signature_keyword_args_still_work(self, monkeypatch):
        """기존 호출자(``analyzer/pipeline.py``) 의 ``check(p, language=..,
        filename=.., original_code=..)`` 시그니처가 그대로 동작한다."""
        _block_real_runners(monkeypatch)

        bandit = _FakeAnalysisRunner()
        semgrep = _FakeAnalysisRunner()
        checker = SecurityChecker(
            bandit_runner=bandit, semgrep_runner=semgrep
        )

        patch = _make_patch()
        out = checker.check(
            patch,
            language="python",
            filename="app.py",
            original_code="",
        )
        assert isinstance(out, PatchSuggestion)

    def test_check_batch_iterates_with_injected_runners(self, monkeypatch):
        _block_real_runners(monkeypatch)

        bandit = _FakeAnalysisRunner()
        semgrep = _FakeAnalysisRunner()
        checker = SecurityChecker(
            bandit_runner=bandit, semgrep_runner=semgrep
        )

        patches = [_make_patch(vuln_id=f"v{i}") for i in range(3)]
        outs = checker.check_batch(
            patches,
            language="python",
            filename="app.py",
            original_code="",
        )

        assert len(outs) == 3
        # 각 패치마다 fixed 1 회씩
        assert len(bandit.calls) == 3
        assert len(semgrep.calls) == 3


__all__: list[str] = []
