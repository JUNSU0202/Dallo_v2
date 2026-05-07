"""
테스트 실행 모듈 (validator/test_runner.py)

LLM이 생성한 수정 코드를 임시로 적용하고 테스트를 실행하여
기존 기능이 깨지지 않았는지 검증합니다.

사용법:
    from validator.test_runner import TestRunner

    runner = TestRunner()
    result = runner.run(patch, original_file_path="test_targets/sql_injection.py")
"""

import os
import sys
import shutil
import tempfile
import subprocess
from dataclasses import dataclass
from typing import Callable, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shared.schemas import PatchSuggestion, PatchStatus
from shared.command_env import build_child_env
from validator.validator_command_runner import ValidatorCommandRunner


# Wave 4-I: sandbox pytest 전용 child env allowlist.
# build_child_env 의 기본 allowlist (PATH/HOME/LANG/proxy/VIRTUAL_ENV 등) 외에,
# pytest 가 정상 동작하기 위해 필요한 비-시크릿 운영 변수만 추가한다.
# ``DALLO_ENCRYPTION_KEY`` / ``DALLO_API_KEYS`` 등 애플리케이션 시크릿은
# allowlist 에 포함하지 않으며, deny filter 로 한 번 더 차단된다.
_VALIDATOR_PYTEST_ENV_ALLOWLIST: tuple[str, ...] = (
    "PYTEST_ADDOPTS",
    "PYTEST_DISABLE_PLUGIN_AUTOLOAD",
    "PYTEST_VERSION",
    "PY_COLORS",
    "FORCE_COLOR",
    "NO_COLOR",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "REQUESTS_CA_BUNDLE",
    "CURL_CA_BUNDLE",
    "XDG_CACHE_HOME",
    "XDG_CONFIG_HOME",
    "COVERAGE_FILE",
    "COVERAGE_RCFILE",
    "COVERAGE_PROCESS_START",
)


# Wave 4-K: sandbox 복사 시 무시할 경로 패턴.
# 기존 ``shutil.ignore_patterns(...)`` 동작을 보존하면서 symlink 항목을
# 추가로 차단해, 외부 경로를 가리키는 link 의 내용이 sandbox 안에 일반
# 파일로 복사되지 않도록 한다.
_SANDBOX_IGNORE_PATTERNS: tuple[str, ...] = ("__pycache__", "*.pyc", ".git")


def _make_sandbox_copy_ignore() -> Callable[[str, list[str]], list[str]]:
    """``shutil.copytree(ignore=...)`` 용 콜러블을 만든다.

    기존 패턴 (``__pycache__``, ``*.pyc``, ``.git``) 에 더해, 디렉토리 안의
    심볼릭 링크 항목을 모두 무시 목록에 추가한다. ``shutil.copytree`` 의
    ``symlinks=False`` 는 link 를 *따라가* 대상 내용을 일반 파일로 복사하는
    기본 동작이므로 그 인자 자체로는 link 가 차단되지 않는다. 이 콜러블이
    link 항목을 ignore 목록에 미리 넣어, copytree 가 link 를 따라가기 전에
    sandbox 외부 대상이 일반 파일로 복사되지 않도록 사전 차단한다.
    """

    base_ignore = shutil.ignore_patterns(*_SANDBOX_IGNORE_PATTERNS)

    def _ignore(directory: str, names: list[str]) -> list[str]:
        ignored = set(base_ignore(directory, names))
        for name in names:
            full = os.path.join(directory, name)
            if os.path.islink(full):
                ignored.add(name)
        return list(ignored)

    return _ignore


def _is_safe_sandbox_relative_path(base: str, candidate: str) -> bool:
    """``candidate`` 가 ``base`` 디렉토리 안쪽(자기 자신 제외)을 가리키는지 검사.

    절대 경로, 상위 디렉토리 traversal 등 sandbox 바깥을 가리키는 경로는
    거부한다 (``False`` 반환). ``base`` / ``candidate`` 모두 realpath 로
    정규화해 비교하므로 ``safe/../../outside`` 같은 중첩 traversal 도 차단된다.
    """

    if not candidate or os.path.isabs(candidate):
        return False
    base_real = os.path.realpath(base)
    target_real = os.path.realpath(os.path.join(base, candidate))
    if target_real == base_real:
        return False
    return target_real.startswith(base_real + os.sep)


@dataclass
class TestResult:
    """테스트 실행 결과"""
    passed: bool
    output: str = ""
    error: str = ""
    tests_run: int = 0
    tests_failed: int = 0


class TestRunner:
    """LLM 생성 코드에 대한 테스트 실행기.

    외부 도구(``pytest``) 호출은 ``ValidatorCommandRunner`` 어댑터에
    위임한다. 테스트는 생성자에 더블을 주입해 실제 subprocess 호출을 막을
    수 있다 (Wave 4-A).
    """

    def __init__(
        self,
        project_root: Optional[str] = None,
        runner: Optional[ValidatorCommandRunner] = None,
    ):
        self.project_root = project_root or os.path.dirname(
            os.path.dirname(os.path.abspath(__file__))
        )
        self._runner = runner or ValidatorCommandRunner()

    def run(
        self,
        patch: PatchSuggestion,
        original_file_path: str,
        test_dir: Optional[str] = None,
    ) -> PatchSuggestion:
        """
        수정 코드를 임시 적용하고 테스트를 실행합니다.

        1. 프로젝트를 임시 디렉토리에 복사
        2. 원본 파일을 수정 코드로 교체
        3. pytest 실행
        4. 결과를 PatchSuggestion에 반영

        Args:
            patch: LLM이 생성한 수정안
            original_file_path: 수정 대상 원본 파일 경로
            test_dir: 테스트 디렉토리 (기본: tests/)

        Returns:
            테스트 결과가 반영된 PatchSuggestion
        """
        if not patch.fixed_code or not patch.fixed_code.strip():
            patch.test_passed = False
            patch.status = PatchStatus.FAILED
            return patch

        if not patch.syntax_valid:
            patch.test_passed = False
            return patch

        result = self._run_in_sandbox(patch.fixed_code, original_file_path, test_dir)
        patch.test_passed = result.passed

        if result.passed is True:
            if patch.status != PatchStatus.FAILED:
                patch.status = PatchStatus.VERIFIED
        elif result.passed is None:
            # 테스트 파일 없음 — 문법만 통과한 상태 유지
            pass
        else:
            patch.status = PatchStatus.FAILED
            patch.explanation += f"\n\n⚠️ 테스트 실패:\n{result.error or result.output}"

        return patch

    def _run_in_sandbox(
        self,
        fixed_code: str,
        original_file_path: str,
        test_dir: Optional[str] = None,
    ) -> TestResult:
        """임시 환경에서 수정 코드를 적용하고 테스트를 실행합니다."""
        tmp_dir = tempfile.mkdtemp(prefix="dallo_test_")

        try:
            # Wave 4-K: 복사 시작 전에 ``original_file_path`` 가 sandbox 바깥을
            # 가리키는지 먼저 검증한다. 절대 경로 / 상위 traversal 이 들어오면
            # 외부 파일을 절대 덮어쓰지 않도록 차단한다.
            if not _is_safe_sandbox_relative_path(tmp_dir, original_file_path):
                raise ValueError(
                    "안전하지 않은 original_file_path (sandbox 바깥 경로)"
                )

            # 프로젝트 복사 (venv, .git 제외).
            # Wave 4-K: 외부를 가리키는 symlink 가 일반 파일로 sandbox 에
            # 복사되지 않도록 한다. ``symlinks=False`` 자체는 link 를 *따라가*
            # 대상 내용을 일반 파일로 복사하므로 그것만으로는 차단되지 않는다.
            # Wave 4-K 는 ``_make_sandbox_copy_ignore()`` 로 디렉토리 내부의
            # link 항목을 ignore 목록에 넣고, 최상위 항목은 아래
            # ``os.path.islink(src)`` 검사로 사전 스킵해 copytree/copy2 가
            # link 를 따라가기 전에 차단한다. ``ignore_dangling_symlinks=True``
            # 는 깨진 link 가 남아 있어도 copytree 가 예외로 깨지지 않게 한다.
            ignore = _make_sandbox_copy_ignore()
            for item in os.listdir(self.project_root):
                if item in ("venv", ".git", ".scannerwork", "__pycache__", "node_modules"):
                    continue
                src = os.path.join(self.project_root, item)
                # 최상위 항목이 symlink 면 sandbox 로 복사하지 않는다.
                if os.path.islink(src):
                    continue
                dst = os.path.join(tmp_dir, item)
                if os.path.isdir(src):
                    shutil.copytree(
                        src,
                        dst,
                        symlinks=False,
                        ignore_dangling_symlinks=True,
                        ignore=ignore,
                    )
                else:
                    shutil.copy2(src, dst)

            # 수정 코드 적용
            target_file = os.path.join(tmp_dir, original_file_path)
            if os.path.exists(target_file):
                with open(target_file, "w", encoding="utf-8") as f:
                    f.write(fixed_code)

            # pytest 실행
            test_path = os.path.join(tmp_dir, test_dir or "tests")
            if not os.path.exists(test_path) or not os.listdir(test_path):
                # 테스트 파일이 없으면 테스트 미실행으로 표시 (VERIFIED로 올리지 않음)
                return TestResult(passed=None, output="테스트 파일 없음 - 문법 검사만 완료")

            result = self._runner.run(
                [sys.executable, "-m", "pytest", test_path, "-v", "--tb=short"],
                cwd=tmp_dir,
                timeout=60,
                env=build_child_env(allowlist=_VALIDATOR_PYTEST_ENV_ALLOWLIST),
            )

            return TestResult(
                passed=(result.returncode == 0),
                output=result.stdout,
                error=result.stderr,
            )

        except subprocess.TimeoutExpired:
            return TestResult(passed=False, error="테스트 실행 시간 초과 (60초)")
        except Exception as e:
            return TestResult(passed=False, error=f"테스트 실행 오류: {str(e)}")
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)
