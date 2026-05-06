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
from typing import Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shared.schemas import PatchSuggestion, PatchStatus
from analyzer.command_env import build_child_env
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
            # 프로젝트 복사 (venv, .git 제외)
            for item in os.listdir(self.project_root):
                if item in ("venv", ".git", ".scannerwork", "__pycache__", "node_modules"):
                    continue
                src = os.path.join(self.project_root, item)
                dst = os.path.join(tmp_dir, item)
                if os.path.isdir(src):
                    shutil.copytree(src, dst, ignore=shutil.ignore_patterns(
                        "__pycache__", "*.pyc", ".git"
                    ))
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
