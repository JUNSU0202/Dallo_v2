"""
run_analysis.py 라이트웨이트 스모크/회귀 테스트
(tests/test_run_analysis_smoke.py)

scripts/run_analysis.py를 --skip-llm 모드로 실행해 LLM/네트워크 호출 없이
파이프라인 전체(Bandit → 문맥 추출 → JSON 출력)가 깨지지 않는지 검증한다.

이 테스트는 실제로 bandit 바이너리를 호출하므로 다음 조건이 필요하다:
  - Python 가상환경에 bandit이 설치되어 있어야 함
  - bandit 실행 파일이 PATH에 있어야 함

위 조건이 충족되지 않으면 (예: 외부 CI 환경에서 bandit 미설치),
정확한 에러 메시지와 함께 테스트는 스킵된다 — 아래 fixture 참고.

이 테스트는 빠르게 실행되도록(<1초) tmp_path 안의 매우 작은 타겟에서만 동작한다.
"""

import json
import os
import shutil
import subprocess
import sys

import pytest


REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RUN_ANALYSIS = os.path.join(REPO_ROOT, "scripts", "run_analysis.py")


def _bandit_executable():
    """현재 venv 또는 PATH에서 bandit 실행 파일을 찾는다."""
    # venv의 bin 디렉터리 우선
    venv_bin = os.path.dirname(sys.executable)
    candidate = os.path.join(venv_bin, "bandit")
    if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
        return candidate, venv_bin
    found = shutil.which("bandit")
    if found:
        return found, os.path.dirname(found)
    return None, None


@pytest.fixture(scope="module")
def bandit_path_env():
    """bandit이 사용 가능하면 PATH가 보강된 env를 반환, 아니면 스킵."""
    exe, bin_dir = _bandit_executable()
    if not exe:
        pytest.skip("bandit 실행 파일을 찾을 수 없어 run_analysis 스모크를 스킵합니다.")
    env = os.environ.copy()
    env["PATH"] = bin_dir + os.pathsep + env.get("PATH", "")
    # API 키는 사용하지 않지만, 다른 import 경로 보호용
    env.setdefault("DALLO_ENCRYPTION_KEY", "test-key")
    env.setdefault("DALLO_API_KEYS", "test-api-key")
    return env


def _make_vulnerable_target(tmp_path):
    """SQL injection 패턴 1줄을 가진 매우 작은 Python 파일 생성."""
    target = tmp_path / "vuln.py"
    target.write_text(
        "import sqlite3\n"
        "def lookup(username):\n"
        "    conn = sqlite3.connect('u.db')\n"
        "    cur = conn.cursor()\n"
        "    query = f\"SELECT * FROM users WHERE name='{username}'\"\n"
        "    cur.execute(query)\n"
        "    return cur.fetchall()\n",
        encoding="utf-8",
    )
    return target


def test_run_analysis_skip_llm_smoke(tmp_path, bandit_path_env):
    """
    Bandit이 SQL injection을 탐지하고, --json-output 결과의 스키마가
    스키마(`vulnerabilities`, `summary` 등)에 맞는지 검증한다.

    네트워크/LLM은 --skip-llm으로 차단된다. 외부 IO 없음.
    """
    target = _make_vulnerable_target(tmp_path)
    json_out = tmp_path / "result.json"
    bandit_out = tmp_path / "bandit.json"

    proc = subprocess.run(
        [
            sys.executable,
            RUN_ANALYSIS,
            "--target", str(target),
            "--skip-llm",
            "--output", str(bandit_out),
            "--json-output", str(json_out),
        ],
        cwd=REPO_ROOT,
        env=bandit_path_env,
        capture_output=True,
        text=True,
        timeout=60,
    )

    assert proc.returncode == 0, (
        f"run_analysis.py가 비정상 종료. stdout={proc.stdout!r}\nstderr={proc.stderr!r}"
    )

    # 표준 출력에 단계 헤더가 모두 등장해야 함
    assert "Step 1: Bandit 정적 분석 실행" in proc.stdout
    assert "Step 5: LLM 수정안 생성 (건너뜀)" in proc.stdout
    assert "분석 완료" in proc.stdout

    # JSON 결과 파일이 생성되어야 함
    assert json_out.exists(), "--json-output 파일이 생성되지 않음"
    data = json.loads(json_out.read_text(encoding="utf-8"))

    # 필수 키 존재
    assert "vulnerabilities" in data
    assert "summary" in data or "stats" in data  # AnalysisSession.to_dict() 변형 허용

    vulns = data["vulnerabilities"]
    assert len(vulns) >= 1, "SQL injection 패턴 한 줄짜리 파일에서 취약점이 잡히지 않음"

    # 적어도 하나의 vuln이 B608(SQL injection) 또는 file_path를 포함해야 함
    rule_ids = {v.get("rule_id", "") for v in vulns}
    assert any(r.startswith("B") for r in rule_ids), f"Bandit rule_id가 없음: {rule_ids}"

    # 각 vuln 객체에 필수 필드가 있어야 함 (PR/CI 게이트가 의존)
    for v in vulns:
        assert "severity" in v
        assert "file_path" in v
        assert "line_number" in v
