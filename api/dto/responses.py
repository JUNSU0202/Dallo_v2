"""API 응답 DTO (Pydantic 모델).

대시보드 및 API 계약 테스트가 의존하는 공개 응답 셰이프를 동결합니다.

설계 원칙:
- 키 이름은 절대 변경하지 않습니다 (예: high/high_count는 그대로 유지).
- 누락 가능한 필드는 Optional로 두어 빈 상태에서도 직렬화가 가능하도록 합니다.
- extra="allow"로 두어 레거시/추가 필드가 응답에서 사라지지 않게 합니다
  (FastAPI response_model 필터링이 프런트엔드 의존 필드를 떨어뜨리지 않도록).
- 라우터는 response_model_exclude_unset=True로 호출하여, 핸들러가 반환하지 않은
  Optional 필드가 null로 채워져 응답 셰이프에 새 키가 생기는 것을 막습니다
  (HEAD~1과 동일한 키 집합 보장).
"""

from typing import Optional

from pydantic import BaseModel, ConfigDict


class _Permissive(BaseModel):
    """모든 DTO의 베이스. 알려진 필드만 검증하고, 알 수 없는 키는 그대로 통과시킨다."""

    model_config = ConfigDict(extra="allow")


# ============================================================
# /api/stats
# ============================================================

class StatsResponse(_Permissive):
    total_issues: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    patches_generated: int = 0
    patches_verified: int = 0
    duration_seconds: Optional[float] = None
    session_id: Optional[str] = None
    total_sessions: Optional[int] = None
    # Wave 5-D: 추가만 허용되는 Red/Blue 요약 (handler 가 set 하지 않으면 응답에 등장하지 않음).
    red_blue_summary: Optional[dict] = None


# ============================================================
# /api/vulnerabilities
# ============================================================

class VulnerabilityItem(_Permissive):
    id: str
    tool: str
    rule_id: str
    severity: str
    title: str
    file_path: str
    line_number: int
    code_snippet: str
    confidence: Optional[str] = None
    description: Optional[str] = None
    cwe_id: Optional[str] = None
    more_info: Optional[str] = None
    function_code: Optional[str] = None
    # Wave 5-D: Red Team enrichment (additive only — handler 가 set 한 경우만 응답에 노출).
    red_team_phase: Optional[str] = None
    attack_vector: Optional[str] = None
    attack_scenario: Optional[str] = None
    security_impact: Optional[str] = None
    blue_team_strategy: Optional[str] = None
    exploitability: Optional[str] = None
    attack_plan: Optional[dict] = None


class VulnerabilitiesResponse(_Permissive):
    count: int
    vulnerabilities: list[VulnerabilityItem]


# ============================================================
# /api/vulnerabilities/by-file
# ============================================================

class FileVulnerabilityCount(_Permissive):
    file: str
    high: int = 0
    medium: int = 0
    low: int = 0
    total: int = 0


class VulnerabilitiesByFileResponse(_Permissive):
    files: list[FileVulnerabilityCount]


# ============================================================
# /api/vulnerabilities/by-type
# ============================================================

class VulnerabilityTypeCount(_Permissive):
    rule_id: str
    name: str
    count: int
    severity: str


class VulnerabilitiesByTypeResponse(_Permissive):
    types: list[VulnerabilityTypeCount]


# ============================================================
# /api/patches
# ============================================================

class PatchItem(_Permissive):
    vulnerability_id: str
    fixed_code: str
    explanation: str
    fix_type: str
    status: str
    file_path: str
    line_number: int
    rule_id: str
    severity: str
    title: str
    original_code: str
    syntax_valid: Optional[bool] = None
    test_passed: Optional[bool] = None
    created_at: Optional[str] = None
    # Wave 5-D: Blue Team enrichment (additive only — handler 가 set 한 경우만 응답에 노출).
    blue_team_phase: Optional[str] = None
    defense_strategy: Optional[str] = None
    defense_outcome: Optional[str] = None
    residual_risk: Optional[str] = None
    defense_plan: Optional[dict] = None


class PatchesResponse(_Permissive):
    count: int
    patches: list[PatchItem]


# ============================================================
# /api/sessions
# ============================================================

class SessionItem(_Permissive):
    session_id: str
    repo: Optional[str] = None
    pr_number: Optional[int] = None
    commit_sha: Optional[str] = None
    total_issues: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    patches_generated: int = 0
    patches_verified: int = 0
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    duration_seconds: Optional[float] = None


class SessionsResponse(_Permissive):
    count: int
    sessions: list[SessionItem]


# ============================================================
# POST /api/analyze (즉시 응답)
# ============================================================

class AnalyzeStartResponse(_Permissive):
    job_id: str
    status: str
    message: str
    backend: str


# ============================================================
# /api/red-blue/summary
# ============================================================

class RedBlueSummaryResponse(_Permissive):
    """Red/Blue 종합 요약 응답.

    중첩 객체는 ``shared.red_blue.build_red_blue_summary`` 가 만든 dict 를
    그대로 통과시킨다 (permissive). top-level 키 셰이프만 동결한다.
    """

    red_team: Optional[dict] = None
    blue_team: Optional[dict] = None
    comparison: Optional[dict] = None
    attack_paths: Optional[list] = None
