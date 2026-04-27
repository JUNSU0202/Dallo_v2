"""API DTO 패키지.

API 응답 셰이프를 Pydantic 모델로 동결하여 클린 아키텍처의 첫 경계를 만듭니다.
기존 응답 키와 100% 호환되며, 새로운 필드는 extra="allow"로 통과시킵니다.
"""

from api.dto.responses import (
    StatsResponse,
    VulnerabilityItem,
    VulnerabilitiesResponse,
    FileVulnerabilityCount,
    VulnerabilitiesByFileResponse,
    VulnerabilityTypeCount,
    VulnerabilitiesByTypeResponse,
    PatchItem,
    PatchesResponse,
    SessionItem,
    SessionsResponse,
    AnalyzeStartResponse,
)

__all__ = [
    "StatsResponse",
    "VulnerabilityItem",
    "VulnerabilitiesResponse",
    "FileVulnerabilityCount",
    "VulnerabilitiesByFileResponse",
    "VulnerabilityTypeCount",
    "VulnerabilitiesByTypeResponse",
    "PatchItem",
    "PatchesResponse",
    "SessionItem",
    "SessionsResponse",
    "AnalyzeStartResponse",
]
