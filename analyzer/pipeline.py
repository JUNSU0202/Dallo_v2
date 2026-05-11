"""
분석 파이프라인 (analyzer/pipeline.py)

정적 분석 → 문맥 추출 → 중복 제거 → 위험도 산정 → LLM → 검증 → 보안 재검증
전체 흐름을 단일 모듈로 통합합니다.

api/server.py와 api/tasks.py 양쪽에서 이 모듈을 호출하여 중복을 제거합니다.
"""

import os
import tempfile
import shutil
import time
import logging
from datetime import datetime
from typing import Optional, Callable

logger = logging.getLogger(__name__)

# 입력 크기 제한
MAX_CODE_SIZE = 1_000_000  # 1MB


class PipelineResult:
    """파이프라인 실행 결과"""

    def __init__(self):
        self.result_data: dict = {}
        self.language: str = "unknown"
        self.llm_error: Optional[str] = None
        self.db_error: Optional[str] = None


def execute_pipeline(
    job_id: str,
    code: str,
    filename: str,
    use_llm: bool = True,
    provider: str = "gemini",
    model: str = "gemini-2.0-flash-lite",
    multi_patch: bool = False,
    on_progress: Optional[Callable[[str], None]] = None,
) -> PipelineResult:
    """
    분석 파이프라인을 실행합니다.

    Args:
        job_id: 작업 고유 ID
        code: 분석 대상 코드 문자열
        filename: 파일명 (언어 감지에 사용)
        use_llm: LLM 수정안 생성 여부
        provider: LLM 프로바이더
        model: LLM 모델명
        multi_patch: 다중 수정안 생성 여부
        on_progress: 진행 상황 콜백 (단계 메시지 문자열 전달)

    Returns:
        PipelineResult

    Raises:
        ValueError: 코드 크기 초과
        Exception: 분석 실패
    """
    def _progress(msg: str):
        if on_progress:
            on_progress(msg)

    if len(code) > MAX_CODE_SIZE:
        raise ValueError("코드가 너무 큽니다 (최대 1MB)")

    start_time = time.time()
    pipeline_result = PipelineResult()
    tmp_dir = tempfile.mkdtemp(prefix="dallo_analyze_")

    try:
        # 임시 파일 생성
        file_path = os.path.join(tmp_dir, filename)
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(code)

        lang = _detect_language(filename)
        pipeline_result.language = lang

        # Step 1: 정적 분석
        _progress(f"정적 분석 중... ({lang})")
        vuln_reports = _run_static_analysis(file_path, filename, lang)

        # Step 2: 문맥 추출
        _progress("코드 문맥 추출 중...")
        vuln_reports = _extract_context(vuln_reports, filename)

        # Step 3: 중복 제거
        _progress("중복 취약점 제거 중...")
        llm_targets = _deduplicate(vuln_reports)

        # Step 4: 위험도 산정
        _progress("위험도 산정 중...")
        _score_risk(vuln_reports)

        # Step 5: LLM 수정안 생성
        patches = []
        if use_llm and llm_targets:
            _progress(f"AI 수정안 생성 중... ({len(llm_targets)}/{len(vuln_reports)}건)")
            patches, llm_error = _generate_patches(llm_targets, provider, model, multi_patch)
            pipeline_result.llm_error = llm_error

        # Step 6: 코드 검증
        if patches:
            _progress("코드 검증 중...")
            _validate_syntax(patches, lang)

        # Step 7: 보안 재검증
        if patches:
            _progress("보안 재검증 중...")
            _validate_security(patches, vuln_reports, lang, filename)

        # 결과 조립
        _progress("결과 저장 중...")
        elapsed = time.time() - start_time
        result_data = _build_result(job_id, vuln_reports, patches, elapsed)

        # DB 저장
        db_error = _persist_to_db(result_data)
        pipeline_result.db_error = db_error
        pipeline_result.result_data = result_data

        _progress("완료")
        return pipeline_result

    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


# ============================================================
# 파이프라인 단계별 private 함수
# ============================================================

def _detect_language(filename: str) -> str:
    """파일 확장자에서 언어를 감지합니다."""
    from analyzer.semgrep_runner import EXTENSION_MAP
    ext = os.path.splitext(filename)[1].lower()
    return EXTENSION_MAP.get(ext, "unknown")


def _run_static_analysis(file_path: str, filename: str, lang: str) -> list:
    """정적 분석을 실행하고 raw 취약점 목록을 반환합니다."""
    from analyzer.semgrep_runner import detect_and_run
    from shared.schemas import VulnerabilityReport

    result = detect_and_run(file_path)

    vuln_reports = []
    for vuln in result.vulnerabilities:
        vuln_reports.append(VulnerabilityReport(
            id=f"vuln_{vuln.rule_id}_{vuln.line_number}",
            tool=vuln.tool,
            rule_id=vuln.rule_id,
            severity=vuln.severity,
            confidence=vuln.confidence,
            title=vuln.title,
            description=vuln.description,
            file_path=filename,
            line_number=vuln.line_number,
            code_snippet=vuln.code_snippet,
            cwe_id=vuln.cwe_id,
        ))
    return vuln_reports


def _extract_context(vuln_reports: list, filename: str) -> list:
    """취약점 주변 코드 문맥을 추출하여 vuln_reports에 반영합니다."""
    from analyzer.context_extractor import ContextExtractor

    extractor = ContextExtractor(context_lines=10)
    # context_extractor는 원래 분석기 결과 객체를 받으므로,
    # VulnerabilityReport에 대해서는 file_path 기반으로 추출 시도
    try:
        contexts = extractor.extract_batch(vuln_reports)
        context_map = {}
        for ctx in contexts:
            key = (ctx.vulnerability.file_path, ctx.vulnerability.line_number)
            context_map[key] = ctx

        for vuln in vuln_reports:
            ctx = context_map.get((vuln.file_path, vuln.line_number))
            if ctx:
                vuln.function_code = ctx.full_function
                vuln.file_imports = ctx.file_imports
    except Exception:
        # 문맥 추출 실패는 치명적이지 않음 — 코드 스니펫으로 진행
        logger.warning("[PIPELINE] 문맥 추출 실패 — 코드 스니펫으로 진행")

    return vuln_reports


def _deduplicate(vuln_reports: list) -> list:
    """중복 취약점을 제거하고 LLM 전달 대상(대표)을 반환합니다."""
    from analyzer.deduplicator import deduplicate

    dedup_result = deduplicate(vuln_reports)
    for vuln in vuln_reports:
        vuln.duplicate_group_id = dedup_result.group_map.get(vuln.id, "")
    return dedup_result.representatives


def _score_risk(vuln_reports: list):
    """전체 취약점에 위험도를 산정합니다."""
    from analyzer.risk_scorer import score_vulnerabilities
    score_vulnerabilities(vuln_reports)


def _generate_patches(
    llm_targets: list, provider: str, model: str, multi_patch: bool
) -> tuple[list, str | None]:
    """LLM 수정안을 생성합니다. (에러 시 빈 리스트 + 에러 메시지 반환)"""
    try:
        from agent.llm_agent import DalloAgent
        agent = DalloAgent(provider=provider, model=model)
        patches = agent.generate_patches(llm_targets, multi=multi_patch)
        return patches, None
    except Exception as e:
        logger.warning(f"[PIPELINE] LLM 수정안 생성 실패: {e}")
        return [], str(e)


def _validate_syntax(patches: list, lang: str):
    """패치 코드의 문법을 검증합니다."""
    from validator.syntax_checker import SyntaxChecker
    checker = SyntaxChecker()
    for p in patches:
        checker.check(p, language=lang)


def _validate_security(patches: list, vuln_reports: list, lang: str, filename: str):
    """패치 코드를 보안 재검증합니다."""
    from validator.security_checker import SecurityChecker
    from shared.schemas import PatchStatus

    vuln_map = {v.id: v for v in vuln_reports}
    sec_checker = SecurityChecker()

    for p in patches:
        if p.status == PatchStatus.FAILED:
            continue
        vuln = vuln_map.get(p.vulnerability_id)
        orig = (vuln.function_code or vuln.code_snippet or "") if vuln else ""
        sec_checker.check(p, language=lang, filename=filename, original_code=orig)


def _build_result(
    job_id: str, vuln_reports: list, patches: list, elapsed: float,
    *, now: Optional[datetime] = None,
) -> dict:
    """분석 결과를 세션 딕셔너리로 조립합니다.

    ``now`` 미주입 시 모듈 ``datetime.now()`` 를 호출하므로 운영 동작은 그대로다
    (Wave 4-U fakeable clock seam — 테스트가 ``completed_at`` 을 결정적으로
    검증할 수 있도록 keyword-only ``now`` 인자를 추가).
    """
    from shared.schemas import AnalysisSession

    session = AnalysisSession(
        session_id=job_id,
        repo="dashboard-upload",
        pr_number=0,
        commit_sha="direct-upload",
        vulnerabilities=vuln_reports,
        patches=patches,
    )
    session.update_stats()
    if now is None:
        now = datetime.now()
    session.completed_at = now.isoformat()
    session.duration_seconds = round(elapsed, 2)
    return session.to_dict()


def _persist_to_db(result_data: dict) -> str | None:
    """결과를 DB에 저장합니다. 실패 시 에러 메시지 반환."""
    try:
        from db import service as db_service
        db_service.save_analysis(result_data)
        return None
    except Exception as e:
        logger.warning(f"[PIPELINE] DB 저장 실패: {e}")
        return str(e)
