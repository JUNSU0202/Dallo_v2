"""분석 리포트 생성 패키지 (reports).

ReportGenerator 는 정적 분석 결과 dict 로부터 HTML / Markdown 리포트를
순수 Python 으로 생성한다 (네트워크/LLM 호출 없음).
"""

from reports.report_generator import ReportGenerator

__all__ = ["ReportGenerator"]
