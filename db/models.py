"""
DB 모델 정의 (db/models.py)

임해안 담당: 이 파일의 테이블 구조를 기반으로 DB를 구성하고
대시보드에서 데이터를 조회합니다.

사용법:
  from db.models import engine, SessionLocal, Vulnerability, Patch, AnalysisRun

  # DB 테이블 생성
  Base.metadata.create_all(bind=engine)

  # 데이터 저장
  with SessionLocal() as session:
      vuln = Vulnerability(rule_id="B608", severity="MEDIUM", ...)
      session.add(vuln)
      session.commit()
"""

import os
from sqlalchemy import (
    create_engine,
    Column,
    Integer,
    String,
    Text,
    Boolean,
    Float,
    DateTime,
    ForeignKey,
    Enum as SQLEnum,
)
from sqlalchemy.orm import (
    DeclarativeBase,
    sessionmaker,
    relationship,
)

from db import clock


# ============================================================
# DB 연결 설정
# ============================================================

_DB_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SQLITE_PATH = os.path.join(_DB_DIR, "dallo.db")
_SQLITE_URL = f"sqlite:///{_SQLITE_PATH}"

DATABASE_URL = os.environ.get("DATABASE_URL") or _SQLITE_URL

def _create_engine():
    """PostgreSQL 우선, 실패 시 SQLite 폴백"""
    url = DATABASE_URL
    if url.startswith("postgresql"):
        try:
            eng = create_engine(url, echo=False, pool_pre_ping=True)
            with eng.connect():
                pass  # 연결 테스트
            return eng
        except Exception:
            url = _SQLITE_URL

    return create_engine(url, echo=False,
                         connect_args={"check_same_thread": False} if "sqlite" in url else {})

engine = _create_engine()
SessionLocal = sessionmaker(bind=engine)


class Base(DeclarativeBase):
    pass


# ============================================================
# 테이블 1: 분석 실행 이력 (analysis_runs)
# ============================================================

class AnalysisRun(Base):
    """
    분석 파이프라인 1회 실행 기록

    PR 1개당 1개의 레코드가 생성됨.
    대시보드에서 '분석 이력' 페이지에 표시.
    """
    __tablename__ = "analysis_runs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(String(100), unique=True, nullable=False)
    repo = Column(String(200), nullable=False)             # owner/repo
    pr_number = Column(Integer, nullable=False)
    commit_sha = Column(String(40), nullable=False)
    branch = Column(String(200), default="")

    # 통계
    total_issues = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    patches_generated = Column(Integer, default=0)
    patches_verified = Column(Integer, default=0)

    # 시간
    started_at = Column(DateTime, default=clock.now)
    completed_at = Column(DateTime, nullable=True)
    duration_seconds = Column(Float, nullable=True)

    # 관계
    vulnerabilities = relationship("Vulnerability", back_populates="analysis_run")

    def __repr__(self):
        return f"<AnalysisRun PR#{self.pr_number} ({self.total_issues} issues)>"


# ============================================================
# 테이블 2: 취약점 (vulnerabilities)
# ============================================================

class Vulnerability(Base):
    """
    탐지된 취약점 레코드

    이준수의 분석 결과가 여기에 저장됨.
    대시보드에서 '취약점 목록' 페이지에 표시.
    """
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True, autoincrement=True)
    vuln_id = Column(String(100), nullable=False)  # 세션 내 고유 ID
    run_id = Column(Integer, ForeignKey("analysis_runs.id"), nullable=True)

    # 취약점 정보
    tool = Column(String(50), nullable=False)          # bandit / sonarqube
    rule_id = Column(String(50), nullable=False)       # B608 등
    severity = Column(String(20), nullable=False)      # HIGH / MEDIUM / LOW
    confidence = Column(String(20), default="")
    title = Column(String(500), nullable=False)
    description = Column(Text, default="")
    cwe_id = Column(String(20), nullable=True)

    # 코드 위치
    file_path = Column(String(500), nullable=False)
    line_number = Column(Integer, nullable=False)
    code_snippet = Column(Text, default="")
    function_code = Column(Text, default="")

    # 시간
    detected_at = Column(DateTime, default=clock.now)

    # 관계
    analysis_run = relationship("AnalysisRun", back_populates="vulnerabilities")
    patches = relationship("Patch", back_populates="vulnerability")

    def __repr__(self):
        return f"<Vulnerability [{self.severity}] {self.rule_id} at {self.file_path}:{self.line_number}>"


# ============================================================
# 테이블 3: 수정 제안 (patches)
# ============================================================

class Patch(Base):
    """
    LLM이 생성한 코드 수정 제안

    박영주의 LLM 모듈이 생성한 수정안이 여기에 저장됨.
    대시보드에서 '수정 제안' 페이지 및 Diff 비교에 사용.
    """
    __tablename__ = "patches"

    id = Column(Integer, primary_key=True, autoincrement=True)
    vulnerability_id = Column(Integer, ForeignKey("vulnerabilities.id"), nullable=False)

    # 수정 내용
    fixed_code = Column(Text, nullable=False)
    explanation = Column(Text, default="")
    fix_type = Column(String(50), default="recommended")  # minimal / recommended / structural

    # 검증 결과
    status = Column(String(20), default="pending")
    syntax_valid = Column(Boolean, nullable=True)
    test_passed = Column(Boolean, nullable=True)

    # 시간
    created_at = Column(DateTime, default=clock.now)
    verified_at = Column(DateTime, nullable=True)

    # 관계
    vulnerability = relationship("Vulnerability", back_populates="patches")

    def __repr__(self):
        return f"<Patch vuln={self.vulnerability_id} status={self.status}>"


# ============================================================
# DB 초기화 함수
# ============================================================

def init_db():
    """테이블 생성 (없으면 새로 만듦)"""
    Base.metadata.create_all(bind=engine)
    print("[+] DB 테이블 초기화 완료")


def drop_db():
    """테이블 전체 삭제 (주의!)"""
    Base.metadata.drop_all(bind=engine)
    print("[!] DB 테이블 전체 삭제")
