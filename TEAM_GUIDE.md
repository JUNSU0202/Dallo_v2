# 팀원 연동 가이드

> 3명이 독립적으로 개발하면서도 코드가 자연스럽게 연결되도록 하는 구조입니다.

## 전체 데이터 흐름

```
이준수 (분석/백엔드)      박영주 (AI)              임해안 (프론트/DB)
─────────────────       ──────────────         ──────────────

Bandit + Semgrep        LLM API 호출            React 대시보드 (7개 탭)
     │                    │                       │
     ▼                    ▼                       ▼
VulnerabilityReport → DalloAgent →          FastAPI 서버 (17개 API)
(shared/schemas.py)  PatchSuggestion →      (api/server.py)
     │               (shared/schemas.py)         │
     ├── 문법 검증 ──────┤                       ▼
     ├── 보안 재검증 ────┤                  DB 저장/조회
     ├── 리포트 생성 ────┤                  (db/models.py)
     ▼                    ▼                       ▼
PR 코멘트 게시       Apply to GitHub       대시보드 표시 + 리포트
```

## 공통 규칙

### 1. 데이터는 반드시 shared/schemas.py 를 통해 주고받기

```python
from shared.schemas import VulnerabilityReport, PatchSuggestion, AnalysisSession
```

이 3개 클래스가 팀원 간 데이터 계약입니다.
필드를 추가/변경하려면 팀 전체 공유 후 수정하세요.

### 2. 브랜치 전략

```
main                ← 안정 버전만
├── dev             ← 통합 테스트용
├── feat/analyzer   ← 이준수 작업 브랜치
├── feat/agent      ← 박영주 작업 브랜치
└── feat/dashboard  ← 임해안 작업 브랜치
```

---

## 분석 파이프라인 (6단계)

대시보드에서 코드 분석 시 실행되는 전체 파이프라인:

```
Step 1: 정적 분석 (Bandit + Semgrep)
  → Python: Bandit + Semgrep 병합 / 기타 언어: Semgrep만
Step 2: 코드 문맥 추출 (함수 전체, import 문)
Step 3: LLM 수정안 생성 (Gemini/OpenAI/Claude)
  → 단일 수정안 또는 3가지 수정안 (최소/권장/구조적)
Step 4: 문법 검증 (Python: AST 파싱 / 기타: 중괄호 매칭)
Step 5: 보안 재검증 (수정 코드에 Bandit/Semgrep 재실행)
  → 새로운 취약점 도입 여부 확인
Step 6: 리포트 자동 생성 (HTML + Markdown)
  → DB 저장 + JSON 파일 저장
```

---

## 이준수 → 박영주 연동

### 이준수가 제공하는 것
분석 결과를 `VulnerabilityReport` 리스트로 만들어줍니다:

```python
# 이준수 코드 (analyzer → agent 연결)
from analyzer.semgrep_runner import detect_and_run
from analyzer.context_extractor import ContextExtractor
from shared.schemas import VulnerabilityReport

result = detect_and_run("test_targets/sql_injection.py")
extractor = ContextExtractor()

vuln_reports = []
for vuln in result.vulnerabilities:
    ctx = extractor.extract(vuln)
    report = VulnerabilityReport(
        id=f"vuln_{vuln.rule_id}_{vuln.line_number}",
        tool=vuln.tool,
        rule_id=vuln.rule_id,
        severity=vuln.severity,
        confidence=vuln.confidence,
        title=vuln.title,
        description=vuln.description,
        file_path=vuln.file_path,
        line_number=vuln.line_number,
        code_snippet=vuln.code_snippet,
        function_code=ctx.full_function,
        file_imports=ctx.file_imports,
        cwe_id=vuln.cwe_id,
    )
    vuln_reports.append(report)
```

### 박영주가 구현한 것
`agent/llm_agent.py`의 `DalloAgent` 클래스 (574줄):

```python
from agent.llm_agent import DalloAgent

# 3개 프로바이더 지원 (openai, gemini, anthropic)
agent = DalloAgent(provider="gemini")

# 단일 수정안
patches = agent.generate_patches(vuln_reports)

# 3가지 수정안 (최소/권장/구조적)
patches = agent.generate_patches(vuln_reports, multi=True)
# → list[PatchSuggestion] 반환
```

구현된 주요 기능:
- `_build_prompt()` — 언어별 맞춤 프롬프트 구성
- `_build_multi_prompt()` — 3가지 수정안 요청 프롬프트
- `_call_llm()` — OpenAI/Gemini/Claude API 호출
- `_parse_response()` — 응답에서 코드와 설명 추출 (3단계 폴백)
- `_parse_multi_response()` — 3가지 수정안 파싱
- API 키 로테이션, Rate limit 자동 대응

---

## 이준수 → 임해안 연동

### 이준수가 제공하는 것
분석 결과를 JSON으로 저장하고, API 서버로 제공합니다:

```bash
# 전체 파이프라인 실행
python scripts/run_analysis.py --target test_targets/ --json-output reports/full_result.json

# 서버 시작
python start.py
```

### 임해안이 사용하는 것

**API 엔드포인트 (17개)**

| Method | Endpoint | 설명 |
|--------|----------|------|
| GET | `/` | 서버 상태 확인 |
| GET | `/api/stats` | 대시보드 통계 |
| GET | `/api/vulnerabilities` | 취약점 목록 (필터: severity, tool, file_path) |
| GET | `/api/vulnerabilities/by-file` | 파일별 취약점 집계 |
| GET | `/api/vulnerabilities/by-type` | 유형별 취약점 집계 |
| GET | `/api/patches` | AI 수정 제안 목록 |
| GET | `/api/sessions` | 분석 세션 이력 |
| GET | `/api/sessions/{id}` | 세션 상세 조회 |
| POST | `/api/analyze` | 코드 분석 실행 (비동기) |
| POST | `/api/analyze/file` | 파일 업로드 분석 |
| GET | `/api/analyze/{job_id}` | 분석 진행 상태 |
| POST | `/api/apply-patch` | 수정안 적용 + GitHub PR 생성 |
| GET | `/api/report/generate` | 리포트 생성 (HTML/MD) |
| GET | `/api/report/preview` | 리포트 미리보기 (HTML+MD 반환) |
| GET | `/api/report/download/{filename}` | 리포트 파일 다운로드 |
| GET | `/api/dependencies` | 프로젝트 의존성 스캔 |
| POST | `/api/dependencies/scan` | 의존성 스캔 (텍스트 입력) |
| GET | `/dashboard` | 웹 대시보드 |

**DB 직접 접근**
```python
from db.models import init_db, SessionLocal, Vulnerability, AnalysisRun, Patch
from db.service import save_analysis, get_latest_analysis, get_all_sessions, get_stats

# 테이블 생성
init_db()

# 최신 분석 결과 조회
result = get_latest_analysis()

# 통계 조회
stats = get_stats()
```

### 대시보드 페이지 구성 (7개 탭)

| 탭 | 컴포넌트 | 설명 |
|----|---------|------|
| 코드 분석 | AnalyzeView.jsx | 코드 입력/업로드, 실시간 분석, 결과+수정안 표시 |
| 대시보드 | StatsCards + FileChart + TypeChart | 통계 카드 6개, 파일별/유형별 차트 |
| 취약점 목록 | VulnTable.jsx | 심각도별 필터, 상세 코드 보기, CWE 링크 |
| AI 수정안 | PatchView.jsx | 수정안 상세, 보안 재검증 결과, Diff 비교 |
| 의존성 검사 | DependencyView.jsx | pip-audit/npm audit 스캔, SBOM 목록 |
| 리포트 | ReportView.jsx | HTML 리포트 새 탭 열기, 마크다운 다운로드 |
| 분석 이력 | HistoryView.jsx | 세션 목록, 취약점 추이 차트, 패치 성공률 |

---

## 박영주 → 이준수 연동 (수정안 검증)

박영주가 생성한 PatchSuggestion을 이준수가 2단계로 검증합니다:

### 1단계: 문법 검증 (validator/syntax_checker.py)
```python
from validator.syntax_checker import SyntaxChecker

checker = SyntaxChecker()
patch = checker.check(patch, language="python")
# patch.syntax_valid = True/False
# Python: AST 파싱, Java/JS/Go/C: 중괄호 매칭
```

### 2단계: 보안 재검증 (validator/security_checker.py)
```python
from validator.security_checker import SecurityChecker

sec_checker = SecurityChecker()
patch = sec_checker.check(patch, language="python", filename="app.py", original_code=original)
# 수정 코드에 Bandit/Semgrep 재실행
# 새로운 취약점 도입 여부 확인
# patch.security_revalidation = {passed: True/False, ...}
# patch.status = "verified" 또는 "failed"
```

검증 완료된 수정안은 PR 코멘트에 포함되고, 대시보드에서 검증 상태가 표시됩니다.

---

## 추가 기능

### 의존성 취약점 분석 (analyzer/dependency_scanner.py)
```python
from analyzer.dependency_scanner import DependencyScanner

scanner = DependencyScanner()
# 프로젝트 디렉토리 스캔 (requirements.txt, package.json 자동 감지)
results = scanner.scan("/path/to/project")

# 또는 requirements.txt 텍스트 직접 전달
result = scanner.scan_requirements_text("django==3.2.0\nflask==2.0.0")
```

### 리포트 자동 생성 (reports/report_generator.py)
```python
from reports.report_generator import ReportGenerator

gen = ReportGenerator()
# 마크다운 리포트
md = gen.generate_markdown(session_data)
# HTML 리포트
html = gen.generate_html(session_data)
# 파일로 저장
gen.save_report(session_data, output_dir="reports", fmt="both")
```

### 민감정보 마스킹 (shared/masking.py)
```python
from shared.masking import DataMasker

masker = DataMasker()
result = masker.mask(code_with_secrets)
# API 키, 비밀번호, 토큰 등이 [MASKED_xxx]로 치환됨
# LLM 응답 후 masker.unmask()로 복원
```

---

## 파일 구조 (팀원별 담당)

```
dallo-devsecops/
├── shared/                     ← 공통 (3명 공유)
│   ├── schemas.py              ✅ VulnerabilityReport, PatchSuggestion, AnalysisSession
│   ├── masking.py              ✅ 민감정보 마스킹/복원
│   └── encryption.py           ✅ AES-256 암호화
│
├── analyzer/                   ← 이준수
│   ├── bandit_runner.py        ✅ Bandit 정적 분석
│   ├── semgrep_runner.py       ✅ Semgrep 다중 언어 분석
│   ├── sonar_runner.py         ✅ SonarQube 연동
│   ├── context_extractor.py    ✅ 코드 문맥 추출 (14개 언어)
│   ├── result_parser.py        ✅ 다중 도구 결과 병합
│   └── dependency_scanner.py   ✅ 의존성 취약점 스캔 (pip-audit/npm audit)
│
├── agent/                      ← 박영주
│   └── llm_agent.py            ✅ 3개 LLM 프로바이더, 다중 수정안, 키 로테이션
│
├── validator/                  ← 이준수
│   ├── syntax_checker.py       ✅ 문법 검증 (AST + 중괄호 매칭)
│   ├── test_runner.py          ✅ pytest 샌드박스 실행
│   └── security_checker.py     ✅ 보안 재검증 (수정 코드 재스캔)
│
├── api/                        ← 임해안
│   └── server.py               ✅ FastAPI 서버 (17개 엔드포인트)
├── db/                         ← 임해안
│   ├── models.py               ✅ 테이블 구조 (3개 테이블)
│   └── service.py              ✅ DB 서비스 레이어
│
├── dashboard/src/components/   ← 임해안
│   ├── AnalyzeView.jsx         ✅ 코드 분석 (입력/업로드/샘플/결과)
│   ├── StatsCards.jsx          ✅ 통계 카드 (6개)
│   ├── FileChart.jsx           ✅ 파일별 취약점 차트
│   ├── TypeChart.jsx           ✅ 유형별 취약점 차트
│   ├── VulnTable.jsx           ✅ 취약점 테이블 (필터/상세)
│   ├── PatchView.jsx           ✅ AI 수정안 (보안 재검증 표시)
│   ├── DependencyView.jsx      ✅ 의존성 취약점 검사
│   ├── ReportView.jsx          ✅ 리포트 생성/보기/다운로드
│   └── HistoryView.jsx         ✅ 분석 이력 + 추이 차트
│
├── integrations/               ← 이준수
│   ├── github_client.py        🟡 보류/미사용: Wave 4-C 기준 active caller 없음, 향후 사용 전 adapter seam/test 필요
│   └── pr_commenter.py         ✅ PR 코멘트 작성
├── scripts/                    ← 이준수
│   ├── run_analysis.py         ✅ CLI 분석 실행
│   └── post_pr_comment.py      ✅ PR 코멘트 게시
├── reports/
│   └── report_generator.py     ✅ 리포트 생성 (HTML/마크다운)
│
├── docker/                     ← 공통
│   └── docker-compose.yml      ✅ API + PostgreSQL + SonarQube
├── config/                     ← 공통
│   ├── bandit.yml              ✅
│   └── sonar-project.properties ✅
├── tests/                      ← 공통
│   ├── test_bandit_runner.py   ✅ (8개)
│   ├── test_context_extractor.py ✅ (5개)
│   ├── test_llm_parser.py      ✅ (8개)
│   ├── test_syntax_checker.py  ✅ (6개)
│   └── test_api_server.py      ✅ (8개)
├── test_targets/               ← 공통 (10개 샘플)
│   ├── sql_injection.py        ✅
│   ├── command_injection.py    ✅
│   ├── hardcoded_secrets.py    ✅
│   ├── insecure_crypto.py      ✅
│   ├── xss_vulnerable.py       ✅
│   ├── insecure_auth.py        ✅
│   ├── insecure_deserialization.py ✅
│   ├── VulnerableApp.java      ✅
│   ├── vulnerable_app.js       ✅
│   └── vulnerable_app.go       ✅
│
├── .github/workflows/
│   └── security-analysis.yml   ✅ PR 자동 분석
├── start.py                    ✅ 원클릭 실행
├── Dockerfile                  ✅
└── requirements.txt            ✅
```

---

## 빠른 시작

```bash
# 1. 클론
git clone https://github.com/JUNSU0202/dallo-devsecops.git
cd dallo-devsecops

# 2. 가상환경 + 의존성
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# 3. 환경변수
cp .env.example .env
# .env에 GEMINI_API_KEY 등 설정

# 4. 서버 시작
python start.py
# → http://localhost:8000/dashboard

# 5. 대시보드에서 사용
# 코드 분석 탭 → 코드 붙여넣기 또는 샘플 로드 → 분석 시작
# 의존성 검사 탭 → 프로젝트 스캔 또는 requirements.txt 입력
# 리포트 탭 → 리포트 보기 (새 탭에서 열림)
```
