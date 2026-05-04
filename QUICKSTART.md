# 🚀 Dallo 프로젝트 빠른 시작 가이드

> 이준수 담당: 백엔드 / DevSecOps 파트

## 1단계: 프로젝트 초기 세팅

```bash
# GitHub 레포 생성 후 clone
git clone https://github.com/<your-org>/dallo-devsecops.git
cd dallo-devsecops

# Python 가상환경 생성
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# 의존성 설치
pip install -r requirements.txt

# 환경 변수 설정
cp .env.example .env
# .env 파일을 열어서 실제 값 입력
```

## 2단계: Bandit 분석 테스트 (가장 먼저!)

```bash
# 테스트용 취약 코드에 대해 Bandit 실행
bandit -r test_targets/ -f json -o reports/bandit_report.json

# 결과 확인 (CLI)
bandit -r test_targets/ -f screen

# 파이프라인 스크립트로 실행
python scripts/run_analysis.py --target test_targets/ --markdown
```

예상 결과: 약 20~30건의 취약점 탐지 (SQL Injection, 하드코딩 비밀번호, 취약 암호화 등)

## 3단계: SonarQube Docker 실행

```bash
# SonarQube + PostgreSQL 실행
cd docker
docker-compose up -d

# 상태 확인 (약 1~2분 소요)
docker-compose logs -f sonarqube
# "SonarQube is operational" 메시지가 나오면 준비 완료

# 웹 UI 접속
# http://localhost:9000
# 기본 계정: admin / admin (첫 로그인 시 비밀번호 변경)
```

### SonarQube 초기 설정:
1. http://localhost:9000 접속 → admin/admin 로그인
2. 비밀번호 변경
3. "Create Project" → Manual → Project Key: `dallo-devsecops`
4. "Locally" 선택 → 토큰 생성 → `.env`의 `SONAR_TOKEN`에 저장
5. sonar-scanner 설치:
   ```bash
   # macOS
   brew install sonar-scanner
   
   # Linux (apt)
   # https://docs.sonarqube.org/latest/analyzing-source-code/scanners/sonarscanner/
   
   # 또는 Docker로 실행
   docker run --rm \
     --network dallo-network \
     -e SONAR_HOST_URL=http://sonarqube:9000 \
     -e SONAR_TOKEN=<your-token> \
     -v "$(pwd):/usr/src" \
     sonarsource/sonar-scanner-cli
   ```

## 4단계: GitHub Actions 테스트

```bash
# 새 브랜치에서 작업
git checkout -b feature/test-analysis

# 취약 코드를 약간 수정 (PR 트리거용)
echo "# test" >> test_targets/sql_injection.py
git add .
git commit -m "test: 보안 분석 파이프라인 테스트"
git push origin feature/test-analysis

# GitHub에서 PR 생성 → Actions 자동 실행 → PR 코멘트 확인
```

### GitHub Secrets 설정 (레포 Settings → Secrets):
- `GITHUB_TOKEN`: 자동 제공 (별도 설정 불필요)
- `SONAR_TOKEN`: SonarQube 토큰 (3단계에서 생성한 것)

## 5단계: 전체 파이프라인 로컬 테스트

```bash
# 전체 파이프라인 실행 (마크다운 출력 포함)
python scripts/run_analysis.py \
  --target test_targets/ \
  --severity MEDIUM \
  --markdown \
  --json-output reports/full_result.json
```

---

## 역할별 연동 포인트

### 박영주 (AI) ← 이준수가 제공
- `analyzer/context_extractor.py`의 `CodeContext.to_prompt_context()` 출력을 LLM 프롬프트에 삽입
- `reports/bandit_report.json` → LLM 입력용 취약점 데이터
- `analyzer/bandit_runner.py`의 `Vulnerability` 데이터 구조

### 임해안 (프론트엔드/DB) ← 이준수가 제공  
- `analyzer/bandit_runner.py`의 `AnalysisResult.to_dict()` → DB 저장용 JSON
- `integrations/pr_commenter.py`의 코멘트 포맷 → 대시보드 표시용 참고

### 이준수가 박영주에게 받을 것
- `agent/` 디렉토리의 LLM 수정안 생성 결과
- 수정안 포맷: `{"explanation": str, "fixed_code": str}` 형태
- → `pr_commenter.py`의 `llm_suggestions` 파라미터로 연동

---

## 현재 완성된 모듈

| 모듈 | 파일 | 상태 |
|------|------|------|
| Bandit 분석 실행 | `analyzer/bandit_runner.py` | ✅ 완료 |
| SonarQube 분석 실행 | `analyzer/sonar_runner.py` | ✅ 완료 (Docker 필요) |
| 코드 문맥 추출 | `analyzer/context_extractor.py` | ✅ 완료 |
| 결과 파서/정규화 | `analyzer/result_parser.py` | ✅ 완료 |
| GitHub API 클라이언트 | `integrations/github_client.py` | 🟡 보류/미사용: Wave 4-C 기준 active caller 없음, 향후 사용 전 adapter seam/test 필요 |
| PR 코멘트 포맷터 | `integrations/pr_commenter.py` | ✅ 완료 |
| GitHub Actions 워크플로우 | `.github/workflows/security-analysis.yml` | ✅ 완료 |
| PR 코멘트 게시 스크립트 | `scripts/post_pr_comment.py` | ✅ 완료 |
| 전체 파이프라인 스크립트 | `scripts/run_analysis.py` | ✅ 완료 |
| Docker Compose | `docker/docker-compose.yml` | ✅ 완료 |
| 테스트용 취약 코드 (5종) | `test_targets/` | ✅ 완료 |

## 다음 할 일 (우선순위)

1. ☐ GitHub 레포 생성 & 코드 push
2. ☐ `pip install -r requirements.txt` 로컬 테스트
3. ☐ `bandit -r test_targets/` 실행해서 결과 확인
4. ☐ Docker에서 SonarQube 올리기
5. ☐ GitHub Actions PR 트리거 테스트
6. ☐ 박영주 LLM 모듈과 연동 인터페이스 확정
