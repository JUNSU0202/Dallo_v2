# Dallo 클린 아키텍처 리팩터링 Wave 이력

> 본 문서는 Dallo DevSecOps 프로젝트가 **Wave 2-A 부터 Wave 4-I 까지** 어떤 순서와 이유로 구조를 정리해 왔는지를 기록한다.
> 후일 코드를 다시 열지 않고도 "왜 이 방향으로 갔는가"를 재구성할 수 있도록 설계되었다.
> 본 문서에는 어떠한 운영 비밀(secret), 토큰 값, 자격 증명도 포함되어 있지 않다. 환경 변수 이름만이 등장한다.

---

## 1. 문서의 목적

Dallo는 AI/Vibe-Coding 환경에서 자동 보안 분석을 수행하는 DevSecOps 도구다.
이 프로젝트는 여러 wave에 걸쳐 “큰 폴더 이동(Big-Bang Reshuffle) 없이 동작을 보존하면서 점진적으로 클린 아키텍처/클린 코드 원칙으로 정리한다”는 방침을 유지해 왔다.

이 문서는 다음 질문들에 답하기 위해 작성되었다.

1. 각 Wave 가 **왜** 수행되었는가? (문제/위험)
2. **이전 구조** 는 어떻게 생겼었는가?
3. **무엇이 바뀌었는가?** (파일/책임/경계)
4. 그 변화가 **클린 아키텍처/클린 코드 원칙에 어떻게 부합** 하는가?
5. **무엇은 바뀌지 않았는가?** (보존된 동작)
6. **어떤 검증** 으로 안전성이 입증되었는가?
7. 문제가 발생했을 때 **어떻게 되돌릴 수 있는가?** (rollback)

대상 독자는 Dallo 프로젝트에 새로 합류하는 주니어 엔지니어와, 같은 패턴을 다른 모듈에 적용하려는 시니어 엔지니어다.

---

## 2. Executive Summary — 전체 리팩터링 전략

Dallo 의 리팩터링은 **세 단계의 큰 흐름** 으로 진행되었다.

| 큰 단계 | 범위 | 핵심 키워드 | 결과 |
| --- | --- | --- | --- |
| **Wave 2 (A~S, 19 wave)** | API/라우터/서비스/부트스트랩/경로 안정화 | 단일 파일에 뭉친 책임을 라우터·서비스 계층으로 분리, 부트스트랩 부수효과 정리, 경로 안전성 강화 | `api/server.py` 거대 파일을 라우터/서비스 단위로 분해 |
| **Wave 3 (A~J, 11 wave)** | analyzer/외부 의존 경계 추출 | subprocess·HTTP·시간 의존성을 어댑터(seam)로 분리, fakeable 테스트 가능한 구조로 전환 | `pip-audit`, Bandit, Semgrep, Sonar scanner, Sonar HTTP, polling clock 까지 모두 외부 경계 격리 |
| **Wave 4 (A~I, 9 wave)** | validator·통합·토큰·환경 변수 보안 강화 | argv exposure 제거, child env sanitizer 도입, GitHub PR 코멘트 어댑터 분리, deferred legacy 표시, dependency scanner env sanitizer, validator child env sanitizer | 비밀(secret) 누출 가능 경로를 명시적 capability grant 모델로 재설계 |

핵심 원칙은 다음 네 가지다.

1. **동작 보존(behavior-preserving)**
   - 매 Wave 는 외부에서 본 입력/출력/HTTP 응답/CLI 메시지/타임아웃/한국어 에러 문구를 그대로 유지했다.
   - 변경된 것은 “책임이 어느 모듈에 있는가” 와 “외부 세계와 어떻게 닿는가” 뿐이다.
2. **점진(incremental) 리팩터링**
   - 한 Wave 에서 한 책임만 옮긴다.
   - 폴더 구조를 한꺼번에 바꾸지 않는다.
3. **포트(port) / 어댑터(adapter) / 심(seam) 도입**
   - subprocess, HTTP, 시계, 파일 시스템 등 외부 세계로 닿는 호출을 별도 어댑터 클래스로 추출한다.
   - 어댑터는 의존성 주입(DI)을 통해 fake 로 교체 가능하다.
4. **AI/Vibe-Coding 환경에 특화된 보안 우선(security-first) 강화**
   - 부모 프로세스 환경에는 LLM API 키, GitHub 토큰, 클라우드 자격증명, 패키지 레지스트리 토큰이 흔히 존재한다.
   - 외부 도구(Semgrep, Bandit, Sonar 등)에 이런 비밀이 묵시적으로 상속되지 않도록 한다.
   - 비밀은 argv 가 아닌 명시적 capability grant 로 전달한다.

---

## 3. 아키텍처 방향성

### 3.1 동작을 깨지 않는 점진적 리팩터링

리팩터링은 “기능을 그대로 유지하되 내부 구조를 더 좋게 만드는 작업” 이다.
Dallo 는 기능을 깨면 보안 분석 파이프라인 전체가 멈추기 때문에, 모든 Wave 에서 다음 규칙을 강제했다.

- `shared/schemas.py` 는 시스템 계약(contract) 이므로 명시 승인 없이 수정하지 않는다.
- 기존 HTTP 응답 모양, CLI 종료 코드, 한국어 에러 메시지, 타임아웃 값은 보존한다.
- 모든 Wave 는 “Targeted tests → Broader tests → Full tests → Independent review → Security scan” 순서로 검증한다.

### 3.2 빅뱅(big-bang) 폴더 재배치를 하지 않는 클린 아키텍처

Robert C. Martin 의 *Clean Architecture* 는 일반적으로 다음과 같은 동심원 구조로 설명된다.

```
Entities  ←  Use Cases  ←  Interface Adapters  ←  Frameworks/Drivers
```

Dallo 는 이 그림에 맞춰 디렉터리를 다 옮기는 대신, **현재 디렉터리 구조를 그대로 두고 책임만 단계적으로 옮기는 방식** 을 택했다.

- 폴더 이동은 git diff 면에서 “바뀐 줄” 이 폭발적으로 증가하기 때문에 회귀 위험이 크다.
- 대신 “외부 의존(subprocess, requests, time, os.environ) 을 만나는 단 한 곳을 어댑터로 빼낸다” 라는 작은 변환을 반복했다.
- 그 결과 디렉터리 이름은 그대로지만, 각 모듈의 **책임은 점점 좁고 명확해졌다**.

### 3.3 포트·어댑터·심(seam)으로 외부 의존을 격리

- `analyzer/static_tool_command_runner.py` 는 Bandit·Semgrep 의 subprocess 경계 어댑터다.
- `analyzer/sonar_runner.py` + `analyzer/sonar_http_client.py` 는 Sonar 스캐너의 subprocess 와 HTTP 경계를 분리한 어댑터 쌍이다.
- `validator/validator_command_runner.py` 는 flake8/pytest 호출을 격리한 어댑터다.
- `integrations/github_pr_comment_adapter.py` 는 GitHub Issues comments API 의 GET/PATCH/POST 경계를 분리한 어댑터다.

이 어댑터들은 모두 다음 특성을 갖는다.

- 단일 책임: subprocess.run 또는 requests 호출 한 종류만 담당한다.
- shell=True 금지, list-argv 만 허용.
- 타임아웃 명시.
- 의존성 주입으로 fake 객체 교체 가능.

### 3.4 보안 우선 강화 (AI/Vibe-Coding hardening)

Wave 4-D 이후의 흐름은 “외부 도구가 부모 프로세스에 있는 비밀을 무심코 상속받지 않게 한다” 는 보안 강화에 집중한다.

- argv exposure 제거: 비밀을 `-Dsonar.token=...` 같은 argv 로 전달하지 않는다.
- ambient env 차단: 부모 환경 변수의 secret-like 이름을 자식 프로세스에 그대로 넘기지 않는다.
- explicit capability grant: 자식 프로세스가 정말로 필요로 하는 변수만 명시적으로 허용한다.

---

## 4. 용어집 (Glossary)

본 문서를 처음 읽는 독자를 위해 핵심 용어를 한 번에 정리한다.

- **클린 아키텍처(Clean Architecture)**
  - 비즈니스 규칙(엔티티/유스케이스) 이 프레임워크·DB·외부 서비스에 의존하지 않도록 의존 방향을 안쪽으로 모으는 설계 사상.
  - Dallo 에서는 “분석 흐름” 이 “subprocess/HTTP/파일시스템” 을 직접 알지 않게 한다는 의미로 적용된다.

- **클린 코드(Clean Code)**
  - 한 함수/클래스가 한 가지 일만 하고, 이름이 의도를 드러내며, 부수효과(side effect) 가 명시되어 있는 코드 스타일.
  - “함수가 길면 잘라라, 책임이 섞이면 분리하라” 정도로 요약된다.

- **경계(Boundary)**
  - 우리 코드와 외부 세계(OS, 네트워크, 외부 도구, 시계, 파일시스템) 가 만나는 지점.
  - 경계에는 항상 어댑터를 둔다는 것이 본 프로젝트의 원칙이다.

- **어댑터(Adapter)**
  - 외부 세계로 나가는 호출을 한 곳에 모은 구현체.
  - 예: `StaticToolCommandRunner` 는 `subprocess.run` 호출을 한 군데로 모은다.
  - 어댑터가 있으면 테스트에서 외부 도구를 실제로 실행하지 않고도 호출 인자를 검증할 수 있다.

- **포트(Port)**
  - 어댑터가 만족해야 하는 “계약(인터페이스)” 의 역할.
  - Python 에서는 명시적 인터페이스 클래스 대신 “이런 시그니처의 객체를 받는다” 는 약속으로 표현되는 경우가 많다.

- **심(Seam)**
  - 코드 안에서 “여기서 의존성을 끼워 넣어 다른 구현으로 바꿀 수 있다” 는 지점.
  - DI 가능한 생성자 인자, 키워드 인자, 모듈 레벨 함수 주입이 모두 seam 이다.

- **의존성 주입(Dependency Injection, DI)**
  - 객체가 자신이 필요한 의존을 직접 만들지 않고, 외부에서 받아오게 하는 방식.
  - 예: `TestRunner(project_root=..., runner=ValidatorCommandRunner())`.

- **Fake / 테스트 더블(Test Double)**
  - 실제 외부 호출 대신 미리 정의된 응답을 돌려주는 가짜 객체.
  - “Mock” 과 비슷하지만, fake 는 실제 동작을 단순화해서 흉내 내는 객체에 가깝다.
  - 본 프로젝트에서는 어댑터를 통해 외부 도구를 fake 로 대체한다.

- **Ambient Environment Variable**
  - “주변 환경에 떠다니는” 환경 변수.
  - 부모 셸/CI/Docker 호스트가 가진 모든 환경 변수가 자식 프로세스로 그대로 흘러 들어가는 상황을 가리킨다.
  - AI/Vibe-Coding 환경에서는 이 ambient env 에 비밀이 잘 들어 있어 위험하다.

- **Capability Grant**
  - 자식 프로세스에게 “이 변수는 명시적으로 허락한다” 라고 한 번 결정해서 넘겨주는 방식.
  - ambient inheritance 의 반대 개념. Wave 4-D ~ 4-G 의 핵심 패턴이다.

- **argv exposure**
  - 명령줄 인자(argv) 에 비밀이 들어가 `ps`, `/proc/<pid>/cmdline`, audit/eBPF 도구, CI 로그 등을 통해 노출되는 위험.
  - Wave 4-D 가 이를 직접적으로 차단했다.

- **allowlist / deny filter**
  - allowlist: 허용 목록. “이 이름들만 통과시킨다.”
  - deny filter: 금지 목록. “이 이름들은 무조건 막는다.”
  - `build_child_env()` 는 allowlist 를 1차 게이트로, secret-name deny filter 를 2차 게이트로, `extras` capability grant 를 마지막 게이트로 사용하는 다층 방어다.

- **Lazy import**
  - 모듈을 파일 상단이 아니라, 함수가 실제로 호출될 때 import 하는 기법.
  - 부트스트랩 시 무거운 의존(예: Celery, Redis) 을 강제로 끌어오지 않게 해서 시작 부수효과를 줄인다.
  - Wave 2-K 가 이 패턴을 도입했다.

- **Smoke test**
  - 실제 외부 호출 없이 “경로가 호출되긴 했고, 인자/환경/순서가 의도대로 구성되었다” 를 fake 로 빠르게 확인하는 테스트.
  - Dallo 의 보안 속성(예: 토큰이 argv 에 없는가) 검증의 핵심 도구다.

- **Targeted test / Full test**
  - Targeted test: 이번 Wave 가 직접 건드린 모듈만 좁게 도는 테스트.
  - Full test: `pytest tests/ -q` 로 전체 회귀를 점검하는 테스트.
  - 모든 Wave 는 두 종류 모두 통과해야 merge 된다.

- **Rollback**
  - 문제가 생겼을 때 변경을 되돌리는 절차.
  - Dallo 에서는 각 Wave 의 머지 커밋이 단일 머지 커밋이라 `git revert -m 1 <merge>` 한 번으로 되돌릴 수 있다.

---

## 5. 전체 Wave 타임라인

본 표는 git log 와 각 Wave 의 rationale/continuity 문서로부터 검증된 사실만을 담는다.

| Wave | 머지 커밋 | 한 줄 목적 | 주요 영역 | 주요 아키텍처 효과 |
| --- | --- | --- | --- | --- |
| 2-A | `6f99768` | API 응답 DTO 레이어 도입 | `api/dto/*`, `api/server.py` | HTTP 응답 모양을 명시적 DTO 로 고정 |
| 2-B | `1a22d4c` | 대시보드 조회 라우터 분리 | `api/routers/dashboard.py` | 거대 `server.py` 에서 read-only 엔드포인트 분리 |
| 2-C | `01a0543` | 빠른 스캔 라우터 + 도메인 분리 | `api/routers/quick_scan.py`, `analyzer/quick_scan.py` | quick scan 도메인 로직을 라우터 밖으로 빼냄 |
| 2-D | `4e97659` | 리포트 라우터 분리 | `api/routers/report.py` | 리포트 엔드포인트를 별도 라우터로 |
| 2-E | `f64a30f` | 의존성 스캔 라우터 분리 | `api/routers/dependencies.py` | 의존성 스캔 경로 격리 |
| 2-F | `5fe69e0` | 패치 적용 라우터 분리 | `api/routers/patch.py` | apply-patch 흐름 분리 |
| 2-G | `d2ad34c` | 분석/잡 라우터 분리 | `api/routers/analyze.py` | 분석 잡 흐름을 별도 라우터로 |
| 2-H | `adcab29` | 부트스트랩 settings 분리 | `api/settings.py` | `server.py` 부트스트랩 경계 정리 |
| 2-I | `6d3f911` | lifespan 부트스트랩 정리 | `api/server.py`, lifespan | startup 부수효과를 lifespan 으로 이동 |
| 2-J | `39fedb9` | sys.path bootstrap hack 제거 | `api/server.py`, `api/celery_app.py`, `api/tasks.py`, `db/service.py` | sys.path 변조 제거 |
| 2-K | `012dd17` | Celery/Redis lazy 화 | `api/routers/analyze.py` | Celery import 부수효과 lazy 화 |
| 2-L | `128c7cb` | apply patch 서비스 분리 | `api/services/patch_application.py` | 라우터 → 서비스 책임 분리 |
| 2-M | `2677318` | 대시보드 쿼리 서비스 분리 | `api/services/dashboard_queries.py` | 조회 로직을 서비스 계층으로 |
| 2-N | `ed9795f` | 의존성 스캐닝 서비스 분리 | `api/services/dependency_scanning.py` | 라우터 ↔ 도메인 결합 약화 |
| 2-O | `33c7759` | result_source 하드닝 | `api/result_sources.py` | 결과 로딩 경계 안전성 강화 |
| 2-P | `448c0b0` | analyze reports dir late binding | `api/routers/analyze.py` | reports 디렉터리 경로의 부트스트랩 의존 제거 |
| 2-Q | `5560d23` | 리포트 다운로드 경로 하드닝 | `api/routers/report.py` | 경로 traversal 안전성 |
| 2-R | `c170bd8` | 리포트 생성 서비스 분리 | `api/services/report_generation.py` | 리포트 생성 로직을 서비스 계층으로 |
| 2-S | `8d50caa` | 분석 파이프라인 서비스 분리 | `api/services/analysis_pipeline.py` | 라우터 → 파이프라인 서비스 추출 |
| 3-A | `258a11d`, `e0f1a1c` | Celery detector 서비스 + eval cleanup | `api/services/celery_detector.py` | eval 기반 lazy detection 제거 |
| 3-B | `f91c5e8` | safe_paths 헬퍼 중앙화 | `api/services/safe_paths.py` | 경로 안전 검증 단일 위치 |
| 3-C | `7f7e124` | 경로 settings 안정화 | `api/settings.py` | 경로 설정 단일 출처화 |
| 3-D | `85051af` | analysis job store 분리 | `api/services/analysis_jobs_store.py` | 잡 메모리 스토어 캡슐화 |
| 3-E | `d1c434e` | GitHub patch adapter 분리 | `api/services/github_patch_adapter.py` | 외부 GitHub 호출 격리 |
| 3-F | `d310798` | dependency command runner 어댑터 | `analyzer/dependency_command_runner.py` | pip-audit/npm subprocess 격리 |
| 3-G | `3f67e3d` | static tool command runner 어댑터 | `analyzer/static_tool_command_runner.py` | Bandit/Semgrep subprocess 격리 |
| 3-H | `1096ef4` | sonar scanner runner 추출 | `analyzer/sonar_runner.py` | Sonar 스캐너 subprocess 격리 |
| 3-I | `14e3d35` | sonar http client 추출 | `analyzer/sonar_http_client.py` | Sonar HTTP 호출 격리 |
| 3-J | `47a4e5b` | sonar polling clock/sleeper 격리 | `analyzer/sonar_runner.py` | `time.sleep`/`time.time` seam 화 |
| 4-A | `edd5070` | validator command runner 어댑터 | `validator/validator_command_runner.py` | flake8/pytest subprocess 격리 |
| 4-B | `ae997e8` | PR comment HTTP 어댑터 | `integrations/github_pr_comment_adapter.py` | PR 코멘트 HTTP 경계 분리 |
| 4-C | `50e3e6b` | github_client deferred docs | `integrations/github_client.py` | legacy/deferred 상태 명시화 |
| 4-D | `83d6ebe` | Sonar 토큰 argv exposure 제거 | `analyzer/sonar_runner.py`, `analyzer/static_tool_command_runner.py` | `-Dsonar.token=...` argv 제거, env seam 도입 |
| 4-E | `67a2b79` | 공통 child env sanitizer | `analyzer/command_env.py` | allowlist + deny filter + extras |
| 4-F | `4d2f435` | Bandit child env sanitizer | `analyzer/bandit_runner.py` | Bandit 자식 env 살균 |
| 4-G | `aa92374` | Semgrep child env sanitizer | `analyzer/semgrep_runner.py` | Semgrep caller-specific allowlist |
| 4-H | `00792a6` | Dependency scanner child env sanitizer | `analyzer/dependency_command_runner.py`, `analyzer/dependency_scanner.py`, `analyzer/command_env.py` | pip-audit/npm caller-specific allowlist + AUTH deny 강화 |
| 4-I | `2217036` | Validator child env sanitizer | `validator/validator_command_runner.py`, `validator/syntax_checker.py`, `validator/test_runner.py` | flake8/sandbox pytest sanitized env + sandbox pytest caller-specific allowlist |

---

## 6. Wave 2 — API/라우터/서비스/경로 안정화

Wave 2 의 큰 그림은 “비대해진 `api/server.py` 와 부트스트랩 흐름을, 책임이 작은 라우터와 서비스 계층으로 나누고, 경로/부트스트랩의 부수효과를 통제 가능한 형태로 만든다” 는 것이다.

> 주의: Wave 2 의 일부 항목은 git log 와 변경 파일 목록을 근거로 정리한 것이며, 각 Wave 별 별도 rationale 문서가 모두 남아 있는 것은 아니다. 따라서 “이전 구조” 와 같은 항목은 commit 메시지/파일명에서 추론한 사실 위주로 보수적으로 기술한다.

### Wave 2-A — API 응답 DTO 레이어

- 머지 커밋: `6f99768`
- 주요 파일/영역:
  - `api/dto/__init__.py`
  - `api/dto/responses.py`
  - `api/server.py`
- 이 Wave 이전 구조: 응답 dict/모델이 `api/server.py` 안에서 ad-hoc 으로 구성되었다(commit 메시지/diff 기준 추론).
- 문제/위험: 응답 모양이 코드 변경 시 무심코 깨질 수 있고, 클라이언트(프론트) 와의 계약이 명문화되지 않았다.
- 변경: 명시적 응답 DTO 모듈을 신설하고 `response_model_exclude_unset` 적용 + 회귀 테스트 추가(`9bfcdf3`, `77b1ac7`, `6dfe1a9`).
- 클린 아키텍처 적합성: 인터페이스 어댑터 계층(HTTP) 의 출력 표현을 별도 모듈로 고정 → 내부 변경이 외부 계약을 깨뜨리지 못하게 한다.
- 보존된 동작: 기존 응답 필드 셰이프.
- 검증: API 응답 셰이프 계약 회귀 테스트(`tests/test_api_contract.py`).
- Rollback: `git revert -m 1 6f99768`.

### Wave 2-B — 대시보드 조회 라우터 분리

- 머지 커밋: `1a22d4c`
- 주요 파일/영역:
  - `api/result_sources.py`
  - `api/routers/__init__.py`
  - `api/routers/dashboard.py`
  - `api/server.py`
  - `tests/test_api_contract.py`
- 이전 구조: 조회 전용 엔드포인트가 `api/server.py` 안에 산재해 있었음(commit 메시지 기준 추론).
- 문제/위험: 단일 파일에 라우팅·도메인 로직·결과 소스 접근이 섞여 변경 영향 범위가 넓다.
- 변경: 조회 전용 라우터를 `routers/dashboard.py` 로 분리.
- 클린 아키텍처 적합성: HTTP 인터페이스 계층의 책임을 “조회”/“변경” 단위로 쪼갠다. read-only 엔드포인트가 한 군데에 모여 있으면 캐싱/권한/로깅 정책을 일괄 적용하기 쉽다.
- 보존된 동작: API 응답 모양과 경로.
- 검증: `tests/test_api_contract.py` 회귀.
- Rollback: `git revert -m 1 1a22d4c`.

### Wave 2-C — 빠른 스캔 라우터 + 도메인 분리

- 머지 커밋: `01a0543`
- 주요 파일/영역:
  - `analyzer/quick_scan.py`
  - `api/routers/dashboard.py`
  - `api/routers/quick_scan.py`
  - `api/server.py`
  - `tests/test_api_server.py`
- 이전 구조: quick scan 도메인 로직과 라우팅이 섞여 있었음(commit 메시지/diff 기준 추론).
- 문제/위험: 라우터가 도메인 알고리즘을 직접 알면 테스트 비용이 커진다.
- 변경: quick scan 도메인을 `analyzer/quick_scan.py` 로, 라우터를 `routers/quick_scan.py` 로 분리. 세션 상세 라우터 이동.
- 클린 아키텍처 적합성: 라우터(인터페이스 어댑터) 와 도메인(유스케이스) 의 책임 분리.
- 보존된 동작: quick scan 응답.
- 검증: `tests/test_api_server.py`.
- Rollback: `git revert -m 1 01a0543`.

### Wave 2-D — 리포트 라우터 분리

- 머지 커밋: `4e97659`
- 주요 파일/영역:
  - `api/routers/report.py`
  - `api/server.py`
  - `tests/test_api_report_router.py`
  - 보조: `2297c64 fix(reports): add missing reports/report_generator.py + import smoke test`
- 이전 구조: 리포트 엔드포인트가 `server.py` 에 직접 정의됨(commit 메시지 기준 추론).
- 문제/위험: 리포트 다운로드/조회 흐름이 섞여 있었다.
- 변경: 리포트 라우터 분리 + 누락된 `reports/report_generator.py` import smoke 테스트 보강.
- 클린 아키텍처 적합성: 기능 단위 모듈 분리.
- 보존된 동작: 리포트 엔드포인트.
- 검증: `tests/test_api_report_router.py`.
- Rollback: `git revert -m 1 4e97659`.

### Wave 2-E — 의존성 스캔 라우터 분리

- 머지 커밋: `f64a30f`
- 주요 파일/영역:
  - `api/result_sources.py`
  - `api/routers/dependencies.py`
  - `api/routers/report.py`
  - `api/server.py`
  - `tests/test_api_dependencies_router.py`
- 변경: 의존성 스캔 엔드포인트를 `routers/dependencies.py` 로 분리.
- 클린 아키텍처 적합성: 도메인별 라우터 분리.
- 검증: `tests/test_api_dependencies_router.py`.
- Rollback: `git revert -m 1 f64a30f`.

### Wave 2-F — 패치 적용 라우터 분리

- 머지 커밋: `5fe69e0`
- 주요 파일/영역:
  - `api/routers/patch.py`
  - `api/server.py`
  - `tests/test_api_apply_patch_router.py`
- 변경: 패치 적용 엔드포인트를 `routers/patch.py` 로 분리.
- 클린 아키텍처 적합성: 기능 단위 분리.
- Rollback: `git revert -m 1 5fe69e0`.

### Wave 2-G — 분석/잡 라우터 분리

- 머지 커밋: `d2ad34c`
- 주요 파일/영역:
  - `api/routers/analyze.py`
  - `api/server.py`
  - `tests/test_api_analyze_router.py`
  - `tests/test_api_contract.py`
- 변경: 분석/잡 엔드포인트를 `routers/analyze.py` 로 분리.
- 클린 아키텍처 적합성: 분석 흐름이 별도 라우터에 격리됨.
- Rollback: `git revert -m 1 d2ad34c`.

### Wave 2-H — 부트스트랩 settings 분리

- 머지 커밋: `adcab29`
- 주요 파일/영역:
  - `api/routers/patch.py`
  - `api/server.py`
  - `api/settings.py`
  - `tests/test_api_settings.py`
- 이전 구조: settings 가 `server.py` 부트스트랩 시점에 직접 구성됨(commit 메시지 기준 추론).
- 변경: settings 를 별도 모듈로 분리.
- 클린 아키텍처 적합성: 설정(infra) 과 라우팅(interface) 의 책임 분리.
- Rollback: `git revert -m 1 adcab29`.

### Wave 2-I — lifespan 부트스트랩 정리

- 머지 커밋: `6d3f911`
- 주요 파일/영역:
  - `api/server.py`
  - `tests/conftest.py`
  - `tests/test_api_lifespan.py`
- 이전 구조: startup 시점 부수효과가 모듈 import 시점에 발생.
- 문제/위험: 테스트 환경에서 의도치 않은 startup side effect 발생 가능.
- 변경: 부트스트랩 부수효과를 FastAPI lifespan 으로 이동.
- 클린 아키텍처 적합성: 구성/생명주기 책임을 lifespan hook 에 모음.
- 검증: `tests/test_api_lifespan.py`.
- Rollback: `git revert -m 1 6d3f911`.

### Wave 2-J — sys.path bootstrap hack 제거

- 머지 커밋: `39fedb9`
- 주요 파일/영역:
  - `api/celery_app.py`
  - `api/server.py`
  - `api/tasks.py`
  - `db/service.py`
  - `tests/test_api_server_syspath.py`
- 이전 구조: 모듈 import 시 `sys.path.insert(...)` 형태의 “부트스트랩 해킹” 이 존재.
- 문제/위험: import 부수효과가 테스트/배포에서 다른 동작을 일으킬 수 있다.
- 변경: sys.path 변조를 제거.
- 클린 아키텍처 적합성: 프레임워크 경계의 명시화. import 가 “읽기” 만 하도록 정리.
- 검증: `tests/test_api_server_syspath.py`.
- Rollback: `git revert -m 1 39fedb9`.

### Wave 2-K — Celery/Redis lazy 화

- 머지 커밋: `012dd17`
- 주요 파일/영역:
  - `api/routers/analyze.py`
  - `tests/test_api_analyze_lazy_celery.py`
- 이전 구조: analyze 라우터 import 시점에 Celery/Redis 의존이 끌려옴.
- 문제/위험: Celery/Redis 가 없는 환경에서도 import 만으로 실패하거나 부수효과가 발생.
- 변경: Celery 탐지/사용을 lazy import 화.
- 클린 아키텍처 적합성: 외부 인프라 의존이 “필요할 때만” 로딩됨.
- 검증: `tests/test_api_analyze_lazy_celery.py`.
- Rollback: `git revert -m 1 012dd17`.

### Wave 2-L — apply patch 서비스 분리

- 머지 커밋: `128c7cb`
- 주요 파일/영역:
  - `api/routers/patch.py`
  - `api/services/__init__.py`
  - `api/services/patch_application.py`
  - `tests/test_api_apply_patch_router.py`
  - `tests/test_api_patch_application_service.py`
- 변경: 패치 적용 도메인 로직을 `api/services/patch_application.py` 로 추출.
- 클린 아키텍처 적합성: 라우터(인터페이스) ↔ 서비스(유스케이스) 분리.
- Rollback: `git revert -m 1 128c7cb`.

### Wave 2-M — 대시보드 쿼리 서비스 분리

- 머지 커밋: `2677318`
- 주요 파일/영역:
  - `api/routers/dashboard.py`
  - `api/services/dashboard_queries.py`
  - `tests/test_api_dashboard_queries_service.py`
- 변경: 대시보드 조회 로직을 서비스 계층으로 추출.
- 클린 아키텍처 적합성: 라우터에서 ORM/쿼리 직접 의존을 빼낸다.
- Rollback: `git revert -m 1 2677318`.

### Wave 2-N — 의존성 스캐닝 서비스 분리

- 머지 커밋: `ed9795f`
- 주요 파일/영역:
  - `api/routers/dependencies.py`
  - `api/services/dependency_scanning.py`
  - `tests/test_api_dependencies_router.py`
  - `tests/test_api_dependency_scanning_service.py`
- 변경: 의존성 스캔 도메인 로직을 서비스로 추출.
- 클린 아키텍처 적합성: 인터페이스 ↔ 유스케이스 분리.
- Rollback: `git revert -m 1 ed9795f`.

### Wave 2-O — result_source 하드닝

- 머지 커밋: `33c7759`
- 주요 파일/영역:
  - `api/result_sources.py`
  - `tests/test_api_result_sources.py`
- 변경: 결과 소스 로딩의 입력 검증/예외 경계 강화.
- 클린 아키텍처 적합성: I/O 경계의 안전성 강화.
- Rollback: `git revert -m 1 33c7759`.

### Wave 2-P — analyze reports dir late-binding

- 머지 커밋: `448c0b0`
- 주요 파일/영역:
  - `api/routers/analyze.py`
  - `tests/test_api_analyze_router.py`
- 변경: reports 디렉터리 경로를 부트스트랩 시점이 아닌 호출 시점에 결정.
- 클린 아키텍처 적합성: 부트스트랩 의존도 감소, 테스트 격리 용이.
- Rollback: `git revert -m 1 448c0b0`.

### Wave 2-Q — 리포트 다운로드 경로 하드닝

- 머지 커밋: `5560d23`
- 주요 파일/영역:
  - `api/routers/report.py`
  - `tests/test_api_report_router.py`
- 변경: 리포트 다운로드 경로 검증 강화(경로 traversal 등).
- 클린 아키텍처 적합성: I/O 경계의 보안 강화.
- Rollback: `git revert -m 1 5560d23`.

### Wave 2-R — 리포트 생성 서비스 분리

- 머지 커밋: `c170bd8`
- 주요 파일/영역:
  - `api/routers/report.py`
  - `api/services/report_generation.py`
  - `tests/test_api_report_generation_service.py`
- 변경: 리포트 생성 로직을 서비스 계층으로 분리.
- 클린 아키텍처 적합성: 도메인 로직 격리.
- Rollback: `git revert -m 1 c170bd8`.

### Wave 2-S — 분석 파이프라인 서비스 분리

- 머지 커밋: `8d50caa`
- 주요 파일/영역:
  - `api/routers/analyze.py`
  - `api/services/analysis_pipeline.py`
  - `tests/test_api_analysis_pipeline_service.py`
- 변경: 분석 파이프라인 흐름을 `services/analysis_pipeline.py` 로 추출.
- 클린 아키텍처 적합성: 분석 유스케이스의 단일 진입점 형성.
- Rollback: `git revert -m 1 8d50caa`.

---

## 7. Wave 3 — analyzer/외부 의존 경계 추출

Wave 3 부터 본격적으로 “외부 세계와 만나는 경계”(subprocess, requests, 시계, 파일시스템) 를 어댑터로 분리하기 시작했다.

### Wave 3-A — Celery detector 서비스 + eval 제거

- 머지 커밋: `258a11d` (서비스 추출), `e0f1a1c` (eval cleanup)
- 주요 파일/영역:
  - `api/routers/analyze.py`
  - `api/services/celery_detector.py`
  - `tests/test_api_celery_detector_service.py`
  - `tests/test_api_analyze_lazy_celery.py`
- 이전 구조: Wave 2-K 의 lazy Celery 탐지에서 일부 테스트가 `eval` 기반으로 작성되어 있었다.
- 문제/위험: `eval` 은 보안/유지보수 모두에 위험하며, 도메인 탐지 로직이 라우터에 머물면 테스트 어렵다.
- 변경: Celery 탐지 로직을 별도 서비스로 추출, lazy celery 테스트의 `eval` 사용 제거(`a2c89b2`).
- 클린 아키텍처 적합성: 라우터 ↔ 서비스 분리 + eval 제거로 표현식 평가 경계 축소.
- Rollback: `git revert -m 1 258a11d` 와 `git revert -m 1 e0f1a1c`.

### Wave 3-B — safe_paths 헬퍼 중앙화

- 머지 커밋: `f91c5e8`
- 주요 파일/영역:
  - `api/routers/report.py`
  - `api/services/analysis_pipeline.py`
  - `api/services/patch_application.py`
  - `api/services/safe_paths.py`
  - `tests/test_api_safe_paths_service.py`
- 이전 구조: 경로 안전 검증 로직이 여러 모듈에 분산.
- 문제/위험: 경로 traversal 방어 누락 가능.
- 변경: 안전 경로 헬퍼를 `api/services/safe_paths.py` 단일 위치로 모음.
- 클린 아키텍처 적합성: 횡단 관심사(security) 의 단일 출처화(SSOT).
- Rollback: `git revert -m 1 f91c5e8`.

### Wave 3-C — 경로 settings 안정화

- 머지 커밋: `7f7e124`
- 주요 파일/영역:
  - `api/result_sources.py`
  - `api/settings.py`
  - `tests/test_api_result_sources.py`
  - `tests/test_api_settings.py`
- 변경: 경로 관련 설정의 단일 출처화 및 테스트 보강.
- Rollback: `git revert -m 1 7f7e124`.

### Wave 3-D — 분석 잡 스토어 분리

- 머지 커밋: `85051af`
- 주요 파일/영역:
  - `api/routers/analyze.py`
  - `api/services/analysis_jobs_store.py`
  - `tests/test_api_analysis_jobs_store_service.py`
  - `tests/test_api_analyze_router.py`
- 변경: 메모리상 분석 잡 스토어를 별도 서비스로 캡슐화.
- 클린 아키텍처 적합성: 상태 보관 책임을 서비스 객체로 격리(future-proof against persistence backends).
- Rollback: `git revert -m 1 85051af`.

### Wave 3-E — GitHub patch adapter 분리

- 머지 커밋: `d1c434e`
- 주요 파일/영역:
  - `api/services/github_patch_adapter.py`
  - `api/services/patch_application.py`
  - `tests/test_api_github_patch_adapter.py`
- 이전 구조: 패치 적용 흐름 중간에 GitHub HTTP 호출이 직접 섞여 있었음(commit 메시지 기준 추론).
- 문제/위험: 패치 도메인 로직이 외부 GitHub 호출과 결합되어 테스트가 실 네트워크에 의존할 위험.
- 변경: GitHub 호출 어댑터(`github_patch_adapter`) 분리, fake 가능한 seam 도입.
- 클린 아키텍처 적합성: 외부 인프라 의존성을 어댑터로 격리.
- Rollback: `git revert -m 1 d1c434e`.

### Wave 3-F — 의존성 스캔 command runner 어댑터

- 머지 커밋: `d310798`
- 주요 파일/영역:
  - `analyzer/dependency_command_runner.py`
  - `analyzer/dependency_scanner.py`
  - `tests/test_dependency_scanner_runner_adapter.py`
- 이전 구조: `dependency_scanner.py` 가 `pip-audit`/npm 관련 명령을 직접 호출.
- 문제/위험: 테스트 시 실 subprocess 가 돌고, shell 인젝션 통제가 분산.
- 변경: subprocess 호출을 `DependencyCommandRunner` 어댑터로 추출.
- 클린 아키텍처 적합성: 외부 명령 경계 단일화 + fake 가능.
- Rollback: `git revert -m 1 d310798`.

### Wave 3-G — Static tool command runner

- 머지 커밋: `3f67e3d`
- 주요 파일/영역:
  - `analyzer/bandit_runner.py`
  - `analyzer/semgrep_runner.py`
  - `analyzer/static_tool_command_runner.py`
  - `tests/test_bandit_runner.py`
  - `tests/test_static_tool_command_runner_adapter.py`
- 이전 구조: Bandit, Semgrep 이 각자 직접 `subprocess.run` 을 호출.
- 문제/위험: shell=True 통제, argv 검증, timeout 일관성을 서로 다른 위치에서 관리해야 했다.
- 변경: 두 도구 모두 `StaticToolCommandRunner` 어댑터를 통해 실행하도록 변경. shell=True 금지, list-argv 만 허용.
- 클린 아키텍처 적합성: 외부 명령 어댑터 단일화. 추후 env sanitizer (Wave 4-E ~ 4-G) 가 이 경계 위에 손쉽게 얹힐 수 있는 토대.
- Rollback: `git revert -m 1 3f67e3d`.

### Wave 3-H — Sonar scanner runner 추출

- 머지 커밋: `1096ef4`
- 주요 파일/영역:
  - `analyzer/sonar_runner.py`
  - `tests/test_sonar_runner_adapter.py`
- 변경: Sonar 스캐너 subprocess 호출을 별도 runner 로 추출.
- 클린 아키텍처 적합성: 외부 도구 호출 어댑터 분리. Wave 4-D 의 argv 토큰 제거가 가능해진 기반.
- Rollback: `git revert -m 1 1096ef4`.

### Wave 3-I — Sonar HTTP client 추출

- 머지 커밋: `14e3d35`
- 주요 파일/영역:
  - `analyzer/sonar_http_client.py`
  - `analyzer/sonar_runner.py`
  - `tests/test_sonar_http_client_adapter.py`
  - `tests/test_sonar_runner_adapter.py`
- 이전 구조: SonarRunner 가 직접 `requests.get` 으로 Sonar API 호출.
- 변경: HTTP 호출을 `SonarHttpClient` 로 분리, fake client 로 URL/params/auth/timeout 검증 가능.
- 클린 아키텍처 적합성: subprocess 와 HTTP 라는 두 외부 경계를 분리. SonarRunner 는 “언제 무엇을 호출할지” 만 결정한다.
- Rollback: `git revert -m 1 14e3d35`.

### Wave 3-J — Sonar polling clock/sleeper 분리

- 머지 커밋: `47a4e5b`
- 주요 파일/영역:
  - `analyzer/sonar_runner.py`
  - `tests/test_sonar_runner_adapter.py`
- 이전 구조: Sonar 분석 결과 polling 이 `time.time()`/`time.sleep()` 에 직접 의존.
- 문제/위험: 테스트가 실시간 sleep 으로 느려지거나 비결정적.
- 변경: clock/sleeper 를 주입 가능한 의존으로 추출.
- 클린 아키텍처 적합성: 시간(time) 도 외부 의존으로 보고 seam 화. 테스트는 fake clock 으로 즉시 진행.
- Rollback: `git revert -m 1 47a4e5b`.

---

## 8. Wave 4 — validator/통합/토큰/환경 변수 보안 강화

Wave 4 의 모든 단계에는 별도 rationale 문서가 존재한다(`/tmp/dallo-wave4{a..g}-clean-architecture-rationale.md`). 본 절은 각 rationale 의 핵심 사실만 옮긴다.

### Wave 4-A — Validator command runner

- 머지 커밋: `edd5070`
- 주요 파일/영역:
  - `validator/validator_command_runner.py`
  - `validator/syntax_checker.py`
  - `validator/test_runner.py`
  - `tests/test_validator_command_runner_adapter.py`
- 이전 구조: `SyntaxChecker` 가 `flake8` 을, `TestRunner` 가 sandbox 안의 `pytest` 를 직접 `subprocess.run` 으로 호출.
- 문제/위험: 도메인(검증 흐름) 과 인프라(외부 프로세스) 가 한 클래스에 섞여 있어 테스트가 실 도구를 호출할 위험. shell=True 통제도 분산.
- 변경: `ValidatorCommandRunner` 어댑터로 subprocess 호출 단일화. `SyntaxChecker`/`TestRunner` 는 runner 를 주입받도록 수정.
- 클린 아키텍처 적합성: “도메인은 외부 도구를 직접 알지 않는다, 어댑터에 가둔다” 는 ports/adapters 원칙의 직접 적용. 비유: 검증기는 선생님, CommandRunner 는 심부름꾼.
- 보존된 동작: flake8 argv `--select=E9,F63,F7,F82`, timeout 10s, FileNotFoundError 시 AST fallback, pytest argv/cwd, timeout 60s, “테스트 실행 시간 초과 (60초)” 한국어 메시지.
- 검증 근거: targeted 31 passed, full 586 passed, AST 검사로 `validator/syntax_checker.py`/`validator/test_runner.py` 에 `subprocess.run`/`shell=True` 잔존 0 (rationale 4-A).
- Rollback: `git revert -m 1 edd5070`.

### Wave 4-B — PR comment HTTP adapter

- 머지 커밋: `ae997e8`
- 주요 파일/영역:
  - `integrations/github_pr_comment_adapter.py`
  - `scripts/post_pr_comment.py`
  - `tests/test_github_pr_comment_adapter.py`
- 이전 구조: `scripts/post_pr_comment.py` 한 파일에 (1) 환경변수/리포트 파일 읽기, Markdown 포맷, stdout/exit 처리 와 (2) GitHub Issues comments API 의 GET/PATCH/POST 가 같이 있었다.
- 문제/위험: 테스트에서 실 GitHub 호출 위험, 실패 응답 본문(`resp.text`) 이 그대로 stdout 에 노출되면 토큰/HTML/프록시 메시지 등 예측 불가능한 내용이 섞일 수 있다.
- 변경: GitHub HTTP 호출을 `integrations/github_pr_comment_adapter.py` 로 추출. `requests` 는 lazy import. 실패 메시지에서 raw response body 제거(보안). 마커 “🔍 Dallo 보안 분석 결과” 가 있으면 PATCH, 없으면 POST 시퀀스 보존.
- 클린 아키텍처 적합성: 인프라(외부 서비스) 의존을 어댑터에 가두고, 스크립트는 흐름과 출력에 집중. 비유: 스크립트는 아나운서, 어댑터는 배달원.
- 보존된 동작: stdout 메시지 (`[+] 기존 PR 코멘트 업데이트 완료 (ID: …)`, `[+] PR 코멘트 생성 완료`, `[!] PR 코멘트 생성 실패: <status_code>`).
- 검증 근거: targeted 37 passed, related 48 passed, full 602 passed; AST 로 `scripts/post_pr_comment.py`/`integrations/github_pr_comment_adapter.py` 에 직접 `requests.*` 호출 0; fake adapter smoke `[GET, PATCH]` (rationale 4-B).
- Rollback: `git revert -m 1 ae997e8`.

### Wave 4-C — github_client deferred docs

- 머지 커밋: `50e3e6b`
- 주요 파일/영역:
  - `integrations/github_client.py` (docstring 만 변경)
  - `QUICKSTART.md`
  - `TEAM_GUIDE.md`
- 이전 구조: `integrations/github_client.py` 는 PR 메타데이터/라인 review/Check Run 등 미래 기능을 포함하지만, 현재 active caller 는 0 건.
- 문제/위험: “이미 활성 인프라처럼 보이는 dead-code 후보” 상태. 삭제하면 미래 기능 자산 상실, 리팩터하면 “리팩터를 위한 리팩터”.
- 변경: 모듈 docstring 과 문서에 “Wave 4-C 기준 active caller 없음. 운영 PR comment 는 `scripts/post_pr_comment.py → integrations/github_pr_comment_adapter.py` 경로. 활성화 전 fakeable HTTP seam, timeout, tests, token non-leak checks 필요. 신규 코드 직접 import 금지.” 라고 명시.
- 클린 아키텍처 적합성: 클린 아키텍처는 “모든 코드를 어댑터로 쪼개기” 가 아니라, “현재 활성 경계는 정리하고, 비활성 미래 surface 는 명시적 상태로 남긴다” 는 전략을 포함한다.
- 보존된 동작: 런타임 동작 변경 없음. 기능 변경이 아니라 상태/의도 명확화 wave.
- 검증 근거: targeted 58 passed, full 602 passed, external caller 0건 재확인 (rationale 4-C).
- Rollback: `git revert -m 1 50e3e6b`.

### Wave 4-D — Sonar token argv exposure 제거

- 머지 커밋: `83d6ebe`
- 구현 커밋: `9ec3362`, `422d6fd`
- 주요 파일/영역:
  - `analyzer/sonar_runner.py`
  - `analyzer/static_tool_command_runner.py`
  - `tests/test_sonar_runner_adapter.py`
- 이전 구조: `SonarRunner.run_scan()` 가 argv 에 `-Dsonar.token=<token>` 을 포함시켰다.
- 문제/위험: Linux/CI/Docker 호스트에서 process argv 는 `ps`, `/proc/<pid>/cmdline`, audit/eBPF, CI 로그를 통해 노출될 수 있다. 실질적 secret exposure 위험.
- 변경:
  - argv 에서 `-Dsonar.token` 제거. argv 에는 `sonar.projectKey`, `sonar.host.url`, `sonar.projectBaseDir` 만 남김.
  - `StaticToolCommandRunner.run()` 에 선택 키워드 인자 `env` 추가.
  - `SonarConfig.token` 이 비어 있지 않으면 자식 env 에 `SONAR_TOKEN` 을 설정, 비어 있으면 부모 환경의 ambient `SONAR_TOKEN` 까지 명시 제거.
- 클린 아키텍처 적합성: 외부 부수효과 경계는 `static_tool_command_runner` 에 그대로 두면서, secret 전달을 argv → env 로 옮기는 “보안 강화 + 어댑터 경계 보존”.
- 보존된 동작: 스캐너 명령 이름, 프로젝트 키, host URL, base dir, timeout, returncode mapping, FileNotFoundError 한국어 안내.
- 검증 근거: targeted 46 passed, related 94 passed, full 604 passed, security scan clean (rationale 4-D).
- Rollback: `git revert -m 1 83d6ebe`.

### Wave 4-E — 공통 child env sanitizer

- 머지 커밋: `67a2b79`
- 구현 커밋: `812f2c1`
- 주요 파일/영역:
  - `analyzer/command_env.py` (신설)
  - `analyzer/sonar_runner.py`
  - `tests/test_command_env_sanitizer.py`
  - `tests/test_sonar_runner_adapter.py`
- 이전 구조: Wave 4-D 가 SONAR_TOKEN 을 통제했지만, `SonarRunner.run_scan()` 은 여전히 `os.environ.copy()` 로 부모 env 를 거의 그대로 넘기고 있었다.
- 문제/위험: 부모 환경에 LLM API 키, GitHub 토큰, 클라우드 자격증명, NPM/PyPI 토큰, DATABASE_URL, 웹훅 URL 등이 있을 수 있고, 이들이 스캐너 자식 프로세스에 묵시적으로 흘러간다.
- 변경: `analyzer/command_env.py::build_child_env()` 헬퍼 도입.
  - 1차 게이트: 보수적 allowlist (PATH, HOME, locale, Python/JVM/Sonar 런타임, proxy, 최소 CI 마커).
  - 2차 게이트: secret-name deny filter.
  - 3차 게이트: `extras` 키워드 인자로 의도된 capability grant (예: `SONAR_TOKEN`).
  - 빈 extra 값은 무시.
- 클린 아키텍처 적합성: 환경 변수 구성도 인프라 경계로 보고, 정책을 단일 함수로 모음. defense-in-depth: allowlist + deny + capability.
- 보존된 동작: Sonar 스캐너 실행 결과 자체. (env 통제만 강화)
- 검증 근거: targeted 68 passed, broader 154 passed, full 626 passed, security scan clean (rationale 4-E).
- 명시적 비적용: Bandit/Semgrep/Dependency/Validator 는 이 단계에서 의도적으로 변경하지 않음 (호환성 평가 후 단계 적용).
- Rollback: `git revert -m 1 67a2b79`.

### Wave 4-F — Bandit child env sanitizer

- 머지 커밋: `4d2f435`
- 구현 커밋: `c6f57f5`
- 주요 파일/영역:
  - `analyzer/bandit_runner.py`
  - `tests/test_static_tool_command_runner_adapter.py`
  - `tests/test_bandit_runner.py`
- 이전 구조: `BanditRunner.run()` 이 `self._runner.run(cmd, timeout=120)` 형태로, `env` 인자 없이 호출되어 자식 프로세스가 부모 env 전체를 상속받았다.
- 문제/위험: AI/Vibe-Coding/CI 환경에서 부모 env 에는 흔히 LLM API 키, GitHub 토큰, 클라우드 자격증명, NPM/PyPI 토큰, DB URL 이 들어 있다.
- 변경: `self._runner.run(cmd, timeout=120, env=build_child_env())` 로 변경. Bandit 의 단순한 env 호환성은 기본 allowlist 로 충분.
- 클린 아키텍처 적합성: Wave 4-E 의 공유 boundary helper 를 재사용. 각 스캐너에서 ad-hoc `os.environ` 처리하지 않는다.
- 보존된 동작: Bandit argv shape, `-c` config 동작, timeout 120s, JSON 파싱, returncode 동작, 한국어 에러 메시지.
- 검증 근거: targeted 63 passed, broader 105 passed, full 631 passed, security scan clean (rationale 4-F).
- 명시적 비적용: Semgrep 은 이 단계에서 미적용 (TLS/proxy/캐시/private rules/`SEMGREP_APP_TOKEN` 정책 결정 필요).
- Rollback: `git revert -m 1 4d2f435`.

### Wave 4-G — Semgrep child env sanitizer

- 머지 커밋: `aa92374`
- 구현 커밋: `8b34fa9`
- 주요 파일/영역:
  - `analyzer/semgrep_runner.py`
  - `tests/test_static_tool_command_runner_adapter.py`
- 이전 구조: `SemgrepRunner` 는 `StaticToolCommandRunner` 를 통해 `semgrep` 을 실행했지만, 명시 `env` 인자 없이 호출 → 자식이 부모 env 전체 상속.
- 문제/위험: Semgrep 도 LLM API 키/토큰/자격증명 등 부모 비밀을 그대로 받아왔다.
- 변경: caller 경계에서 `env=build_child_env(allowlist=_SEMGREP_ENV_ALLOWLIST)` 적용.
  - Semgrep 전용 추가 allowlist: `SSL_CERT_FILE`, `SSL_CERT_DIR`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, `XDG_CACHE_HOME`, `XDG_CONFIG_HOME`, `SEMGREP_SETTINGS_FILE`, `SEMGREP_SEND_METRICS`, `SEMGREP_ENABLE_VERSION_CHECK`.
  - `SEMGREP_APP_TOKEN` 은 의도적으로 ambient 상속 미허용. 향후 Semgrep Cloud/private rules 가 필요해지면 별도 wave 로 explicit `extras` capability grant 패턴(예: `SemgrepRunner(app_token=...)` + `build_child_env(extras={"SEMGREP_APP_TOKEN": token})`) 으로 도입.
- 클린 아키텍처 적합성: caller-specific allowlist 를 도입함으로써, Sonar/Bandit 등 다른 도구의 child env 표면을 늘리지 않으면서 Semgrep 운영 호환성을 보장. `StaticToolCommandRunner` 는 그대로 단일 외부 명령 어댑터로 유지.
- 보존된 동작: argv `semgrep --config <config> --json --quiet <target>`, timeout 120s, JSON 파싱, `AnalysisResult` shape, 한국어 에러, output_path JSON 쓰기, default 생성자, fake runner 주입 seam, `semgrep_runner.py` 내 직접 `subprocess.run`/`shell=True` 없음.
- 검증 근거: targeted 109 passed, broader 77 passed, full 635 passed, fake Semgrep env smoke PASS, security scan clean, independent review APPROVED (rationale 4-G + continuity 4-G).
- Rollback: `git revert -m 1 aa92374`.

### Wave 4-H — Dependency scanner child env sanitizer

- 머지 커밋: `00792a6` (구현 커밋: `368b7e5 security(analyzer): Wave 4-H sanitize dependency scanner child env`)
- 주요 파일/영역:
  - `analyzer/dependency_command_runner.py`
  - `analyzer/dependency_scanner.py`
  - `analyzer/command_env.py`
  - `tests/test_dependency_scanner_runner_adapter.py`
  - `tests/test_command_env_sanitizer.py`
- 이전 구조: Wave 3-F 가 `DependencyScanner` 의 pip-audit / npm install / npm audit subprocess 호출을 `DependencyCommandRunner` 어댑터로 분리했지만, 어댑터는 `env` 키워드를 받지 않았고 호출자도 sanitized env 를 넘기지 않았다. 결과적으로 자식 프로세스가 부모 env 전체를 그대로 상속받았다.
- 문제/위험: AI/Vibe-Coding/CI 환경에서 부모 env 에는 `ANTHROPIC_API_KEY` / `GITHUB_TOKEN` / `NPM_TOKEN` / `PYPI_TOKEN` / `DATABASE_URL` 같은 비밀과, `PIP_INDEX_URL` / `PIP_EXTRA_INDEX_URL` / `PIP_TRUSTED_HOST` / `PIP_CONFIG_FILE` / `NPM_CONFIG_REGISTRY` / `NPM_CONFIG_USERCONFIG` / `NPM_CONFIG_HTTPS_PROXY` / `NPM_CONFIG_PROXY` / 소문자 `npm_config_*` / npm `_authToken` 류 사설 레지스트리·자격증명 변수가 흔히 들어 있다. 이들이 pip-audit / npm 자식 프로세스의 로그·캐시·원격 호출로 누출될 수 있었다.
- 결정 (정책): 사용자 read-only audit 후 **C. Hybrid / explicit capability** 안 채택. 운영에 필요한 안전 변수만 caller-specific allowlist 로 통과시키고, 사설 PyPI/npm 레지스트리 자격증명 변수는 ambient 상속을 허용하지 않는다. 사설 레지스트리 지원은 향후 별도 wave 의 명시적 capability grant 작업으로 분리한다.
- 변경:
  - `DependencyCommandRunner.run()` 에 선택 키워드 인자 `env: Optional[Mapping[str, str]] = None` 추가. `subprocess.run(..., env=env)` 로 그대로 전달. `env=None` (default) 면 기존 부모 env 상속 동작이 유지되어 미마이그레이션 caller 호환성을 보존.
  - `analyzer/dependency_scanner.py` 에 `_PIP_AUDIT_ENV_ALLOWLIST` 와 `_NPM_ENV_ALLOWLIST` caller-specific 상수 도입. 두 allowlist 모두 비-시크릿 운영 변수만 포함 (PIP_CACHE_DIR, PIP_DISABLE_PIP_VERSION_CHECK, PIP_NO_INPUT, PIP_CERT, PIP_CLIENT_CERT, NPM_CONFIG_CACHE, NPM_CONFIG_AUDIT_LEVEL, NPM_CONFIG_STRICT_SSL, NODE_EXTRA_CA_CERTS, SSL_CERT_FILE, SSL_CERT_DIR, REQUESTS_CA_BUNDLE, CURL_CA_BUNDLE, XDG_CACHE_HOME). `PIP_INDEX_URL`/`PIP_EXTRA_INDEX_URL`/`PIP_TRUSTED_HOST`/`PIP_CONFIG_FILE`/`NPM_CONFIG_REGISTRY`/`NPM_CONFIG_USERCONFIG`/`NPM_CONFIG_HTTPS_PROXY`/`NPM_CONFIG_PROXY`/소문자 `npm_config_*`/npm `_authToken` 류는 의도적으로 미포함.
  - `_scan_pip()` 가 `env=build_child_env(allowlist=_PIP_AUDIT_ENV_ALLOWLIST)` 로 호출. `scan_package_json_text()` 의 npm install 과 `_scan_npm()` 의 npm audit 모두 `env=build_child_env(allowlist=_NPM_ENV_ALLOWLIST)` 로 호출.
  - `analyzer/command_env.py::_DEFAULT_DENY_SUBSTRINGS` 에 `"AUTH"` 추가. npm `_authToken` / `_auth` / 사설 `*_AUTH` 처럼 `TOKEN`/`PASSWORD` 토큰을 포함하지 않는 auth-like 이름까지 한 번 더 거른다. 기본 allowlist 에는 `AUTH` 부분문자열을 포함한 키가 없어 false positive 위험이 낮음.
- 클린 아키텍처 적합성: Wave 4-E 의 공유 boundary helper(`build_child_env`)를 그대로 재사용하고, Wave 4-G 와 동일한 *caller-specific allowlist* 패턴을 적용. `DependencyCommandRunner` 는 외부 명령 어댑터라는 단일 책임을 유지하면서, Wave 4-D/E/F/G 와 동일한 env 키워드 seam 만 노출. 정책(어떤 변수를 통과시킬지)은 도메인 caller(`DependencyScanner`) 가 보유한다.
- 보존된 동작: pip-audit / npm install / npm audit 의 argv shape, cwd, timeout(120/60/120), JSON 파싱, fallback 분기, `pip-audit이 설치되어 있지 않습니다`/`pip-audit 미설치`/`pip-audit 출력 파싱 실패`/`pip-audit 시간 초과 (120초)`/`npm이 설치되어 있지 않습니다`/`npm audit 시간 초과 (120초)` 한국어 에러 메시지, fake runner 주입 seam, 인자 없는 생성자 동작.
- 검증 근거:
  - Targeted: `tests/test_dependency_scanner_runner_adapter.py` `tests/test_command_env_sanitizer.py` `tests/test_api_dependency_scanning_service.py` → 65 passed in 0.20s.
  - Broader: 위 + `tests/test_static_tool_command_runner_adapter.py` `tests/test_sonar_runner_adapter.py` → 142 passed in 0.30s.
  - Full: `pytest tests/ -q` → 645 passed, 5 warnings in 16.21s (기존 SQLAlchemy `datetime.datetime.utcnow()` deprecation + asyncio no-current-event-loop 경고로 본 wave 와 무관).
  - Post-merge 검증 (로컬 main, working tree clean): targeted 65 passed in 0.20s, broader 142 passed in 0.30s, full 645 passed, 5 warnings in 16.21s, fake dependency env smoke `main_dependency_fake_env_smoke PASS 3`, security scans clean.
  - 실 외부 도구 호출 0건 (pip-audit / npm / 네트워크 모두 fake runner 로 격리, parent env 는 `monkeypatch.setattr(os, "environ", ...)` 로 격리).
- 명시적 비적용: 사설 PyPI/npm 레지스트리 자격증명 변수의 ambient 상속은 의도적으로 허용하지 않음. 향후 사설 레지스트리 기능이 product requirement 가 되면 별도 wave 에서 `extras` capability grant 패턴으로 도입.
- Rollback: `git revert -m 1 00792a6` (구현 커밋만으로 되돌릴 경우 `git revert 368b7e5`).

### Wave 4-I — Validator child env sanitizer

- 머지 커밋: `2217036`
- 구현 커밋: `7fe88d8`
- 주요 파일/영역:
  - `validator/validator_command_runner.py`
  - `validator/syntax_checker.py`
  - `validator/test_runner.py`
  - `tests/test_validator_command_runner_adapter.py`
- 이전 구조: Wave 4-A 가 ``SyntaxChecker.check_with_flake8()`` 와 ``TestRunner._run_in_sandbox()`` 의 ``subprocess.run`` 호출을 ``ValidatorCommandRunner`` 어댑터로 분리했지만, 어댑터는 ``env`` 키워드를 받지 않았고 호출자도 sanitized env 를 넘기지 않았다. 결과적으로 flake8 / sandbox pytest 자식 프로세스가 부모 env 전체(LLM API 키, GitHub 토큰, 클라우드 자격증명, NPM/PyPI 토큰, ``DALLO_ENCRYPTION_KEY``, ``DALLO_API_KEYS`` 포함)를 그대로 상속받았다.
- 문제/위험: AI/Vibe-Coding 환경에서 부모 셸/CI 에는 흔히 ``ANTHROPIC_API_KEY`` / ``GITHUB_TOKEN`` / ``AWS_SECRET_ACCESS_KEY`` / ``NPM_TOKEN`` / ``PYPI_TOKEN`` / ``DATABASE_URL`` 등 시크릿이 export 되어 있으며, Dallo 자체의 애플리케이션 시크릿 (``DALLO_ENCRYPTION_KEY``, ``DALLO_API_KEYS``) 도 부모 env 에 들어 있다. flake8 자체는 외부 네트워크를 호출하지 않지만, sandbox pytest 가 LLM 이 생성한 임의 코드를 실행한다는 점에서 위험이 가장 크다 — LLM 코드가 ``os.environ`` 을 들여다보거나 외부 호출에 사용하면 시크릿이 sandbox 로 누출되거나 임시 디렉토리 로그/네트워크 경로로 흘러나갈 수 있다.
- 변경:
  - ``ValidatorCommandRunner.run()`` 에 선택 키워드 인자 ``env: Optional[Mapping[str, str]] = None`` 추가. ``subprocess.run(..., env=env)`` 로 그대로 전달. ``env=None`` (default) 면 기존 부모 env 상속 동작이 유지되어 미마이그레이션 caller 호환성을 보존.
  - ``validator/syntax_checker.py`` 의 ``check_with_flake8()`` 가 ``env=build_child_env()`` 로 호출. flake8 은 추가 운영 변수 없이 기본 allowlist 만으로 동작 가능하므로 caller-specific allowlist 를 도입하지 않는다.
  - ``validator/test_runner.py`` 에 ``_VALIDATOR_PYTEST_ENV_ALLOWLIST`` caller-specific 상수 도입. 비-시크릿 운영 변수만 포함 (``PYTEST_ADDOPTS``, ``PYTEST_DISABLE_PLUGIN_AUTOLOAD``, ``PYTEST_VERSION``, ``PY_COLORS``, ``FORCE_COLOR``, ``NO_COLOR``, ``SSL_CERT_FILE``, ``SSL_CERT_DIR``, ``REQUESTS_CA_BUNDLE``, ``CURL_CA_BUNDLE``, ``XDG_CACHE_HOME``, ``XDG_CONFIG_HOME``, ``COVERAGE_FILE``, ``COVERAGE_RCFILE``, ``COVERAGE_PROCESS_START``). ``_run_in_sandbox()`` 가 ``env=build_child_env(allowlist=_VALIDATOR_PYTEST_ENV_ALLOWLIST)`` 로 호출.
  - ``DALLO_ENCRYPTION_KEY`` / ``DALLO_API_KEYS`` 는 어떤 allowlist 에도 포함하지 않으며, ``extras`` capability grant 로도 자식에 주입하지 않는다. Wave 4-H 에서 보강한 ``AUTH`` substring deny + 기본 ``KEY`` substring deny 가 한 번 더 차단한다.
- 클린 아키텍처 적합성: Wave 4-E 의 공유 boundary helper(``build_child_env``)를 그대로 재사용하고, Wave 4-G/4-H 와 동일한 *caller-specific allowlist* 패턴을 적용. ``ValidatorCommandRunner`` 는 외부 명령 어댑터라는 단일 책임을 유지하면서, Wave 4-D/E/F/G/H 와 동일한 env 키워드 seam 만 노출. 정책(어떤 변수를 통과시킬지)은 도메인 caller(``SyntaxChecker``/``TestRunner``) 가 보유한다.
- 보존된 동작: flake8 argv ``["flake8", "--select=E9,F63,F7,F82", tmp_path]`` / timeout 10 / cwd None / ``FileNotFoundError`` AST fallback / 임시 파일 cleanup / ``CheckResult`` shape, sandbox pytest argv ``[sys.executable, "-m", "pytest", test_path, "-v", "--tb=short"]`` / cwd=tmp_dir / timeout 60 / 프로젝트 복사 동작 / "테스트 파일 없음" ``passed=None`` / ``TimeoutExpired`` 한국어 메시지 (``"테스트 실행 시간 초과 (60초)"``) / ``TestResult`` shape, fake runner 주입 seam, 인자 없는 생성자 동작.
- 검증 근거:
  - RED: targeted 8 failed (validator runner ``env`` kwarg 미수용 + flake8/pytest sanitized env 미주입 → 모두 `NoneType` / TypeError) + 26 passed in 0.22s.
  - Targeted (구현 후): `tests/test_validator_command_runner_adapter.py` `tests/test_command_env_sanitizer.py` → 55 passed in 0.12s.
  - Full: `pytest tests/ -q` → 654 passed, 5 warnings in 17.27s (기존 SQLAlchemy `datetime.datetime.utcnow()` deprecation + asyncio no-current-event-loop 경고로 본 wave 와 무관).
  - 실 외부 도구 호출 0건 (flake8 / pytest sandbox 모두 fake runner 로 격리, parent env 는 ``monkeypatch.setattr(os, "environ", ...)`` 로 격리).
  - Security scans: secret-like 패턴 / `os.system|shell=True` / `eval|exec` / `pickle.loads?` 모두 clean (placeholder 토큰 값은 짧은 더미 ``"x"`` 만 사용).
- 명시적 비적용: sandbox pytest 환경에서 LLM 코드가 사용할 수 있는 추가 capability (DB 접근, 외부 API 호출) 는 의도적으로 부여하지 않는다. 향후 사용자 코드가 명시적으로 그 capability 를 요구한다면 별도 wave 에서 ``extras`` capability grant 패턴으로 도입.
- Rollback: `git revert -m 1 2217036` (구현 커밋만으로 되돌릴 경우 `git revert 7fe88d8`).
- 초보자용 설명: "flake8 는 코드 스타일을 보는 도구라 시크릿이 안 새겠지만, sandbox pytest 는 LLM 이 만든 새 코드를 실행한다. 부모 셸의 ``ANTHROPIC_API_KEY`` 같은 비밀이 그 자식 프로세스 ``os.environ`` 에 그대로 보이면, LLM 코드가 의도치 않게 (또는 prompt-injection 으로) 그 값을 읽어 외부로 보낼 수 있다. Wave 4-I 는 자식에게 진짜로 필요한 변수(PATH, HOME, LANG, VIRTUAL_ENV, pytest 운영 변수 등)만 통과시키고 나머지(특히 ``DALLO_ENCRYPTION_KEY``)는 모두 차단한다."

---

## 9. 보안 강화 관점 요약

이 절은 Wave 2-S → Wave 4-I 을 보안 관점으로 다시 본다.

### 9.1 무엇이 줄어들었나

- **secret 누출 경로 감소**
  - argv exposure: Sonar 토큰이 `-Dsonar.token=...` 로 argv 에 들어가던 위험 제거(Wave 4-D).
  - ambient env leakage: 부모 env 의 secret-like 변수가 자식 도구로 묵시 상속되던 위험 제거(Wave 4-E ~ 4-I). Wave 4-H 는 pip-audit/npm 의 사설 레지스트리·자격증명 변수까지 ambient 상속을 차단하고 `AUTH` substring 기반 deny 보강을 추가했고, Wave 4-I 는 validator 의 flake8 와 sandbox pytest 자식 프로세스까지 같은 sanitizer 를 적용해 LLM 이 생성한 코드가 부모 env 의 ``ANTHROPIC_API_KEY`` / ``GITHUB_TOKEN`` / ``DALLO_ENCRYPTION_KEY`` / ``DALLO_API_KEYS`` 같은 시크릿에 닿지 못하게 했다.
- **외부 명령 보안 통제 일원화**
  - `subprocess.run` 호출이 어댑터(`StaticToolCommandRunner`, `DependencyCommandRunner`, `ValidatorCommandRunner`) 에 모임.
  - shell=True 금지, list-argv 강제, timeout 명시.
- **외부 HTTP 보안 통제 일원화**
  - Sonar HTTP 는 `SonarHttpClient` (Wave 3-I) 로, GitHub PR 코멘트는 `github_pr_comment_adapter.py` (Wave 4-B) 로 분리.
  - 실패 응답 본문(`resp.text`) 의 무차별 stdout 노출 방지(Wave 4-B).
- **경로 안전성**
  - `safe_paths.py` (Wave 3-B) 와 리포트 다운로드 경로 하드닝(Wave 2-Q) 으로 traversal 위험 감소.

### 9.2 왜 argv/env 강화가 중요한가

- argv 는 OS 수준에서 다른 프로세스가 쉽게 들여다볼 수 있는 “공개 정보” 에 가깝다. 토큰을 argv 에 넣으면 그 자체가 누출이다.
- env 는 자식 프로세스가 묵시적으로 상속한다. AI/Vibe-Coding 환경에서 부모 셸/CI/컨테이너가 가진 비밀이 자식 외부 도구에 자동으로 전달되면, “Dallo 코드는 비밀을 다루지 않았는데도 Dallo 가 실행한 외부 도구의 메모리/로그/네트워크 호출에 비밀이 노출” 되는 상황이 가능하다.
- 명시적 capability grant 는 이 두 채널 모두를 통제하는 일관된 모델이다.

### 9.3 fake seam 이 줄여 주는 외부 호출

- 모든 외부 명령/HTTP 어댑터는 fake 로 교체 가능하다.
- 따라서 테스트 실행은 실제 Bandit/Semgrep/Sonar/pip-audit/npm/flake8/sandbox pytest/GitHub API 를 호출하지 않는다.
- 이 구조 덕분에 “테스트가 비밀을 흘리거나 외부에 부수효과를 일으킬 가능성” 자체가 거의 0 이 된다.

### 9.4 GitHub push 를 미루고 있는 이유 (의도된 비행동)

- 모든 Wave 의 검증/문서/테스트 정책은 “local main 에만 머지하고, push 는 사용자 명시 승인 시에만 수행” 으로 운영되었다.
- 이는 다음 이유에서 의도적이다.
  - PR/외부 가시 행위는 되돌리기 어렵다.
  - 보안 강화 wave 는 외부에 알릴 시점이 별도 결정 사안이다.
  - 사용자가 직접 push/PR 시점을 통제하도록 둔다.
- 현재 상태에서도 모든 Wave 는 local revert 한 번으로 되돌릴 수 있다.

---

## 10. 현재 상태 (Wave 4-I 시점)

- 로컬 `main` 에 Wave 4-I 머지 커밋 `2217036` 이 포함되어 있다 (구현 커밋 `7fe88d8`).
  - Wave 4-H 머지 커밋 `00792a6` 위에 Wave 4-I 가 단일 커밋으로 추가되었다 (push/PR/deploy 미수행 정책 유지).
- 본 head 는 **로컬에만 존재**하며 원격으로 push 되지 않았고, PR/deploy 도 수행되지 않았다.
- 마지막 검증된 전체 테스트 결과 (Wave 4-I 시점): `654 passed, 5 warnings in 17.27s` (targeted 55 passed in 0.12s 동반).
  - 5 warnings 는 SQLAlchemy `datetime.datetime.utcnow()` 와 asyncio no-current-event-loop 관련 기존 deprecation warnings 로, 이번 리팩터링과 무관하다.
- 보안 스캔(추가 라인 secret-like / dangerous patterns / 운영 영역) 모두 clean.
- 다음 권장 작업 후보:
  - 사설 PyPI/npm 레지스트리 capability grant wave (필요해질 때): pip 의 `PIP_INDEX_URL`/`PIP_EXTRA_INDEX_URL` 와 npm 의 `NPM_CONFIG_REGISTRY` + `_authToken` 을 명시적 `DependencyScanner` 생성자 인자 + `build_child_env(extras=...)` 패턴으로 도입.
  - Sandbox pytest 격리 강화: 별도 user 또는 chroot 등 OS 수준 격리 검토 (현재는 환경 변수 통제만 강화).

---

## 11. 이 문서를 나중에 다시 읽는 법

1. 어떤 머지 커밋이 “지금 이 동작” 의 출처인지 알고 싶다면 → §5 의 타임라인 표에서 머지 커밋 SHA 를 찾아 `git show --stat <sha>` 로 변경 파일을 본다.
2. “왜 이 어댑터가 여기 있나?” 가 궁금하다면 → §6/§7/§8 의 해당 Wave 절을 읽고, 필요한 경우 `/tmp/dallo-wave4*-clean-architecture-rationale.md` 의 원본 rationale 을 확인한다.
3. “어떤 보안 속성이 보장되는가?” 가 궁금하다면 → §9 를 읽는다.
4. 새 모듈에 같은 패턴을 적용하고 싶다면 → §3 의 원칙 + §4 의 용어집 + 가장 가까운 Wave (예: Bandit 비슷한 도구라면 Wave 4-F, HTTP 호출이라면 Wave 4-B/3-I) 의 절을 템플릿으로 사용한다.
5. 어떤 Wave 가 문제를 일으켰다고 의심된다면 → 해당 Wave 절의 “Rollback” 절에서 `git revert -m 1 <merge>` 를 그대로 사용한다.

---

## 12. 비밀(secret) 비포함 명시

본 문서는 다음을 포함하지 않는다.

- 실제 토큰/비밀 값.
- 운영 자격증명.
- 사설 레지스트리 자격증명.

본 문서가 언급하는 것은 **환경 변수 이름**(예: `SONAR_TOKEN`, `SEMGREP_APP_TOKEN`, `PIP_INDEX_URL`, `NPM_CONFIG_REGISTRY`) 뿐이다.
이 이름들은 secret 자체가 아니며, 어떤 변수가 “secret 가능성이 있는 capability” 로 취급되어야 하는지를 설명하는 데 사용된다.

---

*문서 버전: Wave 4-I 시점 (2026-05-06).*
