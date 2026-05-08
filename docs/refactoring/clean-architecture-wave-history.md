# Dallo 클린 아키텍처 리팩터링 Wave 이력

> 본 문서는 Dallo DevSecOps 프로젝트가 **Wave 2-A 부터 Wave 4-O 까지** 어떤 순서와 이유로 구조를 정리해 왔는지를 기록한다.
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
| **Wave 4 (A~O, 15 wave)** | validator·통합·토큰·환경 변수 보안 강화 + 공유 boundary 중립화 + sandbox 경로 하드닝 + security checker seam + agent LLM retry sleeper seam + analyzer 파일 I/O seam + validator 파일 쓰기 seam | argv exposure 제거, child env sanitizer 도입, GitHub PR 코멘트 어댑터 분리, deferred legacy 표시, dependency scanner env sanitizer, validator child env sanitizer, ``command_env`` boundary 중립화 (analyzer → shared), validator sandbox 경로/심볼릭 링크 하드닝, ``SecurityChecker`` Bandit/Semgrep DI seam, ``DalloAgent`` LLM retry sleeper DI seam, ``BanditRunner``/``SemgrepRunner`` 파일 I/O 어댑터, ``TestRunner``/``SecurityChecker``/``SyntaxChecker`` 파일 쓰기 어댑터 | 비밀(secret) 누출 가능 경로를 명시적 capability grant 모델로 재설계 + 공유 sanitizer 의 의존 방향 정정 + LLM 코드 격리 환경 강화 + 보안 재검증기 fakeable 화 + LLM retry 시계 경계 fakeable 화 + analyzer/validator 파일 시스템 경계 fakeable 화 |

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
| 4-J | `4a77782` | command_env boundary 중립화 | `shared/command_env.py`, `analyzer/command_env.py` (shim), `validator/syntax_checker.py`, `validator/test_runner.py`, `analyzer/{bandit,semgrep,sonar,dependency_scanner}_runner.py` | analyzer→shared 이동 + analyzer 측 호환성 shim, validator 의 analyzer 의존 제거 |
| 4-K | `515a9d1` | Validator sandbox 경로/심볼릭 링크/cleanup 하드닝 | `validator/test_runner.py`, `tests/test_validator_sandbox_hardening.py` | sandbox 경로 traversal 차단 + symlink 정책 명시 + finally cleanup |
| 4-L | `875c3ac` | Security checker 스캐너 seam (Bandit/Semgrep DI) | `validator/security_checker.py`, `tests/test_security_checker.py` | ``SecurityChecker`` DI seam + lazy default factory + 23 신규 회귀 테스트 |
| 4-M | `b842b21` | LLM agent retry sleeper seam | `agent/llm_agent.py`, `tests/test_llm_agent_sleeper_adapter.py` | retry-loop ``time.sleep`` 경계를 DI 로 fakeable 화하고 운영 기본값(``time.sleep``) 보존 |
| 4-N | `660c810` | Bandit/Semgrep 파일 I/O seam | `analyzer/file_io.py`, `analyzer/bandit_runner.py`, `analyzer/semgrep_runner.py`, `tests/test_bandit_file_io_seam.py`, `tests/test_semgrep_file_io_seam.py` | 결과 JSON 쓰기 + Semgrep snippet 원본 라인 읽기 경계를 ``FileIO`` 어댑터로 위임, keyword-only DI |
| 4-O | (TBD — 머지 전) | Validator 파일 쓰기 seam | `validator/file_io.py`, `validator/test_runner.py`, `validator/security_checker.py`, `validator/syntax_checker.py`, `tests/test_validator_file_io_seam.py` | sandbox 타깃 / 보안 재검증 임시 / flake8 임시 ``.py`` 쓰기 경계를 validator-local ``FileIO`` 어댑터로 위임, keyword-only DI |

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

### Wave 4-J — command_env 경계 중립화 (analyzer → shared)

- 머지 커밋: `4a77782`
- 구현 커밋: `cdd1399`
- 주요 파일/영역:
  - `shared/command_env.py` (신규 — Wave 4-E 구현 이전)
  - `analyzer/command_env.py` (호환성 shim 으로 축소)
  - `validator/syntax_checker.py`, `validator/test_runner.py` (analyzer→shared import 경로 정정)
  - `analyzer/bandit_runner.py`, `analyzer/semgrep_runner.py`, `analyzer/sonar_runner.py`, `analyzer/dependency_scanner.py` (shared 경로로 import 통일)
  - `tests/test_command_env_neutral_boundary.py` (신규 회귀 테스트)
  - `tests/test_command_env_sanitizer.py` (import 경로 정정)
- 이전 구조: Wave 4-E 가 도입한 ``build_child_env`` 는 분석기/검증기/통합 어디서나 동일하게 필요한 *공유 경계 헬퍼* 임에도, 구현이 ``analyzer/command_env.py`` 에 위치해 있어 Wave 4-I 시점의 ``validator/syntax_checker.py`` 와 ``validator/test_runner.py`` 가 ``from analyzer.command_env import build_child_env`` 로 analyzer 패키지를 import 해야 했다. 즉 **검증 계층이 분석 계층의 모듈을 참조** 하는 의존 방향이 발생했다.
- 문제/위험: 클린 아키텍처 관점에서, validator (검증 도메인) 가 analyzer (분석 도메인) 에 의존하는 것은 두 도메인의 결합을 강화하고 향후 어느 한쪽만 다시 패키징할 때 import 경로를 강제로 끌고 다니게 한다. 또한 보안 관점에서, 시크릿 차단이라는 횡단 관심사가 한 응용 패키지(``analyzer/``)에 묶여 있으면 “이 sanitizer 는 analyzer 전용” 으로 오해될 위험이 있다 (실제로 4-I 가 그 오해를 깨면서 의존 방향만 비뚤어진 채 확장된 형태였다).
- 변경:
  - ``shared/command_env.py`` 를 신규 생성 — Wave 4-I 까지의 ``analyzer/command_env.py`` 구현(allowlist/deny/extras/시그니처) 을 그대로 옮긴다. 정책/상수/시그니처는 한 글자도 바꾸지 않는다 (동작 보존). 모듈 docstring 만 “analyzer 전용” → “shared 중립 boundary” 표현으로 갱신한다.
  - ``analyzer/command_env.py`` 는 ``from shared.command_env import build_child_env`` 한 줄 + ``__all__`` 만 갖는 호환성 shim 으로 축소한다. 외부/legacy caller 가 여전히 ``from analyzer.command_env import build_child_env`` 로 동작하도록 유지한다.
  - validator 의 두 caller (``validator/syntax_checker.py``, ``validator/test_runner.py``) 와, 일관성을 위해 analyzer 의 caller 4 개 (``bandit_runner.py``, ``semgrep_runner.py``, ``sonar_runner.py``, ``dependency_scanner.py``) 의 import 를 ``shared.command_env`` 로 통일한다.
  - 회귀 테스트 ``tests/test_command_env_neutral_boundary.py`` 추가: shared 경로 import 동작, shim identity (``analyzer.command_env.build_child_env is shared.command_env.build_child_env``), validator 소스에 analyzer 경로 import 부재, ``shared/command_env.py`` 가 analyzer/validator 를 import 하지 않음, 그리고 secret-deny / extras capability grant 동작이 shared 경로에서도 보존됨을 검증.
- 클린 아키텍처 적합성: 횡단 관심사인 “자식 env sanitizer” 를 ``shared/`` 로 끌어올려, analyzer/validator/integrations 가 동등한 의존 방향(*안쪽으로*) 으로 참조하게 한다. validator 가 analyzer 를 참조하던 비뚤어진 의존을 제거하고, 새 도메인이 같은 sanitizer 를 쓰고 싶을 때 analyzer 를 끌어들이지 않아도 되도록 만든다.
- 보존된 동작:
  - ``build_child_env`` 의 함수 시그니처, 키워드 인자(``extras`` / ``base_env`` / ``allowlist`` / ``deny_name_patterns``), 기본 allowlist (PATH, HOME, USER, LOGNAME, SHELL, TERM, TMPDIR, TEMP, TMP, LANG, LANGUAGE, LC_ALL, TZ, VIRTUAL_ENV, PYENV_ROOT, PYENV_VERSION, PYTHONPATH, PYTHONUTF8, PYTHONDONTWRITEBYTECODE, PYTHONIOENCODING, JAVA_HOME, JAVA_OPTS, SONAR_SCANNER_OPTS, SONAR_USER_HOME, HTTP/HTTPS/NO/ALL_PROXY 대·소문자 8 개, CI, GITHUB_ACTIONS), ``LC_`` prefix, deny substring (TOKEN/SECRET/PASSWORD/PASS/CREDENTIAL/API_KEY/APIKEY/KEY/AUTH), deny exact (``ANTHROPIC_API_KEY`` ~ ``SONAR_TOKEN`` 의 21 개) 모두 동일.
  - extras 빈 문자열 무시, extras 가 base 의 동명 변수를 덮어쓰는 마지막 단계 적용, ``GITHUB_TOKEN`` 의 ambient 차단 정책 동일.
  - Wave 4-D ~ Wave 4-I 가 도입한 caller-specific allowlist (Bandit/Semgrep/dependency_scanner/validator pytest) 는 caller 측에 그대로 남아 있으며, sanitizer 가 함수 객체로 동일하므로 결과 dict 도 동일.
  - ``analyzer.command_env.build_child_env`` 호출은 shim 을 통해 동일 함수 객체로 redirect 되어 caller 호환성을 100% 유지.
- 검증 근거:
  - RED: ``tests/test_command_env_neutral_boundary.py`` 의 7 개 신규 테스트 모두 fail (``shared.command_env`` 미존재 + validator 소스에 analyzer import 잔존), ``test_command_env_sanitizer.py`` 21 passed.
  - GREEN targeted: ``tests/test_command_env_neutral_boundary.py`` ``tests/test_command_env_sanitizer.py`` ``tests/test_static_tool_command_runner_adapter.py`` ``tests/test_sonar_runner_adapter.py`` ``tests/test_dependency_scanner_runner_adapter.py`` ``tests/test_validator_command_runner_adapter.py`` → **183 passed in 0.39s**.
  - GREEN full: 전체 테스트 스위트 **661 passed, 5 warnings in 16.15s**. 5 warnings 는 Wave 4-J 와 무관한 기존 deprecation warning 으로, 본 wave 의 blocker 가 아니다.
  - Import smoke: ``shared.command_env.build_child_env`` 와 ``analyzer.command_env.build_child_env`` 가 동일 함수 객체로 redirect 됨을 확인 — ``WAVE4J_IMPORT_SMOKE_PASS shared_and_shim_identity_preserved``.
  - 운영 import 방향 검사: validator 소스에 ``from analyzer.command_env`` import 잔존 0건, ``shared/command_env.py`` 가 ``analyzer`` / ``validator`` 패키지를 import 하지 않음 — shared 레이어/의존 방향 모두 clean.
  - 추가 라인 보안 스캔: 본 wave 의 추가/변경 라인에 대한 secret-like 및 dangerous pattern 스캔 clean.
  - AST 운영 코드 dangerous 스캔: production 영역 AST 기반 dangerous pattern 스캔 clean.
  - 실 외부 도구 호출 0건. 본 wave 는 내부 import 경로 + 신규 모듈 파일 추가만 다루며, subprocess/HTTP/파일 어댑터의 동작 면은 건드리지 않는다.
- 명시적 비적용 (Wave 4-K 는 본 wave 에서 구현하지 않는다):
  - sandbox 경로/심볼릭 링크/cleanup 하드닝 (Wave 4-K 후보) 은 의도적으로 다루지 않는다. 본 wave 는 import boundary 정정 한 가지 책임만 옮긴다.
  - 신규 caller-specific allowlist 추가/삭제, deny substring 변경, extras 동작 변경, validator/analyzer 의 어댑터 시그니처 변경, ``shared/schemas.py`` 변경 모두 비적용.
- Rollback: `git revert -m 1 4a77782` (구현 커밋만 되돌릴 경우 `git revert cdd1399`). 되돌려도 호환성 shim 패턴이 사라지는 것뿐, validator 가 다시 analyzer 를 import 하는 4-I 시점 동작으로 복귀한다.
- 초보자용 설명: "Wave 4-E 가 만든 자식 env sanitizer 는 analyzer 전용이 아니라 *모두가 쓰는 보안 헬퍼* 다. 그런데 파일이 analyzer 폴더에 있다 보니, validator 가 그 함수를 쓰려고 analyzer 를 import 해야 했다. Wave 4-J 는 그 헬퍼를 ``shared/`` 로 옮기고, 옛 위치는 ‘이 함수는 사실 shared 에 있어요’ 라고 가리키는 빈 껍데기(shim) 만 남겼다. 동작은 한 글자도 바뀌지 않았다."

### Wave 4-K — Validator sandbox 경로/심볼릭 링크/cleanup 하드닝

- 머지 커밋: 515a9d1 merge: integrate Wave 4-K validator sandbox hardening
- 구현 커밋: 7bf8781 refactor(validator): Wave 4-K harden sandbox paths
- 주요 파일/영역:
  - `validator/test_runner.py`
  - `tests/test_validator_sandbox_hardening.py` (신규 회귀 테스트)
- 이전 구조: Wave 4-A 가 ``TestRunner._run_in_sandbox()`` 의 ``subprocess.run`` 호출을 ``ValidatorCommandRunner`` 어댑터로 분리했고, Wave 4-I 가 sandbox pytest 자식 프로세스에 sanitized child env 만 전달하도록 했다. 그러나 sandbox 디렉토리 자체의 *경로/파일 안전성* 은 별도로 보강하지 않은 상태였다. ``original_file_path`` 는 호출자가 넘기는 임의의 문자열이고, ``_run_in_sandbox()`` 는 ``os.path.join(tmp_dir, original_file_path)`` 후 ``os.path.exists(...)`` 만 체크한 뒤 그대로 ``open(..., "w")`` 로 ``fixed_code`` 를 기록했다. 또한 프로젝트 복사는 ``shutil.copytree(src, dst, ignore=shutil.ignore_patterns(...))`` 만 사용했고 ``symlinks`` / ``ignore_dangling_symlinks`` 인자가 명시되지 않았다.
- 문제/위험:
  - **경로 traversal**: ``original_file_path = "../outside.py"`` 또는 절대 경로 (``"/etc/passwd"`` 등) 가 들어오면 ``os.path.join(tmp_dir, ...)`` 가 sandbox 바깥 경로를 만들고, 해당 외부 파일이 존재하면 ``fixed_code`` 로 그대로 덮어써질 수 있었다. ``"safe/../../outside.py"`` 같은 중첩 traversal 도 동일하게 sandbox 바깥을 가리킬 수 있었다.
  - **심볼릭 링크 leakage**: ``shutil.copytree`` 의 ``symlinks=False`` 기본 동작은 link 를 *따라가* 대상 내용을 일반 파일로 복사한다. 즉 프로젝트 root 또는 서브 디렉토리에 외부 파일을 가리키는 symlink 가 있으면 그 외부 파일의 내용이 sandbox 안에 일반 파일로 복사되어, LLM 이 생성해 sandbox 에서 실행되는 코드가 그 내용을 읽을 수 있었다.
  - **dangling symlink**: 대상이 없는 symlink 가 서브 디렉토리에 있으면 ``shutil.copytree`` 가 ``Error`` 를 던져 sandbox 셋업이 깨졌다 — robustness 결여.
- 변경:
  - ``validator/test_runner.py`` 에 ``_is_safe_sandbox_relative_path(base, candidate)`` 헬퍼 도입. ``candidate`` 가 빈 문자열, 절대 경로, 또는 ``base`` 와 동일하거나 ``base + os.sep`` 로 시작하지 않는 경로인 경우 ``False`` 를 반환한다. ``os.path.realpath`` 정규화로 중첩 traversal 도 차단한다.
  - ``_run_in_sandbox()`` 가 ``tempfile.mkdtemp`` 직후, 프로젝트 복사 *이전에* ``_is_safe_sandbox_relative_path(tmp_dir, original_file_path)`` 검증을 수행. 안전하지 않으면 ``ValueError("안전하지 않은 original_file_path (sandbox 바깥 경로)")`` 를 raise — 기존 ``except Exception`` 분기로 흡수되어 ``TestResult(passed=False, error="테스트 실행 오류: ...")`` 를 반환하고, ``finally`` 의 ``shutil.rmtree(tmp_dir, ignore_errors=True)`` 가 sandbox 디렉토리를 정리한다.
  - 프로젝트 복사 시 symlink 정책을 명시적으로 한다:
    - ``shutil.copytree(..., symlinks=False, ignore_dangling_symlinks=True, ignore=_make_sandbox_copy_ignore())``.
    - ``_make_sandbox_copy_ignore()`` 는 기존 ``shutil.ignore_patterns("__pycache__", "*.pyc", ".git")`` 결과에 *디렉토리 안의 모든 symlink 항목* 을 추가로 무시 목록에 더한다. ``symlinks=False`` 가 link 를 따라가 일반 파일로 복사하는 동작과 결합되어도 link 자체가 사전 차단되므로 외부 대상 내용은 sandbox 로 복사되지 않는다.
    - 프로젝트 root 의 최상위 항목이 symlink 인 경우 ``os.path.islink(src)`` 검사로 사전 스킵.
  - 기존 ``shutil.rmtree(tmp_dir, ignore_errors=True)`` 의 finally cleanup 동작은 그대로 유지 — 성공 / 실패 / 예외 / 경로 거부 어느 경로에서든 sandbox 디렉토리가 잔존하지 않는다.
- 클린 아키텍처 적합성: ``TestRunner`` (검증 도메인) 의 책임 — “LLM 수정 코드를 격리된 임시 환경에서 시험” — 의 *격리 경계* 자체를 도메인 안에서 강화한다. 외부 어댑터(``ValidatorCommandRunner``) 시그니처와 환경 sanitizer (``shared.command_env.build_child_env``) 는 손대지 않는다. 동일 도메인 안의 path safety 한 가지 책임만 추가.
- 보존된 동작:
  - 빈/누락 ``fixed_code`` → ``patch.test_passed=False`` + ``status=FAILED``.
  - ``syntax_valid=False`` → sandbox 미진입.
  - 정상 상대 경로 (``target.py``, ``pkg/module.py``) 에 대해 fake runner 가 동일한 argv (``[sys.executable, "-m", "pytest", test_path, "-v", "--tb=short"]``) / cwd=tmp_dir / timeout=60 / sanitized env 로 호출됨.
  - 테스트 디렉토리 부재 또는 비어있음 → ``passed=None`` + 한국어 메시지 (``"테스트 파일 없음 - 문법 검사만 완료"``) 반환, ``VERIFIED`` 승격 안 함.
  - ``subprocess.TimeoutExpired`` → ``"테스트 실행 시간 초과 (60초)"`` 한국어 메시지 보존.
  - 일반 ``Exception`` → ``"테스트 실행 오류: {str(e)}"`` 한국어 prefix 보존 (Wave 4-K 가 도입한 ``ValueError`` 도 동일 분기로 흡수).
  - ``TestResult`` shape, ``PatchSuggestion`` 매핑 (``test_passed`` / ``status`` / ``explanation`` 추가) 그대로.
  - fake runner 주입 seam, 기본 생성자 동작, 기존 sanitized env allowlist (``_VALIDATOR_PYTEST_ENV_ALLOWLIST``) 그대로.
  - ``shared/schemas.py`` 변경 없음.
- 검증 근거:
  - RED: ``tests/test_validator_sandbox_hardening.py`` 의 6 개 신규 테스트 fail (``../outside.py`` 가 외부 파일을 덮어씀, 절대 외부 경로가 외부 파일을 덮어씀, 중첩 traversal 미차단, 경로 거부 시 cleanup 검증, symlink 외부 내용 sandbox 누출, dangling symlink 가 sandbox 셋업 깨뜨림) + 7 passed (정상 상대 경로 / cleanup 성공 케이스 / AST 가드 — 회귀 가드 역할).
  - GREEN targeted: ``tests/test_validator_sandbox_hardening.py`` ``tests/test_validator_command_runner_adapter.py`` ``tests/test_command_env_neutral_boundary.py`` ``tests/test_command_env_sanitizer.py`` → **75 passed in 0.17s**.
  - GREEN full: ``pytest tests/ -q`` → **674 passed, 5 warnings in 15.91s**. 5 warnings 는 Wave 4-K 와 무관한 기존 SQLAlchemy ``datetime.datetime.utcnow()`` deprecation + asyncio no-current-event-loop 경고로 본 wave 의 blocker 가 아니다 (Wave 4-J 시점 661 → +13 신규 회귀 테스트).
  - 실 외부 도구 호출 0건 — 신규 테스트는 모두 fake ``_RecordingRunner`` / ``_InspectingRunner`` 로 sandbox pytest 호출을 격리. ``tempfile.mkdtemp`` 만 stdlib 임시 디렉토리를 사용한다.
  - 추가 라인 보안 스캔: ``validator/test_runner.py`` 본문에 ``shell=True`` / ``os.system`` / ``os.popen`` / ``eval`` / ``exec`` / ``subprocess.run`` 직접 호출 모두 부재 — AST 정적 가드 (``TestTestRunnerSourceStaticGuards``) 와 기존 Wave 4-A 의 ``_calls_with_shell_true`` / ``_direct_subprocess_run_calls`` 가드로 이중 보장.
- 명시적 비적용 (의도적 비행동):
  - Docker / 컨테이너 격리, OS user 격리, chroot, Linux resource limits, network namespaces, CI / root 권한 변경 — 모두 본 wave 범위 밖. 본 wave 는 stdlib (``shutil`` / ``tempfile`` / ``os.path``) 만 사용한 *경로/심볼릭 링크/cleanup* 하드닝에 한정한다.
  - ``ValidatorCommandRunner`` 시그니처 변경, ``build_child_env`` allowlist 변경, ``shared/schemas.py`` 변경, 새 caller-specific allowlist 도입 모두 비적용.
  - 새 한국어 에러 문자열 도입은 최소화 — 기존 ``"테스트 실행 오류: ..."`` 분기를 그대로 사용해 호출자 (``run()``) 의 ``patch.explanation`` 누적 동작을 깨지 않는다.
- Rollback: `git revert -m 1 <merge>` (구현 커밋만 되돌릴 경우 `git revert <impl>`). 되돌리면 traversal/symlink 노출 위험이 다시 열리지만, 도메인 시그니처는 변하지 않는다.
- 초보자용 설명: "검증기는 LLM 이 만든 새 코드를 임시 폴더(sandbox)에 떨어뜨리고 그 안에서 pytest 를 돌린다. 그런데 ‘이 파일을 수정해 주세요’ 라고 호출자가 넘기는 경로가 ``../bashrc`` 처럼 폴더 바깥을 가리키면, 그 외부 파일을 LLM 이 만든 코드로 덮어쓸 수 있었다. 또 프로젝트 안에 ‘저쪽 비밀 파일’ 을 가리키는 symlink 가 있으면 sandbox 복사 과정이 그 비밀 파일을 통째로 sandbox 안으로 복사해, LLM 코드가 그 내용을 읽을 수 있었다. Wave 4-K 는 (1) 경로가 sandbox 안쪽인지 ``realpath`` 비교로 확인하고 아니면 거부, (2) 복사할 때 symlink 항목은 아예 무시, (3) 깨진 symlink 가 있어도 sandbox 셋업이 멈추지 않게 했다. 끝나면 sandbox 폴더는 성공/실패/거부 어느 쪽이든 항상 지운다."

### Wave 4-L — Security checker scanner seam (Bandit/Semgrep DI)

- 머지 커밋: 875c3ac merge: integrate Wave 4-L security checker seam
- 구현 커밋: 55b6731 refactor(validator): Wave 4-L add security checker scanner seam (브랜치 `w4l-security-checker-seam` head)
- 주요 파일/영역:
  - `validator/security_checker.py`
  - `tests/test_security_checker.py` (신규 회귀 테스트)
- 이전 구조: Wave 3-G 에서 ``BanditRunner`` / ``SemgrepRunner`` 는 ``StaticToolCommandRunner`` 어댑터를 받는 fakeable 생성자로 정리되었지만, ``validator/security_checker.py`` 의 ``SecurityChecker`` 자체는 외부 도구 실행 측에 대한 시(seam)이 없었다. ``_run_bandit`` 과 ``_run_semgrep`` 은 매 호출마다 함수 본문에서 ``from analyzer.bandit_runner import BanditRunner`` / ``from analyzer.semgrep_runner import SemgrepRunner`` 를 실행하고 ``BanditRunner()`` / ``SemgrepRunner(config="auto")`` 를 직접 생성했다. 결과적으로 ``SecurityChecker`` 단위 테스트는 fake 를 주입할 자리가 없어 작성되지 못했다 (이번 wave 까지 ``tests/test_security_checker.py`` 가 부재).
- 문제/위험:
  - **테스트 가능성 결여**: ``SecurityChecker`` 의 상태 매핑(``passed → VERIFIED``, 새 취약점 → ``FAILED``), ``removed_count`` / ``introduced_count`` 산정, 빈/누락 ``fixed_code`` short-circuit, fail-open 분기 (``tool_used="error"``) 동작이 단위 테스트 회귀 가드 없이 운영되었다.
  - **암묵적 외부 호출 위험**: 어떤 호출자가 ``SecurityChecker().check(...)`` 를 직접 호출하면 fake 를 주입할 자리가 없으므로 실제 ``bandit`` / ``semgrep`` subprocess 가 실행될 수 있었다. 일반 단위 테스트 환경에서 외부 도구 호출은 비결정성/네트워크/런타임 의존을 끌어들인다.
  - **클린 아키텍처 위반**: validator 도메인 클래스가 외부 명령 어댑터의 *생성* 까지 직접 책임지고 있었다. analyzer 측 어댑터 (``BanditRunner`` / ``SemgrepRunner``) 는 이미 fakeable 한데, 그 위 레이어인 validator 의 ``SecurityChecker`` 만 DI seam 이 없는 비대칭 상태였다.
- 변경:
  - ``SecurityChecker.__init__(self, *, bandit_runner=None, semgrep_runner=None)`` 키워드-온리 의존성 주입 시 도입. 두 인자 모두 기본값 ``None`` — 기존 ``SecurityChecker()`` 호출 형태는 그대로 유지.
  - ``_get_bandit_runner()`` / ``_get_semgrep_runner()`` 헬퍼를 도입해 *호출 시점* 에 lazy 하게 ``BanditRunner()`` / ``SemgrepRunner(config="auto")`` 를 생성. 모듈 import 시 부수효과는 없으며, ``SecurityChecker()`` 인스턴스화 자체도 외부 도구를 침범하지 않는다.
  - ``_run_bandit`` / ``_run_semgrep`` 은 더 이상 함수 안에서 ``BanditRunner`` / ``SemgrepRunner`` 를 직접 생성하지 않고 ``self._get_*_runner()`` 가 돌려준 인스턴스의 ``run(file_path)`` 만 호출한다.
  - 기존 try/except 분기는 그대로 — runner 가 예외를 던지면 빈 리스트를 돌려주는 inner fail-open 동작 유지. 외부 ``_run_security_scan`` try/except 의 ``passed=True`` + ``tool_used="error"`` 분기도 그대로.
  - 신규 ``tests/test_security_checker.py`` 추가:
    - ``SimpleNamespace`` 기반 fake ``BanditRunner`` / ``SemgrepRunner`` 더블 (``run(file_path) → SimpleNamespace(vulnerabilities=[...])`` 표면).
    - 정적 가드: 본문에 ``shell=True`` / ``os.system`` / ``os.popen`` / ``eval`` / ``exec`` / ``pickle.loads`` / ``subprocess.run`` 직접 호출 금지 회귀 가드.
    - DI seam: 키워드 인자 수용, 기본 생성자 lazy, 주입된 fake 만 호출되며 실제 ``BanditRunner`` / ``SemgrepRunner`` 인스턴스화가 일어나지 않음 (트립와이어 monkeypatch).
    - 상태 매핑 / fixed_ vs original_ 경로 분기 / Python (bandit+semgrep) vs 비-Python (semgrep only) ``tool_used`` 매핑 보존.
    - ``removed_count`` / ``introduced_count`` (rule_id, title) 셋 차집합 기반 산정 보존.
    - 빈/공백-only ``fixed_code`` 와 ``status=FAILED`` short-circuit (스캔 미실행) 보존.
    - inner runner 예외(``BanditRunner.run`` 이 ``RuntimeError``) → 빈 리스트로 흡수, ``tool_used="bandit+semgrep"`` 유지. outer ``_scan_file`` 예외 → ``passed=True`` + ``tool_used="error"`` fail-open 유지.
    - 기존 호출자 (``analyzer/pipeline.py`` 의 ``sec_checker.check(p, language=lang, filename=filename, original_code=orig)``) 시그니처와 ``check_batch`` 반복 동작 보존 회귀 가드.
- 클린 아키텍처 적합성: validator 도메인 (``SecurityChecker``) 이 더 이상 analyzer 측 어댑터를 *직접 생성* 하지 않는다. 의존성 주입을 통해 “어떤 외부 스캐너 어댑터를 쓸지” 의 결정을 외부에서 주입받을 수 있다. 기본 동작은 lazy 한 default factory 로 보존. 결과적으로 Bandit/Semgrep/Sonar/StaticTool/Dependency/Validator command/Sonar HTTP 어댑터에 이어 *그 위 레이어* 인 ``SecurityChecker`` 까지 같은 fakeable seam 패턴이 통일된다.
- 보존된 동작:
  - ``SecurityChecker()`` 기본 생성자 — 기존 호출자(``analyzer/pipeline.py``)는 변경 없이 동작.
  - ``check(patch, language=.., filename=.., original_code=..)`` 시그니처 / 키워드 인자 / 반환 타입 (``PatchSuggestion``).
  - ``check_batch(patches, ...)`` 반복 동작.
  - 빈 / 공백-only ``fixed_code`` → 그대로 ``patch`` 반환 (``security_revalidation`` 미설정).
  - ``patch.status == FAILED`` → 그대로 ``patch`` 반환.
  - 상태 매핑: 새 취약점 0 → ``VERIFIED`` + ``"보안 재검증 통과"`` 한국어 메시지, 새 취약점 ≥ 1 → ``FAILED`` + ``"보안 재검증 실패"`` + 상위 3개 ``rule_id(severity)`` 요약.
  - ``removed_count = max(0, len(original_vulns) - len(fixed_vulns))``.
  - ``introduced_count = len(fixed_vulns whose (rule_id, title) ∉ original_vulns rule set)``.
  - ``tool_used`` 매핑: ``.py`` → ``"bandit+semgrep"`` / 그 외 → ``"semgrep"`` / outer 예외 → ``"error"``.
  - inner ``_run_bandit`` / ``_run_semgrep`` 의 ``except Exception`` → 빈 리스트 fail-open.
  - outer ``_run_security_scan`` 의 ``except Exception`` → ``passed=True``, ``tool_used="error"``, ``error=str(e)`` fail-open.
  - 임시 디렉토리 ``tempfile.mkdtemp(prefix="dallo_revalidate_")`` 와 ``finally`` 의 ``shutil.rmtree(..., ignore_errors=True)`` 동작 그대로.
  - ``SecurityCheckResult`` dataclass shape 와 ``to_dict()`` 직렬화 그대로.
  - ``shared/schemas.py`` 변경 없음.
- 검증 근거:
  - RED: 신규 ``tests/test_security_checker.py`` 의 23 개 테스트 중 16 개가 구현 전에 ``TypeError: SecurityChecker() takes no arguments`` 로 실패, 7 개 (정적 AST 가드 + 기본 생성자 sanity) 만 패스. 즉 기존 코드가 ``bandit_runner`` / ``semgrep_runner`` 키워드 인자를 받지 못하는 사실을 회귀 가드로 고정.
  - GREEN targeted (final main, post-merge): ``tests/test_security_checker.py`` → **23 passed in 0.10s**.
  - GREEN broader targeted (final main, post-merge): ``tests/test_validator_sandbox_hardening.py`` ``tests/test_validator_command_runner_adapter.py`` ``tests/test_command_env_neutral_boundary.py`` ``tests/test_security_checker.py`` → **77 passed in 0.19s**.
  - GREEN full (final main, post-merge): ``pytest tests/ -q`` → **697 passed, 5 warnings in 16.52s** (Wave 4-K 시점 674 → +23 신규 회귀 테스트). 5 warnings 는 Wave 4-J/4-K 와 동일한 기존 SQLAlchemy ``datetime.datetime.utcnow()`` deprecation + asyncio no-current-event-loop 경고로, 본 wave 의 blocker 가 아니다. (구현/worktree 시점 동일 스위트 timing: targeted 23 passed in 0.09s, broader 77 passed in 0.25s, full 697 passed in 18.28s — 동일 결과, timing 만 환경 차이.)
  - Post-merge 검증 (로컬 main, working tree clean): fake smoke `WAVE4L_MAIN_FAKE_SMOKE_PASS injected_runners_used status_verified no_real_scanners` — 주입된 fake ``BanditRunner`` / ``SemgrepRunner`` 만 호출되고 상태 매핑이 검증되었으며 실제 스캐너 인스턴스화는 없음. 운영 보안 스캔: ``MAIN_AST_PRODUCTION_DANGER_SCAN_CLEAN`` (production AST dangerous pattern 0건), production secret assignment scan clean (하드코딩 시크릿 0건), ``MAIN_NO_API_SERVER_COUPLING_IN_CHANGED_FILES`` (변경 파일에서 ``api.server`` 결합 0건), ``MAIN_SHARED_SCHEMAS_UNCHANGED`` (``shared/schemas.py`` diff 0). push / PR / deploy / production DB / 실 외부 Dallo 호출 모두 0건.
  - 실 외부 도구 호출 0건 — 신규 테스트는 ``SimpleNamespace`` fake 와 monkeypatch 트립와이어로 ``BanditRunner`` / ``SemgrepRunner`` 인스턴스 자체를 차단. ``tempfile.mkdtemp`` 만 stdlib 임시 디렉토리를 사용하며 ``check_with_fixed_code=""`` short-circuit 테스트 등은 임시 디렉토리도 만들지 않는다.
  - 추가 라인 보안 스캔: ``validator/security_checker.py`` 본문에 ``shell=True`` / ``os.system`` / ``os.popen`` / ``eval`` / ``exec`` / ``pickle.loads`` / ``subprocess.run`` 직접 호출 모두 부재 — AST 정적 가드 (``TestSecurityCheckerSourceStaticGuards``) 로 회귀 가드. 새 secret-like 하드코딩 값 / SQL 문자열 보간 / ``api.server`` 의존 도입 0건.
  - ``shared/schemas.py`` / ``shared/command_env.py`` / ``analyzer/bandit_runner.py`` / ``analyzer/semgrep_runner.py`` 변경 없음.
- 명시적 비적용 (의도적 비행동):
  - fail-open → fail-closed 정책 변경 비적용. inner runner 예외와 outer scan 예외 모두 기존 fail-open 동작을 그대로 유지한다 (정책 변화는 별도 wave 로 분리).
  - validator sandbox 경로 traversal 하드닝 추가 비적용 (Wave 4-K 범위).
  - ``BanditRunner`` / ``SemgrepRunner`` 의 result model (``AnalysisResult`` / ``Vulnerability`` 스키마) 변경 비적용.
  - ``shared/command_env.py`` 정책 변경 비적용 (sanitizer/allowlist/deny filter 모두 그대로).
  - 새 caller-specific allowlist 도입 비적용 — Bandit/Semgrep 자식 env sanitizer 는 Wave 4-F/4-G 가 이미 처리.
  - 한국어 메시지 변경 없음 — ``"보안 재검증 통과"`` / ``"보안 재검증 실패"`` / ``"원본 N건 → 수정 M건 (K건 제거)"`` 그대로.
- Rollback: `git revert -m 1 875c3ac` (구현 커밋만 되돌릴 경우 `git revert 55b6731`). 되돌리면 ``SecurityChecker`` 단위 테스트가 사라지지만 (회귀 가드 약화), 외부 호출 정책 / 상태 매핑 / fail-open 동작은 그대로다. ``SecurityChecker()`` 호출자 (``analyzer/pipeline.py``) 는 두 모드 모두에서 호환된다.
- 초보자용 설명: "보안 재검증기는 LLM 이 만든 새 코드를 임시 파일로 떨어뜨리고 거기에 ``bandit`` 과 ``semgrep`` 두 개의 정적 분석기를 다시 돌려, 새로 도입된 취약점이 있는지 본다. Wave 4-L 이전에는 이 두 분석기를 만드는 코드가 ``security_checker`` 함수 안에 박혀 있어, 단위 테스트가 ‘진짜 ``bandit`` 을 실행하지 않고 가짜 ``bandit`` 을 끼워넣는’ 자리가 없었다. Wave 4-L 은 ``SecurityChecker(bandit_runner=..., semgrep_runner=...)`` 라는 작은 ‘구멍’ 을 뚫어, 테스트에서는 가짜를, 실제 운영에서는 그대로 진짜를 쓰게 했다. 사용자가 평소처럼 ``SecurityChecker()`` 라고만 부르면 진짜 ``BanditRunner`` 와 ``SemgrepRunner`` 가 호출 시점에만 만들어지므로, 모듈을 import 하는 것만으로 외부 도구가 깨어나는 일은 없다. 이렇게 해서 보안 재검증기의 ‘상태 매핑이 깨지지 않았는지’ 같은 회귀 검사를 외부 도구 없이도 빠르게 돌릴 수 있다."

### Wave 4-M — LLM agent retry sleeper seam

- 머지 커밋: b842b21 merge: integrate Wave 4-M llm sleeper seam
- 구현 커밋: 0d1a39e refactor(agent): Wave 4-M add llm retry sleeper seam
- 주요 파일/영역:
  - `agent/llm_agent.py`
  - `tests/test_llm_agent_sleeper_adapter.py` (신규 회귀 테스트)
- 이전 구조: ``DalloAgent`` 의 retry 경로 (``generate_patch`` / ``generate_multi_patches``) 는 rate-limit 응답을 만나거나 재시도가 필요할 때 함수 본문에서 ``time.sleep(wait)`` 를 직접 호출했다. 즉 retry 의 “기다린다” 라는 동작이 모듈 전역의 ``time.sleep`` 에 직접 매여 있었다. 결과적으로 retry 경로 단위 테스트는 (1) 실제 wall-clock 만큼 기다리거나, (2) 전역 ``time.sleep`` 을 monkeypatch 해서 우회해야 했다.
- 문제/위험:
  - **테스트 비결정성/지연**: 실제 wall-clock 대기는 retry 경로 검증을 느리고 비결정적으로 만든다 (rate-limit 메시지의 retry-delay 가 ``"3"`` 초로 파싱되면 단위 테스트가 3 초씩 멈춘다).
  - **외부 시계 경계의 도메인 침투**: 핵심 LLM 오케스트레이션(``DalloAgent``) 안에 ``time.sleep`` 이라는 외부 시계 경계가 그대로 박혀 있어, “retry 로직” 이라는 도메인 책임과 “실제 OS 시간을 흘려보낸다” 라는 외부 부수효과가 한 함수 안에서 섞여 있었다.
  - **monkeypatch 의존**: 전역 ``time.sleep`` 을 가로채는 테스트는 같은 인터프리터에서 실행되는 다른 라이브러리에도 영향을 주며, 테스트 격리 측면에서 비대칭적이다.
- 변경:
  - ``DalloAgent.__init__`` 에 키워드-온리 ``sleeper`` 의존성을 추가. 기본값은 ``None`` 이며 ``self._sleeper = sleeper if sleeper is not None else time.sleep`` 로 주입한다. 즉 ``DalloAgent()`` 기존 호출 형태는 그대로 유지된다.
  - ``generate_patch`` 와 ``generate_multi_patches`` 의 retry 대기 호출을 모두 ``time.sleep(wait)`` → ``self._sleeper(wait)`` 로 교체. 동일 인스턴스의 retry 경로는 모두 같은 sleeper 객체를 통과한다.
  - 신규 ``tests/test_llm_agent_sleeper_adapter.py`` 추가:
    - 기본 동작 가드: ``sleeper`` 미주입 시 ``self._sleeper is time.sleep``.
    - 키워드-온리 호환성: ``DalloAgent(sleeper=fake)`` 만 허용되며 위치 인자 형태는 거부.
    - rate-limit retry: 429/유사 응답에서 retry-delay 파싱 후 fake sleeper 가 받은 ``sleep_values`` 에 기대값이 누적되는지 검증.
    - key-rotation skip: rotate_key 로 새 키가 잡히는 경우 sleeper 가 호출되지 않는다 (즉시 재시도).
    - non-rate-limit no-sleep: rate-limit 가 아닌 일반 예외/실패 경로에서는 sleeper 가 호출되지 않는다.
    - success no-sleep: 첫 시도가 성공하면 sleeper 가 호출되지 않는다.
    - exhausted retry: max_retries 소진 시 기존의 “마지막 시도 직전 sleep” 동작이 보존되며, 최종 실패 status 가 그대로다.
    - multi-patch path: ``generate_multi_patches`` 도 동일하게 ``self._sleeper`` 를 통과하며 retry 경로가 동작한다.
- 클린 아키텍처 적합성: 시간(``time.sleep``) 이라는 외부 boundary 를 도메인 안에서 fakeable 한 seam 으로 분리한다. 이는 Wave 3-J 의 Sonar polling clock/sleeper 분리, Wave 4-A 이후의 어댑터/DI seam 패턴과 동일한 형태로, ``DalloAgent`` 에 처음으로 동일 패턴을 적용한 wave 다.
- 보존된 동작:
  - ``DalloAgent()`` 기본 생성자 — sleeper 를 명시하지 않으면 운영 기본값 ``time.sleep`` 그대로 사용.
  - ``max_retries`` 값과 retry 의사결정 흐름.
  - retry-delay 파싱 (``_extract_retry_delay`` 동작) 동일.
  - provider call 흐름, ``rotate_key`` 동작, SYSTEM_PROMPT, prompts/parsers/cache/masking 흐름 모두 동일.
  - API 응답 모양과 ``shared/schemas.py`` 무변경.
  - 기존의 “마지막 시도 직전 sleep 후 FAILED” 동작도 그대로 (sleeper 만 통과 지점이 바뀐다).
- 검증 근거:
  - Worktree targeted: ``tests/test_llm_agent_sleeper_adapter.py`` ``tests/test_llm_parser.py`` → **23 passed in 20.69s**.
  - Worktree full: ``pytest tests/ -q`` → **712 passed, 5 warnings**.
  - Worktree fake smoke: ``WAVE4M_FAKE_SMOKE_PASS fake_provider_used fake_sleeper_used no_real_llm sleep_values=[3]`` — fake provider/fake sleeper 만 호출되고 실제 LLM 호출은 0건, sleeper 가 받은 값은 retry-delay 3 초 1 회.
  - Worktree security/schema: ``WAVE4M_AST_SECURITY_SCAN_CLEAN``, ``WAVE4M_FORBIDDEN_TEXT_SCAN_CLEAN``, ``WAVE4M_SHARED_SCHEMAS_UNCHANGED``.
  - Independent review: APPROVED, scope-correct, behavior preserved, no regression concerns.
  - Final main targeted (post-merge): **23 passed in 21.02s**.
  - Final main full (post-merge): ``pytest tests/ -q`` → **712 passed, 5 warnings in 32.99s** (Wave 4-L 시점 697 → +15 신규 회귀 테스트, 그 중 본 wave 의 sleeper-adapter 테스트가 핵심).
  - Final main fake smoke / 운영 보안 / schema (post-merge): ``WAVE4M_MAIN_FAKE_SMOKE_PASS fake_provider_used fake_sleeper_used no_real_llm sleep_values=[3] status=PatchStatus.GENERATED``, ``WAVE4M_MAIN_AST_SECURITY_SCAN_CLEAN``, ``WAVE4M_MAIN_FORBIDDEN_TEXT_SCAN_CLEAN``, ``WAVE4M_MAIN_SHARED_SCHEMAS_UNCHANGED``.
  - 실 외부 호출 0건. push / PR / deploy / production DB / 실 LLM 호출 / network 호출 모두 수행되지 않았다.
- 명시적 비적용 (의도적 비행동):
  - LLM provider 변경 비적용 (Gemini/OpenRouter 호출 흐름 그대로).
  - Key rotation 정책 변경 비적용 (rotate_key 동작 그대로).
  - Retry 정책 변경 비적용 (max_retries / retry-delay 파싱 / rate-limit 판정 흐름 그대로).
  - API / schema / frontend 변경 비적용.
  - ``shared/schemas.py`` 변경 없음.
- Rollback: `git revert -m 1 b842b21` (구현 커밋만 되돌릴 경우 `git revert 0d1a39e`). 되돌리면 sleeper-adapter 회귀 가드는 사라지지만, 운영 시 ``time.sleep`` 직접 호출로 돌아가 동작은 동일하다.
- 초보자용 설명: "‘sleeper’ 라는 말이 어렵게 들리지만, 실은 단순히 ‘얼마 동안 기다리는 함수’ 다. 평소(운영) 에는 그 함수가 진짜 ``time.sleep`` 이라서 정말로 그 시간만큼 멈춘다. Wave 4-M 이전에는 이 ‘기다린다’ 라는 동작이 ``DalloAgent`` 함수 안에 직접 박혀 있어서, 단위 테스트가 ‘LLM rate-limit 에 걸리면 3 초 기다리고 다시 시도한다’ 를 검증하려면 진짜로 3 초를 기다리거나 전역 ``time.sleep`` 을 우회해야 했다. Wave 4-M 은 ``DalloAgent(sleeper=...)`` 라는 작은 ‘구멍’ 을 만들었다. 테스트는 그 자리에 ‘기다린 척하면서 받은 초 수를 리스트에 적기만 하는 가짜 함수’ 를 끼워넣는다. 그러면 retry 로직은 즉시 실행되고, 테스트는 ‘sleeper 가 [3] 초 받았는가’ 를 보면 끝난다. 사용자가 평소처럼 ``DalloAgent()`` 라고만 부르면 진짜 ``time.sleep`` 이 그대로 쓰이므로 운영 동작은 한 줄도 바뀌지 않는다. 즉 진짜 Gemini/OpenRouter 호출이나 실제 wall-clock 대기 없이 retry 동작이 빠르게, 결정적으로 검증된다."

### Wave 4-N — Bandit/Semgrep file I/O seam

- 머지 커밋: 660c810 merge: integrate Wave 4-N scanner file io seam
- 구현 커밋: 36627f7 refactor(analyzer): Wave 4-N add scanner file io seam (브랜치 `w4n-file-io-seam` head, worktree `/home/ubuntu/dallo-worktrees/w4n-file-io-seam`)
- 주요 파일/영역:
  - `analyzer/bandit_runner.py`
  - `analyzer/semgrep_runner.py`
  - `analyzer/file_io.py` (신규 — 파일 I/O 어댑터)
  - `tests/test_bandit_file_io_seam.py` (신규 회귀 테스트)
  - `tests/test_semgrep_file_io_seam.py` (신규 회귀 테스트)
- 이전 구조: ``BanditRunner`` / ``SemgrepRunner`` 는 외부 명령 실행(Wave 3-G 의 ``StaticToolCommandRunner``) 과 자식 env sanitize(Wave 4-F/4-G 의 ``build_child_env``) 까지는 어댑터/seam 으로 분리되어 있었지만, **결과 JSON 을 디스크에 쓰는 동작** (``output_path`` 가 주어졌을 때 ``open(output_path, "w").json.dump(...)``) 과 **Semgrep snippet enrichment 가 원본 소스 파일을 라인 단위로 읽는 동작** (``open(file_path, "r").readlines()``) 은 여전히 두 runner 본문에 stdlib ``open`` 호출로 박혀 있었다. 결과적으로 “결과 파일 경로가 주어지면 디스크에 정확한 페이로드/포맷으로 기록되는가”, “snippet enrichment 가 원본 파일을 어떤 식으로 읽는가” 같은 회귀 가드를 단위 테스트로 만들려면 임시 파일을 실제로 생성하고 후처리하는 식으로만 가능했고, 진짜 디스크 부수효과를 일으킬 위험이 있었다.
- 문제/위험:
  - **테스트 비결정성/디스크 부수효과**: 디스크 쓰기 검증은 ``tempfile`` 경로를 만들고, 테스트 종료 시 정리하고, OS 별 줄바꿈/인코딩 차이까지 흡수해야 한다. 또 snippet enrichment 의 라인 읽기는 fake 를 끼워넣을 자리가 없어 테스트가 실 파일을 만들거나 ``builtins.open`` 을 monkeypatch 해야 했다.
  - **외부 자원 경계의 도메인 침투**: 두 runner 의 핵심 책임은 “외부 명령 실행 → JSON 파싱 → ``Vulnerability`` 매핑” 이다. 그러나 “결과를 디스크에 떨어뜨린다”, “원본 파일을 라인 단위로 읽는다” 라는 *별개* 의 외부 자원 경계가 같은 클래스 안에 함께 있어, runner 단위 테스트의 격리 비용이 과도했다.
  - **monkeypatch 의존**: 전역 ``builtins.open`` 을 가로채는 방식은 같은 인터프리터의 다른 라이브러리에도 영향을 주며, 테스트 격리 측면에서 비대칭적이다.
- 변경:
  - 신규 ``analyzer/file_io.py`` 모듈을 도입. ``FileIO`` 클래스는 두 개의 메서드만 노출한다.
    - ``write_json(path, payload)``: 부모 디렉토리 자동 생성(``os.makedirs(..., exist_ok=True)``) 후 UTF-8 텍스트로 ``json.dump(payload, f, indent=2, ensure_ascii=False)`` 를 그대로 호출. 즉 기존 두 runner 의 디스크 쓰기 옵션(들여쓰기 2, ``ensure_ascii=False``) 을 한 글자도 바꾸지 않는다.
    - ``read_text_lines(path)``: UTF-8 텍스트로 ``f.readlines()`` 를 그대로 호출. 예외 swallowing 은 호출자(``SemgrepRunner._enrich_with_snippets``) 측에서 유지되며, 본 어댑터는 표준 파일 예외를 그대로 전파한다.
    - 모듈 레벨 ``get_default_file_io()`` 가 단일 기본 ``FileIO`` 인스턴스를 lazy 하게 반환. 두 runner 가 ``file_io=None`` 으로 생성되어도 운영 경로는 그대로 stdlib 파일 I/O 를 사용한다.
  - ``BanditRunner.__init__`` 과 ``SemgrepRunner.__init__`` 에 키워드-온리 ``file_io=None`` 의존성 주입 자리를 추가. 기본값은 ``None`` — 기존 ``BanditRunner()`` / ``SemgrepRunner(config="auto")`` 호출 형태는 그대로 유지.
  - 두 runner 의 디스크 쓰기 호출 (``output_path`` 가 ``None`` 이 아닐 때) 을 ``self._file_io.write_json(output_path, payload)`` 로 교체. ``output_path is None`` 이면 기존처럼 디스크에 아무 것도 쓰지 않는다.
  - ``SemgrepRunner._enrich_with_snippets`` (또는 동등 위치) 의 ``open(file_path, "r").readlines()`` 호출을 ``self._file_io.read_text_lines(file_path)`` 로 교체. snippet enrichment 의 조건/윈도우 계산/예외 swallowing 분기는 그대로.
  - 두 runner 모두 ``self._file_io`` 를 lazy 하게 해석한다 — 인스턴스화 시 ``None`` 이면 ``get_default_file_io()`` 의 기본 인스턴스를 사용. 따라서 ``BanditRunner()`` / ``SemgrepRunner(config="auto")`` 인스턴스화만으로 디스크 부수효과는 발생하지 않는다.
  - 신규 ``tests/test_bandit_file_io_seam.py`` 와 ``tests/test_semgrep_file_io_seam.py`` 를 추가:
    - DI seam: 키워드-온리 ``file_io=...`` 인자 수용, 기본 생성자에서는 ``get_default_file_io()`` 가 돌려준 인스턴스가 lazy 하게 사용됨, 주입된 fake 만 호출되며 stdlib ``open`` 은 호출되지 않음 (트립와이어 monkeypatch).
    - ``output_path`` 가 주어졌을 때 fake ``FileIO`` 의 ``write_json`` 이 정확한 경로/페이로드로 호출되고, 디스크에 실제 파일이 만들어지지 않음.
    - ``output_path=None`` 이면 ``write_json`` 호출 자체가 일어나지 않는 “no-write” 동작 보존.
    - Semgrep snippet enrichment: fake ``read_text_lines`` 가 돌려준 라인 리스트로 snippet 윈도우(앞/뒤 컨텍스트) 가 계산되고, 원본 stdlib ``open`` 은 호출되지 않음. 라인 읽기 예외(``OSError``/``UnicodeDecodeError`` 등) 는 호출자에서 swallow 되어 enrichment 가 실패해도 결과 매핑이 깨지지 않음.
    - 정적 가드: 두 runner 본문에서 ``shell=True`` / ``os.system`` / ``os.popen`` / ``eval`` / ``exec`` / ``pickle.loads`` / ``subprocess.run`` 직접 호출 부재 회귀 가드. 그리고 ``open(``/``json.dump(``/``readlines`` 직접 호출은 오직 ``analyzer/file_io.py`` 에만 존재해야 한다는 추가 회귀 가드 (``analyzer/bandit_runner.py`` / ``analyzer/semgrep_runner.py`` 본문에는 없어야 함).
- 클린 아키텍처 적합성: 외부 자원(파일 시스템) 경계를 도메인 어댑터로 분리한다. 이는 Wave 3-G (외부 명령 어댑터), Wave 4-F/4-G (자식 env sanitizer), Wave 4-L (security checker DI seam), Wave 4-M (sleeper seam) 과 동일한 형태로, 두 정적 분석 runner 에 처음으로 “파일 시스템 어댑터” 패턴을 적용한 wave 다. 결과적으로 ``BanditRunner`` / ``SemgrepRunner`` 는 “명령 실행 + 결과 파싱 + 매핑” 이라는 단일 책임에 더 가까워지고, 디스크 쓰기/원본 라인 읽기는 어느 쪽도 “이 외부 자원에 접근” 이라는 한 종류의 책임만 가진 ``FileIO`` 어댑터로 위임된다.
- 보존된 동작:
  - ``BanditRunner()`` / ``SemgrepRunner(config="auto")`` 기본 생성자 — 기존 호출자(``analyzer/pipeline.py``, ``validator/security_checker.py`` 의 lazy factory) 는 변경 없이 동작.
  - ``run(file_path, output_path=None)`` 시그니처와 반환 타입 (``AnalysisResult``).
  - ``output_path=None`` 일 때 디스크에 아무 것도 쓰지 않는 “no-write” 동작 보존.
  - 부모 디렉토리 자동 생성 (``os.makedirs(..., exist_ok=True)`` 동등) 보존.
  - JSON 직렬화 옵션: UTF-8, ``json.dump(..., indent=2, ensure_ascii=False)`` 한 글자도 바뀌지 않음.
  - Semgrep snippet enrichment 의 조건(라인 정보 존재), 윈도우(앞/뒤 컨텍스트 라인 수), 예외 swallowing(파일 읽기 실패 시 enrichment 만 비고 결과는 그대로) 동작 보존.
  - 외부 명령 실행 흐름(``StaticToolCommandRunner``), 결과 파서(``result_parser``) / ``Vulnerability`` 매핑 그대로.
  - 한국어 메시지 (스캐너 실패/완료 로그 등) 변경 없음.
  - 자식 env sanitizer (Wave 4-F/4-G 의 ``build_child_env``), allowlist/deny 정책 그대로.
  - API 응답 모양과 ``shared/schemas.py`` 무변경 — 프런트엔드 계약/스키마 변화 0.
- 검증 근거:
  - Worktree targeted: ``tests/test_bandit_file_io_seam.py`` ``tests/test_semgrep_file_io_seam.py`` → **23 passed**.
  - Worktree broader targeted: 두 신규 스위트 + 기존 bandit/semgrep/security_checker/pipeline 관련 회귀 → **95 passed**.
  - Worktree full: ``pytest tests/ -q`` → **735 passed, 5 warnings**.
  - Worktree fake smoke: ``WAVE4N_FAKE_SMOKE_PASS injected_file_io_used no_real_disk_write no_real_scanner`` — 주입된 fake ``FileIO`` 만 호출되고 실제 디스크 쓰기/실 스캐너 호출은 0건.
  - Worktree security/schema scans: 변경 diff 에 secret-like 값 부재, 신규 추가 라인에서 ``shell=True`` / ``os.system`` / ``os.popen`` / ``eval`` / ``exec`` / ``pickle.loads`` / ``subprocess.run`` 직접 호출 부재, production AST dangerous pattern 부재, ``api.server`` 결합 부재, ``shared/schemas.py`` diff 0. 직접 ``open(`` / ``json.dump(`` / ``readlines`` 호출은 의도대로 ``analyzer/file_io.py`` 에만 존재.
  - Independent read-only review: **APPROVED** (보고 스트림 ``/tmp/dallo-wave4n-review.stream.jsonl``) — scope-correct, behavior preserved, no regression concerns.
  - Final main targeted (post-merge): **23 passed in 0.09s**.
  - Final main broader targeted (post-merge): **95 passed in 1.86s**.
  - Final main full (post-merge): ``pytest tests/ -q`` → **735 passed, 5 warnings in 33.60s** (Wave 4-M 시점 712 → +23 신규 회귀 테스트). 5 warnings 는 Wave 4-J/4-K/4-L/4-M 과 동일한 기존 SQLAlchemy ``datetime.datetime.utcnow()`` deprecation + asyncio no-current-event-loop 경고로, 본 wave 의 blocker 가 아니다.
  - Final main fake smoke (post-merge): ``WAVE4N_MAIN_FAKE_SMOKE_PASS injected_file_io_used no_real_disk_write no_real_scanner``.
  - Final main security/schema scans (post-merge): worktree 와 동일한 clean 결과; ``shared/schemas.py`` 무변경.
  - 실 외부 호출 0건. push / PR / deploy / production DB / 실 외부 Dallo 호출 / 실 Bandit/Semgrep 실행 / network 호출 모두 수행되지 않았다.
- 명시적 비적용 (의도적 비행동):
  - validator 측 파일 쓰기 seam 도입 비적용 (Wave 4-O 후보 범위).
  - DB clock/deprecation 정리 비적용 (Wave 4-P 후보 범위).
  - dormant ``integrations/github_client.py`` HTTP seam 비적용 (Wave 4-Q 후보 범위).
  - ``shared/schemas.py`` / ``shared/command_env.py`` 변경 없음.
  - subprocess/env 정책 변경 없음 — Wave 4-D ~ 4-J 가 도입한 child env sanitizer / allowlist / deny / extras 정책 그대로.
  - API / frontend / schema 계약 변경 없음.
  - push / PR / deploy / production DB / external service 호출 없음 (정책 유지).
- Rollback: `git revert -m 1 660c810` (구현 커밋만 되돌릴 경우 `git revert 36627f7`). 되돌리면 file I/O seam 회귀 가드는 사라지지만, 운영 시 두 runner 가 stdlib ``open`` / ``json.dump`` / ``readlines`` 를 직접 호출하던 상태로 돌아가 동작 자체는 동일하다. 호출자는 두 모드 모두에서 호환된다.
- 초보자용 설명: "Bandit 과 Semgrep 두 분석기는 ‘외부 도구를 실행’ + ‘결과 JSON 을 받아서 파싱’ + ‘결과를 (옵션으로) 디스크에 떨어뜨린다’ + ‘Semgrep 은 라인 정보를 가지고 원본 소스의 그 줄 주변을 다시 읽어 snippet 을 붙인다’ 를 한 클래스 안에서 했다. 이 중 ‘디스크에 쓴다’, ‘파일을 라인 단위로 읽는다’ 는 사실 ‘파일 시스템’ 이라는 다른 외부 자원이다. Wave 4-N 은 ``FileIO`` 라는 작은 어댑터를 만들어 그 두 동작만 거기에 모았다. 두 runner 는 평소에는 그 어댑터의 기본 인스턴스를 lazy 하게 받아 그대로 쓰지만(즉 운영 동작은 그대로), 테스트는 ``BanditRunner(file_io=fake)`` / ``SemgrepRunner(config='auto', file_io=fake)`` 처럼 가짜 ``FileIO`` 를 끼워넣어 실제 디스크에 쓰거나 실제 파일을 읽지 않고도 ‘결과 파일이 정확한 경로/포맷으로 쓰일까’, ‘snippet 윈도우가 정확히 계산될까’ 를 즉시 검증한다. 사용자가 평소처럼 ``BanditRunner()`` / ``SemgrepRunner(config='auto')`` 라고만 부르면 진짜 디스크 I/O 가 그대로 쓰이므로, 운영 동작은 한 줄도 바뀌지 않는다."

### Wave 4-O — Validator file write seam

- 머지 커밋: (TBD — Hermes local merge 전)
- 구현 커밋: (worktree `/home/ubuntu/dallo-worktrees/w4o-validator-file-io-seam`, 브랜치 `w4o-validator-file-io-seam` 의 단일 구현 커밋)
- 주요 파일/영역:
  - `validator/file_io.py` (신규 — validator 측 파일 쓰기 어댑터)
  - `validator/test_runner.py`
  - `validator/security_checker.py`
  - `validator/syntax_checker.py`
  - `tests/test_validator_file_io_seam.py` (신규 회귀 테스트, 30개)
- 이전 구조: 세 validator 모듈 모두 외부 도구 호출은 어댑터/seam 으로 분리되어 있었지만 (Wave 4-A ``ValidatorCommandRunner``, Wave 4-L ``SecurityChecker`` Bandit/Semgrep DI), **임시/sandbox 파일 쓰기** 책임은 여전히 본문에 stdlib ``open(..., "w").write(...)`` 또는 ``tempfile.NamedTemporaryFile(mode="w").write(...)`` 호출로 박혀 있었다. 구체적으로:
  - `validator/test_runner.py` `_run_in_sandbox` 의 sandbox 타깃 쓰기 — ``with open(target_file, "w", encoding="utf-8") as f: f.write(fixed_code)``.
  - `validator/security_checker.py` `_run_security_scan` 의 ``fixed_{filename}`` / ``original_{filename}`` 임시 쓰기 — 동일 패턴 두 번.
  - `validator/syntax_checker.py` `check_with_flake8` 의 ``.py`` 임시 쓰기 — ``tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False).write(code)``.
- 문제/위험:
  - **테스트 비결정성/디스크 부수효과**: 위 세 boundary 의 회귀 가드를 단위 테스트로 만들려면 실제 파일을 만들고 정리하거나 전역 ``builtins.open`` 을 monkeypatch 해야 했다. 후자는 같은 인터프리터의 다른 라이브러리에도 영향을 주어 비대칭적이다.
  - **외부 자원 경계의 도메인 침투**: 세 클래스의 핵심 책임은 “외부 도구 호출 + 결과 매핑” 이지만 거기에 “파일 시스템에 임시 파일을 쓴다” 라는 *별개* 의 외부 자원 경계가 함께 있어, validator 단위 테스트가 격리되기 어려웠다.
  - **LLM 코드 격리 환경의 검증 한계**: ``TestRunner`` 의 sandbox 타깃 쓰기는 LLM 이 생성한 코드가 sandbox 디렉토리 *안* 의 파일에만 정확히 들어가는지 검증하기 위한 핵심 회귀 가드가 필요한 영역이다 (Wave 4-K traversal 차단의 보완재). 실 디스크 쓰기 없이 “fixed_code 가 정확히 sandbox-내부 경로로 흘러갔는가” 를 검증하는 seam 이 없었다.
  - **Wave 4-N 과의 비대칭성**: analyzer 측 (``BanditRunner`` / ``SemgrepRunner``) 의 파일 I/O 경계는 Wave 4-N 에서 이미 ``analyzer/file_io.py`` 어댑터로 분리되었는데, validator 측은 같은 패턴이 적용되지 않아 “외부 자원 어댑터 패턴” 이 일관되게 적용되지 않은 상태였다.
- 변경:
  - 신규 ``validator/file_io.py`` 모듈을 도입. ``FileIO`` 클래스는 두 개의 메서드만 노출한다.
    - ``write_text(path, content)``: UTF-8 텍스트로 ``open(path, "w").write`` 와 동등한 동작. ``TestRunner`` / ``SecurityChecker`` 의 known-path 쓰기에 사용.
    - ``write_named_temp(content, suffix='')``: ``tempfile.NamedTemporaryFile(mode="w", suffix=..., delete=False, encoding="utf-8")`` 와 동등한 동작으로 새 임시 파일을 생성·기록·반환. 호출자(``SyntaxChecker.check_with_flake8``) 의 ``finally: os.unlink(...)`` cleanup 계약을 그대로 보존.
    - 모듈 레벨 ``get_default_file_io()`` 가 단일 기본 ``FileIO`` 인스턴스를 lazy 하게 반환. 세 validator 모듈이 ``file_io=None`` 으로 생성되어도 운영 경로는 그대로 stdlib 파일 I/O 를 사용한다.
  - ``TestRunner.__init__`` 에 keyword-only ``file_io: Optional[FileIO] = None`` 파라미터를 추가. 기존 ``TestRunner(project_root=..., runner=...)`` / ``TestRunner()`` / ``TestRunner(project_root=...)`` 호출 형태는 그대로 동작한다 (positional 호환성 보존). ``_run_in_sandbox`` 의 sandbox 타깃 쓰기를 ``file_io.write_text(target_file, fixed_code)`` 로 교체.
  - ``SecurityChecker.__init__`` 에 keyword-only ``file_io`` 파라미터를 추가 (기존 ``bandit_runner`` / ``semgrep_runner`` 도 keyword-only). ``_run_security_scan`` 의 fixed/original 두 임시 쓰기를 동일 ``file_io`` 인스턴스의 ``write_text`` 호출로 교체. lazy 해석은 ``_run_security_scan`` 시점에 한 번만 — 같은 호출 내 두 쓰기가 같은 어댑터 인스턴스를 공유.
  - ``SyntaxChecker.__init__`` 에 keyword-only ``file_io`` 파라미터를 추가. 기존 ``SyntaxChecker(runner=...)`` / ``SyntaxChecker()`` 호출 형태는 그대로. ``check_with_flake8`` 의 ``tempfile.NamedTemporaryFile(...)`` 블록을 ``file_io.write_named_temp(code, suffix=".py")`` 한 줄로 교체. ``except FileNotFoundError`` 폴백 분기와 ``finally: os.unlink(tmp_path)`` cleanup 분기는 그대로 보존. ``import tempfile`` 은 syntax_checker.py 본문에서 제거되었으며 (어댑터로 이동), ``os.unlink`` cleanup 만 모듈에 남는다.
  - 신규 ``tests/test_validator_file_io_seam.py`` (총 30개) 를 추가:
    - DI seam: 세 클래스 모두 keyword-only ``file_io=...`` 인자 수용, positional 거부 (TypeError), 기본 생성자에서 ``get_default_file_io()`` 가 lazy 해석됨, 주입된 fake 만 호출되며 stdlib ``open`` / ``NamedTemporaryFile`` 직접 호출은 발생하지 않음.
    - 어댑터 자체 표면: ``FileIO`` / ``write_text`` / ``write_named_temp`` / ``get_default_file_io`` 존재, 기본 어댑터의 UTF-8 디스크 쓰기 동작 (한글 round-trip), 기본 ``write_named_temp`` 의 임시 파일 생성/내용 보존.
    - ``TestRunner(file_io=fake)``: sandbox 타깃 쓰기에 fake 가 단 한 번 호출되고 path 가 sandbox 임시 디렉토리(``dallo_test_*``) 안의 ``target.py`` 임. 원본 ``project_root`` 의 파일은 변경 없음.
    - ``SecurityChecker(file_io=fake)``: ``original_code`` 비어 있으면 1회 (``fixed_app.py``), 있으면 2회 (``fixed_app.py`` + ``original_app.py``) 호출. fake bandit/semgrep 도 같은 임시 경로로 호출됨.
    - ``SyntaxChecker(file_io=fake)``: ``write_named_temp`` 가 정확한 suffix(`.py`) 와 content 로 호출되고, fake 가 돌려준 경로가 flake8 argv 마지막 인자에 들어감. ``FileNotFoundError`` 폴백이 fake 도입 후에도 그대로 동작.
    - 정적 가드(AST): 세 validator 모듈 본문에 직접 ``open(..., 'w'/'a'/'x')`` 호출 / ``.write(...)`` 속성 호출 / ``tempfile.NamedTemporaryFile`` 잔존 0건. 동시에 ``validator/file_io.py`` 본문에는 어댑터 구현으로 ``open(..., 'w')`` + ``.write(...)`` 가 *반드시* 존재해야 한다는 양방향 회귀 가드.
    - lazy quietness: 세 클래스 모두 인스턴스화 시점에 ``FileIO.write_text`` / ``FileIO.write_named_temp`` 가 한 번도 호출되지 않음.
- 클린 아키텍처 적합성: 외부 자원(파일 시스템) 경계를 도메인 어댑터로 분리한다. 이는 Wave 3-G (외부 명령 어댑터), Wave 4-F/4-G (자식 env sanitizer), Wave 4-L (security checker DI seam), Wave 4-M (sleeper seam), Wave 4-N (analyzer 파일 I/O seam) 과 동일한 형태로, 본 wave 는 같은 패턴을 validator 측에 처음으로 적용한다. 결과적으로 ``TestRunner`` / ``SecurityChecker`` / ``SyntaxChecker`` 는 “외부 도구 호출 + 결과 매핑” 단일 책임에 더 가까워지고, 임시/sandbox 파일 쓰기는 어느 쪽도 “이 외부 자원에 접근” 이라는 한 종류의 책임만 가진 ``FileIO`` 어댑터로 위임된다. 의존 방향은 validator 내부에서만 닫히며 (validator-local 어댑터, ``analyzer/file_io.py`` 와 무관), analyzer 와의 양방향 결합을 도입하지 않는다.
- 보존된 동작:
  - ``TestRunner()`` / ``TestRunner(project_root=...)`` / ``TestRunner(project_root=..., runner=...)`` 기본/positional 생성자 — 기존 호출자(파이프라인) 변경 없이 동작.
  - ``SecurityChecker()`` / ``SecurityChecker(bandit_runner=..., semgrep_runner=...)`` 기존 호출 형태 보존.
  - ``SyntaxChecker()`` / ``SyntaxChecker(runner=...)`` 기존 호출 형태 보존.
  - ``_run_in_sandbox`` 의 sandbox 디렉토리 lifecycle (``tempfile.mkdtemp(prefix="dallo_test_")`` + ``shutil.copytree`` + ``finally: shutil.rmtree``), Wave 4-K 의 traversal/symlink/cleanup 하드닝 정책, sandbox pytest argv/cwd/timeout/env 정책 — 한 줄도 바뀌지 않음.
  - ``_run_security_scan`` 의 fixed/original 비교 로직, ``removed_count`` / ``introduced_count`` 산정, ``tool_used`` 매핑(``bandit+semgrep`` / ``semgrep``), Wave 4-L fail-open 동작 (``tool_used="error"`` + ``passed=True``) 보존.
  - ``check_with_flake8`` 의 ``.py`` suffix, flake8 argv (``["flake8", "--select=E9,F63,F7,F82", tmp_path]``), timeout=10, ``FileNotFoundError`` 폴백 → ``_check_syntax``, ``finally: os.unlink(tmp_path)`` cleanup 보존.
  - JSON 직렬화 / Bandit/Semgrep 출력 파싱 / ``Vulnerability`` 매핑 등 analyzer 동작 (Wave 4-N 결과물) 변경 없음.
  - 한국어 메시지 (``"테스트 실행 시간 초과 (60초)"``, ``"보안 재검증 통과"`` / ``"보안 재검증 실패"`` / ``"문법 오류"`` 등) 변경 없음.
  - 자식 env sanitizer (Wave 4-I/4-J 의 ``build_child_env`` + caller-specific allowlist) 변경 없음.
  - subprocess 정책 변경 없음 (Wave 4-A ``ValidatorCommandRunner`` 그대로).
  - API 응답 모양과 ``shared/schemas.py`` 무변경 — 프런트엔드 계약/스키마 변화 0.
- 검증 근거:
  - Worktree pre-implementation RED: ``tests/test_validator_file_io_seam.py`` → **22 failed, 8 passed** (8 = 기존 호환 검증 테스트 — 어댑터 도입 *전* 에도 통과해야 정상). 22 실패의 핵심 메시지: ``ModuleNotFoundError: No module named 'validator.file_io'`` 와 ``assert 'file_io' in mappingproxy(...)`` (생성자 시그니처 미반영) 등.
  - Worktree post-implementation targeted: ``tests/test_validator_file_io_seam.py`` → **30 passed in 0.08s**.
  - Worktree broader targeted: ``tests/test_validator_file_io_seam.py`` ``tests/test_validator_sandbox_hardening.py`` ``tests/test_security_checker.py`` ``tests/test_syntax_checker.py`` ``tests/test_validator_command_runner_adapter.py`` ``tests/test_bandit_file_io_seam.py`` ``tests/test_semgrep_file_io_seam.py`` → **129 passed in 0.44s**.
  - Worktree full: ``pytest tests/ -q`` → **765 passed, 5 warnings in 36.08s** (Wave 4-N 시점 735 → +30 신규 회귀 테스트).
  - Worktree security/schema scans: 변경 diff 에 secret-like 값 부재, 신규 추가 라인에서 ``shell=True`` / ``os.system`` / ``os.popen`` / ``eval`` / ``exec`` / ``pickle.loads`` / ``subprocess.run`` 직접 호출 부재, ``shared/schemas.py`` diff 0. 직접 ``open(..., 'w')`` / ``.write(...)`` / ``NamedTemporaryFile`` 호출은 의도대로 ``validator/file_io.py`` 에만 존재.
  - 실 외부 호출 0건. push / PR / deploy / production DB / 실 외부 Dallo 호출 / 실 flake8 / 실 pytest sandbox / 실 Bandit/Semgrep / network 호출 모두 수행되지 않았다.
- 명시적 비적용 (의도적 비행동):
  - DB clock/deprecation 정리 비적용 (Wave 4-P 후보 범위, ``db/models.py`` / ``db/service.py`` / ``api/services/*`` datetime 정책 무변경).
  - dormant ``integrations/github_client.py`` HTTP seam 비적용 (Wave 4-Q 후보 범위).
  - ``shared/schemas.py`` / ``shared/command_env.py`` 변경 없음.
  - ``analyzer/file_io.py`` 무변경 — analyzer/validator 의 의존 방향 분리 유지.
  - subprocess/env 정책 변경 없음.
  - API / frontend / schema 계약 변경 없음.
  - push / PR / deploy / production DB / external service 호출 없음 (정책 유지).
- Rollback: `git revert -m 1 <merge-sha>` (구현 커밋만 되돌릴 경우 `git revert <impl-sha>`). 되돌리면 validator 측 file write seam 회귀 가드는 사라지지만, 운영 시 세 모듈이 stdlib ``open`` / ``NamedTemporaryFile`` 을 직접 호출하던 상태로 돌아가 동작 자체는 동일하다. 호출자는 두 모드 모두에서 호환된다.
- 초보자용 설명: "validator 의 세 모듈은 LLM 이 생성한 수정 코드를 검증하기 위해 ‘sandbox 디렉토리 안의 타깃 파일에 코드를 쓴다’ (TestRunner), ‘재검증용 fixed/original 임시 파일에 코드를 쓴다’ (SecurityChecker), ‘flake8 에 넘길 .py 임시 파일에 코드를 쓴다’ (SyntaxChecker) 라는 세 종류의 파일 쓰기를 직접 stdlib ``open`` / ``NamedTemporaryFile`` 로 처리해 왔다. Wave 4-O 는 그 세 쓰기 동작만 ``validator/file_io.py`` 라는 작은 어댑터로 모았다. 세 클래스는 평소에는 그 어댑터의 기본 인스턴스를 lazy 하게 받아 그대로 쓰지만(즉 운영 동작은 한 줄도 바뀌지 않음), 테스트는 ``TestRunner(file_io=fake)`` 처럼 가짜 ``FileIO`` 를 끼워넣어 실제 디스크에 쓰지 않고도 ‘정확히 어떤 경로/내용이 들어갔는가’ 를 즉시 검증할 수 있다. analyzer 측 파일 I/O seam (Wave 4-N) 과 같은 패턴이지만 의존 방향 격리를 위해 validator 전용 어댑터를 따로 두었다."

---

## 9. 보안 강화 관점 요약

이 절은 Wave 2-S → Wave 4-O 를 보안 관점으로 다시 본다.

### 9.1 무엇이 줄어들었나

- **secret 누출 경로 감소**
  - argv exposure: Sonar 토큰이 `-Dsonar.token=...` 로 argv 에 들어가던 위험 제거(Wave 4-D).
  - ambient env leakage: 부모 env 의 secret-like 변수가 자식 도구로 묵시 상속되던 위험 제거(Wave 4-E ~ 4-I). Wave 4-H 는 pip-audit/npm 의 사설 레지스트리·자격증명 변수까지 ambient 상속을 차단하고 `AUTH` substring 기반 deny 보강을 추가했고, Wave 4-I 는 validator 의 flake8 와 sandbox pytest 자식 프로세스까지 같은 sanitizer 를 적용해 LLM 이 생성한 코드가 부모 env 의 ``ANTHROPIC_API_KEY`` / ``GITHUB_TOKEN`` / ``DALLO_ENCRYPTION_KEY`` / ``DALLO_API_KEYS`` 같은 시크릿에 닿지 못하게 했다. Wave 4-J 는 동일한 sanitizer 의 의존 방향을 정정했다 — 정책/동작은 그대로 두면서 ``shared/command_env.py`` 로 옮겨 analyzer/validator 가 평등하게 의존하도록 만들고, 외부 caller 호환성을 위한 shim 만 ``analyzer/command_env.py`` 에 남겼다 (보안 정책 변화 없음, 의존 그래프만 정정).
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
- Wave 4-M 이후로는 ``DalloAgent`` 의 retry 대기(``self._sleeper``) 까지 fake 로 교체 가능해, 단위 테스트가 “rate-limit 에 걸려서 3 초 기다리고 재시도한다” 같은 시나리오를 실제 wall-clock 대기 없이 즉시 검증한다. 즉 fake seam 의 적용 범위가 외부 명령/HTTP 에서 *시계 경계(time boundary)* 까지 확장되어, 테스트가 진짜 Gemini/OpenRouter 호출이나 실제 ``time.sleep`` 부수효과를 일으킬 가능성도 0 에 가깝게 줄어들었다.
- Wave 4-N 이후로는 ``BanditRunner`` / ``SemgrepRunner`` 의 결과 파일 쓰기와 Semgrep snippet 원본 라인 읽기까지 fake ``FileIO`` 로 교체 가능해, 단위 테스트가 “결과 JSON 이 정확한 경로/포맷으로 쓰일까”, “snippet 윈도우가 어떻게 잡힐까” 를 실제 디스크 부수효과 없이 즉시 검증한다. 즉 fake seam 의 적용 범위가 *파일 시스템 경계(file-system boundary)* 까지 확장되어, 테스트가 실제 파일 쓰기/읽기로 인한 부수효과(임시 파일 잔류, OS 별 줄바꿈/인코딩 차이) 를 일으킬 가능성도 0 에 가깝게 줄어들었다.
- Wave 4-O 이후로는 validator 측 (``TestRunner`` sandbox 타깃 쓰기, ``SecurityChecker`` fixed/original 임시 쓰기, ``SyntaxChecker`` flake8 ``.py`` 임시 쓰기) 까지 같은 패턴으로 fake ``FileIO`` 교체가 가능해, LLM 이 생성한 코드가 sandbox-내부 경로로만 들어가는지 / 보안 재검증 임시 파일이 정확한 이름·내용으로 만들어지는지 / flake8 임시 파일이 정확한 suffix·content 로 쓰이는지를 실제 디스크 쓰기 없이 즉시 검증한다. analyzer/validator 양쪽 모두에 “파일 시스템 어댑터” 패턴이 균일하게 적용된 셈이다 (validator 측 어댑터는 의존 방향 격리를 위해 ``analyzer/file_io.py`` 와 별도로 ``validator/file_io.py`` 에 둔다).
- 이 구조 덕분에 “테스트가 비밀을 흘리거나 외부에 부수효과를 일으킬 가능성” 자체가 거의 0 이 된다.

### 9.4 GitHub push 를 미루고 있는 이유 (의도된 비행동)

- 모든 Wave 의 검증/문서/테스트 정책은 “local main 에만 머지하고, push 는 사용자 명시 승인 시에만 수행” 으로 운영되었다.
- 이는 다음 이유에서 의도적이다.
  - PR/외부 가시 행위는 되돌리기 어렵다.
  - 보안 강화 wave 는 외부에 알릴 시점이 별도 결정 사안이다.
  - 사용자가 직접 push/PR 시점을 통제하도록 둔다.
- 현재 상태에서도 모든 Wave 는 local revert 한 번으로 되돌릴 수 있다.

---

## 10. 현재 상태 (Wave 4-O 시점)

- 로컬 `main` 에 Wave 4-N 머지 커밋 `660c810` 까지 포함되었다 (Wave 4-N 구현 커밋 `36627f7`, 그 직전 Wave 4-M 머지 커밋 `b842b21` / Wave 4-M 구현 커밋 `0d1a39e`).
  - Wave 4-O 는 Wave 4-N 머지 후의 docs 동기화 커밋(`718ee19`) 위에 단일 구현 커밋으로 worktree `/home/ubuntu/dallo-worktrees/w4o-validator-file-io-seam` (브랜치 `w4o-validator-file-io-seam`) 에서 추가되었으며, 본 worktree 머지 커밋은 아직 생성되지 않은 상태다 (Hermes local merge 대기 중). push / PR / deploy 는 수행되지 않았다 (정책 유지).
- 본 head 는 **로컬에만 존재** 하며 원격으로 push 되지 않았고, PR / deploy / production DB / 실 외부 Dallo 호출 / 실 LLM 호출 / 실 Bandit/Semgrep / 실 flake8 / 실 sandbox pytest / network 호출도 수행되지 않았다.
- 마지막 검증된 targeted 테스트 결과 (worktree pre-merge): `tests/test_validator_file_io_seam.py` → **30 passed in 0.08s**.
  - 마지막 검증된 broader targeted 테스트 결과 (worktree pre-merge): ``tests/test_validator_file_io_seam.py`` ``tests/test_validator_sandbox_hardening.py`` ``tests/test_security_checker.py`` ``tests/test_syntax_checker.py`` ``tests/test_validator_command_runner_adapter.py`` ``tests/test_bandit_file_io_seam.py`` ``tests/test_semgrep_file_io_seam.py`` → **129 passed in 0.44s**.
  - 마지막 검증된 full 테스트 결과 (worktree pre-merge): ``pytest tests/ -q`` → **765 passed, 5 warnings in 36.08s**. Wave 4-N 시점 735 → +30 신규 회귀 테스트 (``tests/test_validator_file_io_seam.py``). 5 warnings 는 Wave 4-J/4-K/4-L/4-M/4-N 과 동일한 기존 SQLAlchemy ``datetime.datetime.utcnow()`` deprecation + asyncio no-current-event-loop 경고로, 본 wave 의 blocker 가 아니다.
- Worktree 보안 스캔: 변경 diff 의 secret-like 값 0건, 신규 추가 라인 dangerous 호출(``shell=True`` / ``os.system`` / ``os.popen`` / ``eval`` / ``exec`` / ``pickle.loads`` / ``subprocess.run`` 직접) 0건, ``shared/schemas.py`` diff 0. 직접 ``open(..., 'w')`` / ``.write(...)`` / ``NamedTemporaryFile`` 호출은 의도대로 ``validator/file_io.py`` 에만 존재 (정적 가드 회귀 테스트가 양방향으로 보장). 본 wave 는 외부 동작 / 정책 변경이 없고 세 validator 클래스 생성자에 keyword-only ``file_io`` 자리를 추가하고 sandbox/임시 쓰기를 ``self._file_io`` 로 통과시킨 변경만 다룬다. ``shared/schemas.py`` / ``shared/command_env.py`` / ``analyzer/file_io.py`` / API / frontend 변경 없음.
- Rollback: `git revert -m 1 <merge-sha>` (구현 커밋만 되돌릴 경우 `git revert <impl-sha>`). 머지 후 갱신 예정.
- 다음 권장 작업 후보 (어느 것도 아직 승인된 wave 가 아님 — 후보 단계):
  - **Wave 4-P (후보)** DB clock seam: DB 서비스 계층의 시계 의존(``datetime.now`` / ``utcnow``) 을 sleeper-adapter 와 동일 패턴으로 fakeable 화.
  - **Wave 4-Q (후보)** dormant GitHub client HTTP seam: 휴면 상태인 ``integrations/github_client.py`` 의 HTTP 경계를 ``github_pr_comment_adapter`` 와 동일한 어댑터 패턴으로 정리할지 검토.
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

*문서 버전: Wave 4-O 시점 (2026-05-08).*
