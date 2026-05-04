"""
GitHub API 연동 클라이언트 (Wave 4-C 기준 보류/미사용 모듈)

[상태]
- Wave 4-C 시점, 본 저장소 및 워크플로우에는 이 모듈을 호출하는
  active caller가 존재하지 않습니다 (audit 완료).
- 운영 중인 PR 코멘트 경로는 다음과 같으며, 본 모듈을 사용하지 않습니다:
    scripts/post_pr_comment.py
      → integrations/github_pr_comment_adapter.py

[보존 사유]
- 향후 GitHub 통합 확장 시 사용할 수 있는 surface(예: PR 메타데이터/변경
  파일 조회, 라인 단위 review comment, Check Run API, GitHub Actions
  이벤트 파서)를 deferred/legacy 형태로 보관합니다.

[활성화 전 필요 작업]
- fakeable HTTP client seam 도입 (Wave 4-B 어댑터 패턴 참고)
- 모든 외부 호출에 대한 timeout 명시
- 단위 테스트 추가 (성공/실패/네트워크 오류 경로 포함)
- 토큰 비누출 확인 (로그/예외 메시지에 token 노출 금지)

활성화 전에는 read-only audit/refactor 대상이며, 신규 코드에서 직접
import 하지 마십시오.
"""

import os
import json
import requests
from dataclasses import dataclass
from typing import Optional


@dataclass
class PRInfo:
    """Pull Request 정보"""
    owner: str
    repo: str
    pr_number: int
    head_sha: str
    base_branch: str
    head_branch: str
    title: str
    changed_files: list[str]


class GitHubClient:
    """GitHub API 클라이언트"""

    BASE_URL = "https://api.github.com"

    def __init__(self, token: Optional[str] = None):
        self.token = token or os.environ.get("GITHUB_TOKEN", "")
        self.headers = {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/vnd.github.v3+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    def get_pr_info(self, owner: str, repo: str, pr_number: int) -> PRInfo:
        """PR 기본 정보 조회"""
        url = f"{self.BASE_URL}/repos/{owner}/{repo}/pulls/{pr_number}"
        resp = requests.get(url, headers=self.headers)
        resp.raise_for_status()
        data = resp.json()

        # 변경된 파일 목록
        files_url = f"{url}/files"
        files_resp = requests.get(files_url, headers=self.headers)
        files_resp.raise_for_status()
        changed_files = [f["filename"] for f in files_resp.json()]

        return PRInfo(
            owner=owner,
            repo=repo,
            pr_number=pr_number,
            head_sha=data["head"]["sha"],
            base_branch=data["base"]["ref"],
            head_branch=data["head"]["ref"],
            title=data["title"],
            changed_files=changed_files,
        )

    def get_changed_python_files(self, owner: str, repo: str, pr_number: int) -> list[str]:
        """PR에서 변경된 Python 파일만 추출"""
        pr_info = self.get_pr_info(owner, repo, pr_number)
        return [f for f in pr_info.changed_files if f.endswith(".py")]

    def create_pr_comment(self, owner: str, repo: str, pr_number: int, body: str) -> dict:
        """PR에 일반 코멘트 작성"""
        url = f"{self.BASE_URL}/repos/{owner}/{repo}/issues/{pr_number}/comments"
        payload = {"body": body}
        resp = requests.post(url, headers=self.headers, json=payload)
        resp.raise_for_status()
        return resp.json()

    def create_review_comment(
        self,
        owner: str,
        repo: str,
        pr_number: int,
        body: str,
        commit_id: str,
        path: str,
        line: int,
    ) -> dict:
        """PR의 특정 코드 라인에 리뷰 코멘트 작성"""
        url = f"{self.BASE_URL}/repos/{owner}/{repo}/pulls/{pr_number}/comments"
        payload = {
            "body": body,
            "commit_id": commit_id,
            "path": path,
            "line": line,
        }
        resp = requests.post(url, headers=self.headers, json=payload)
        resp.raise_for_status()
        return resp.json()

    def create_check_run(
        self,
        owner: str,
        repo: str,
        head_sha: str,
        name: str,
        status: str,
        conclusion: Optional[str] = None,
        summary: str = "",
        text: str = "",
    ) -> dict:
        """Check Run 생성 (PR 상태 표시)"""
        url = f"{self.BASE_URL}/repos/{owner}/{repo}/check-runs"
        payload = {
            "name": name,
            "head_sha": head_sha,
            "status": status,
            "output": {
                "title": name,
                "summary": summary,
                "text": text,
            },
        }
        if conclusion:
            payload["conclusion"] = conclusion

        resp = requests.post(url, headers=self.headers, json=payload)
        resp.raise_for_status()
        return resp.json()

    @staticmethod
    def from_github_event() -> tuple[str, str, int]:
        """GitHub Actions 환경에서 이벤트 정보 추출"""
        event_path = os.environ.get("GITHUB_EVENT_PATH", "")
        if not event_path or not os.path.exists(event_path):
            raise RuntimeError("GITHUB_EVENT_PATH가 설정되지 않았습니다.")

        with open(event_path, "r") as f:
            event = json.load(f)

        repo_full = os.environ.get("GITHUB_REPOSITORY", "")
        if "/" not in repo_full:
            raise RuntimeError("GITHUB_REPOSITORY 형식이 올바르지 않습니다.")

        owner, repo = repo_full.split("/", 1)
        pr_number = event.get("pull_request", {}).get("number")

        if not pr_number:
            raise RuntimeError("Pull Request 이벤트가 아닙니다.")

        return owner, repo, pr_number
