import os
from typing import Dict, List, Optional

import requests


class GithubIssueIntegration:
    def __init__(self, token: str, repo: str) -> None:
        self.token = token
        self.repo = repo
        self.base = f"https://api.github.com/repos/{repo}"

    def create_issue_for_finding(self, finding: Dict) -> Optional[int]:
        title = f"[{finding.get('severity', 'unknown').upper()}] {finding.get('package')} {finding.get('vulnerability_id', finding.get('cve', ''))}"
        body = self._issue_body(finding)
        response = requests.post(
            f"{self.base}/issues",
            headers={
                "Authorization": f"Bearer {self.token}",
                "Accept": "application/vnd.github+json",
            },
            json={"title": title, "body": body, "labels": ["security", "sec-mapper"]},
            timeout=10,
        )
        if response.status_code >= 300:
            return None
        return response.json().get("number")

    def _issue_body(self, finding: Dict) -> str:
        return "\n".join(
            [
                "## Sec Mapper Finding",
                f"- Package: {finding.get('package')}@{finding.get('version')}",
                f"- Vulnerability: {finding.get('vulnerability_id', finding.get('cve'))}",
                f"- Severity: {finding.get('severity')}",
                f"- Confidence: {finding.get('confidence')} ({finding.get('confidence_score')})",
                f"- Dependency path: {' > '.join(finding.get('dependency_path', []))}",
                f"- Fixed version: {finding.get('fixed_version') or 'N/A'}",
                f"- Mitigation: {finding.get('remediation_recommendation')}",
                f"- Evidence: {'; '.join(finding.get('evidence', []))}",
            ]
        )


class JiraIntegration:
    def __init__(self, base_url: str, user: str, token: str, project_key: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.user = user
        self.token = token
        self.project_key = project_key

    def create_ticket_for_finding(self, finding: Dict) -> Optional[str]:
        payload = {
            "fields": {
                "project": {"key": self.project_key},
                "summary": f"[{finding.get('severity', 'unknown').upper()}] {finding.get('package')} {finding.get('vulnerability_id', finding.get('cve', ''))}",
                "description": self._description(finding),
                "issuetype": {"name": "Task"},
            }
        }
        response = requests.post(
            f"{self.base_url}/rest/api/2/issue",
            auth=(self.user, self.token),
            headers={"Content-Type": "application/json"},
            json=payload,
            timeout=10,
        )
        if response.status_code >= 300:
            return None
        return response.json().get("key")

    def _description(self, finding: Dict) -> str:
        lines = [
            "Sec Mapper finding",
            f"Package: {finding.get('package')}@{finding.get('version')}",
            f"Vulnerability: {finding.get('vulnerability_id', finding.get('cve'))}",
            f"Severity: {finding.get('severity')}",
            f"Confidence: {finding.get('confidence')} ({finding.get('confidence_score')})",
            f"Dependency path: {' > '.join(finding.get('dependency_path', []))}",
            f"Fixed version: {finding.get('fixed_version') or 'N/A'}",
            f"Mitigation: {finding.get('remediation_recommendation')}",
            f"Evidence: {'; '.join(finding.get('evidence', []))}",
        ]
        return "\n".join(lines)


def auto_create_high_severity_issues(scan_result: Dict, provider: str = "github") -> List[str]:
    created: List[str] = []
    findings = [
        f
        for f in scan_result.get("findings", [])
        if (f.get("severity") or "").lower() in {"critical", "high"}
    ]

    if provider == "github":
        token = os.getenv("SEC_MAPPER_GH_TOKEN")
        repo = os.getenv("SEC_MAPPER_GH_REPO")
        if not token or not repo:
            return created
        integration = GithubIssueIntegration(token=token, repo=repo)
        for finding in findings:
            issue = integration.create_issue_for_finding(finding)
            if issue:
                created.append(f"github#{issue}")
        return created

    if provider == "jira":
        base = os.getenv("SEC_MAPPER_JIRA_URL")
        user = os.getenv("SEC_MAPPER_JIRA_USER")
        token = os.getenv("SEC_MAPPER_JIRA_TOKEN")
        project = os.getenv("SEC_MAPPER_JIRA_PROJECT")
        if not all([base, user, token, project]):
            return created
        integration = JiraIntegration(base_url=base, user=user, token=token, project_key=project)
        for finding in findings:
            key = integration.create_ticket_for_finding(finding)
            if key:
                created.append(key)
    return created
