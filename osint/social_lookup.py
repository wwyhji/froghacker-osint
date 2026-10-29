"""social_lookup.py — 社交媒体情报收集。

数据源:
  1. GitHub 用户资料 API (公开信息)
  2. GitHub 提交搜索 (按邮箱)

用法:
    from osint.social_lookup import social_lookup
    result = social_lookup("octocat", target_type="username")
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from typing import Optional

import requests

GITHUB_API = "https://api.github.com"

_REQUEST_HEADERS = {
    "User-Agent": "FrogHackerOSINT/1.0",
    "Accept": "application/vnd.github.v3+json",
}

# ── Data Classes ────────────────────────────────────────────────


@dataclass
class GitHubUser:
    """从公共 API 获取的 GitHub 用户资料。"""
    login: str = ""
    name: str = ""
    email: str = ""
    bio: str = ""
    company: str = ""
    location: str = ""
    blog: str = ""
    public_repos: int = 0
    public_gists: int = 0
    followers: int = 0
    following: int = 0
    created_at: str = ""
    updated_at: str = ""
    avatar_url: str = ""
    html_url: str = ""
    repos: list[dict] = field(default_factory=list)
    organizations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "login": self.login,
            "name": self.name,
            "email": self.email,
            "bio": self.bio,
            "company": self.company,
            "location": self.location,
            "blog": self.blog,
            "public_repos": self.public_repos,
            "followers": self.followers,
            "following": self.following,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "avatar_url": self.avatar_url,
            "html_url": self.html_url,
            "repos": self.repos[:10],
            "organizations": self.organizations,
        }


@dataclass
class SocialIntelResult:
    """聚合的社交媒体情报结果。"""
    target: str = ""
    target_type: str = ""
    github: Optional[GitHubUser] = None
    email_in_commits: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d: dict = {
            "target": self.target,
            "target_type": self.target_type,
            "errors": self.errors,
        }
        if self.github:
            d["github"] = self.github.to_dict()
        if self.email_in_commits:
            d["email_in_commits"] = self.email_in_commits[:10]
        return d


# ── Internal Helpers ────────────────────────────────────────────


def _github_user(username: str) -> Optional[GitHubUser]:
    """查询 GitHub 用户资料。"""
    try:
        resp = requests.get(
            f"{GITHUB_API}/users/{username}",
            headers=_REQUEST_HEADERS,
            timeout=10,
        )
        if resp.status_code == 404:
            return None
        if resp.status_code != 200:
            return None

        data = resp.json()
        user = GitHubUser(
            login=data.get("login", ""),
            name=data.get("name") or "",
            email=data.get("email") or "",
            bio=data.get("bio") or "",
            company=data.get("company") or "",
            location=data.get("location") or "",
            blog=data.get("blog") or "",
            public_repos=data.get("public_repos", 0),
            public_gists=data.get("public_gists", 0),
            followers=data.get("followers", 0),
            following=data.get("following", 0),
            created_at=data.get("created_at", ""),
            updated_at=data.get("updated_at", ""),
            avatar_url=data.get("avatar_url", ""),
            html_url=data.get("html_url", ""),
        )

        # 查询仓库列表
        time.sleep(1)
        try:
            repo_resp = requests.get(
                f"{GITHUB_API}/users/{username}/repos?per_page=30&sort=updated",
                headers=_REQUEST_HEADERS,
                timeout=10,
            )
            if repo_resp.status_code == 200:
                for repo in repo_resp.json()[:10]:
                    user.repos.append({
                        "name": repo.get("name", ""),
                        "description": repo.get("description") or "",
                        "language": repo.get("language") or "",
                        "stars": repo.get("stargazers_count", 0),
                        "forks": repo.get("forks_count", 0),
                        "url": repo.get("html_url", ""),
                    })
        except requests.RequestException:
            pass

        # 查询组织
        time.sleep(0.5)
        try:
            org_resp = requests.get(
                f"{GITHUB_API}/users/{username}/orgs",
                headers=_REQUEST_HEADERS,
                timeout=10,
            )
            if org_resp.status_code == 200:
                user.organizations = [
                    org.get("login", "") for org in org_resp.json()
                ]
        except requests.RequestException:
            pass

        return user

    except requests.RequestException:
        return None


def _github_search_commits(email: str) -> list[dict]:
    """搜索 GitHub 提交历史中出现的邮箱。"""
    try:
        headers = {
            **_REQUEST_HEADERS,
            "Accept": "application/vnd.github.cloak-preview",
        }
        resp = requests.get(
            f"{GITHUB_API}/search/commits",
            params={"q": email},
            headers=headers,
            timeout=10,
        )
        if resp.status_code != 200:
            return []

        data = resp.json()
        results = []
        for item in data.get("items", [])[:10]:
            repo = item.get("repository", {})
            commit = item.get("commit", {})
            author = commit.get("author", {})
            results.append({
                "message": commit.get("message", "")[:100],
                "author": author.get("name", ""),
                "date": author.get("date", ""),
                "repo": repo.get("full_name", ""),
                "repo_url": repo.get("html_url", ""),
                "url": item.get("html_url", ""),
            })

        return results

    except requests.RequestException:
        return []


# ── Public API ──────────────────────────────────────────────────


def social_lookup(
    target: str,
    target_type: str = "auto",
    check_github: bool = True,
) -> SocialIntelResult:
    """社交媒体情报收集。

    处理两种模式：
    - "username": 查询 GitHub API 获取用户资料 + 仓库
    - "email":    搜索 GitHub 提交中的邮箱地址

    Args:
        target:       用户名或邮箱
        target_type:  目标类型 ("email" / "username" / "auto")
        check_github: 是否查询 GitHub

    Returns SocialIntelResult.
    """
    import re

    if target_type == "auto":
        target_type = "email" if "@" in target else "username"

    result = SocialIntelResult(target=target, target_type=target_type)

    if target_type == "username" and check_github:
        print(f"  [GitHub] 查询用户资料: {target}")
        user = _github_user(target)
        if user:
            result.github = user
            print(f"    登录: {user.login}")
            print(f"    名称: {user.name or '(未设置)'}")
            print(f"    邮箱: {user.email or '(未公开)'}")
            print(f"    公司: {user.company or '-'}")
            print(f"    位置: {user.location or '-'}")
            print(f"    仓库: {user.public_repos} 个")
            print(f"    关注者: {user.followers}")
            if user.organizations:
                print(f"    组织: {', '.join(user.organizations)}")
            if user.repos:
                print(f"    最近仓库:")
                for r in user.repos[:5]:
                    print(f"      - {r['name']:25s} *{r['stars']}  {r['language'] or '-'}")
        else:
            print(f"    (未找到或查询失败)")

    elif target_type == "email" and check_github:
        print(f"  [GitHub] 搜索提交记录中的邮箱: {target}")
        commits = _github_search_commits(target)
        if commits:
            result.email_in_commits = commits
            print(f"    发现 {len(commits)} 条关联提交:")
            for c in commits[:5]:
                print(f"      [{c['repo']}] {c['message'][:60]}")
        else:
            print(f"    (未找到关联提交)")

    return result
