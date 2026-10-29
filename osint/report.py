"""report.py — OSINT 报告生成。

从 OsintResult 生成结构化 Markdown 报告。

用法:
    from osint.report import generate_report
    md = generate_report(result)
"""

from __future__ import annotations

from .runner import OsintResult


def generate_report(results: OsintResult | dict) -> str:
    """从 OSINT 结果生成结构化 Markdown 报告。

    Args:
        results: OsintResult 或 to_dict() 输出

    Returns 格式化的 Markdown 字符串。
    """
    if isinstance(results, OsintResult):
        data = results.to_dict()
    else:
        data = results

    lines: list[str] = []
    target = data.get("target", "")
    target_type = data.get("target_type", "")
    search_time = data.get("search_time", 0)
    errors = data.get("errors", [])

    lines.append(f"# OSINT 报告：{target}")
    lines.append("")
    lines.append("## 1. 目标摘要")
    lines.append("")
    lines.append(f"| 字段 | 值 |")
    lines.append(f"|------|----|")
    lines.append(f"| 目标 | {target} |")
    lines.append(f"| 类型 | {target_type} |")
    lines.append(f"| 耗时 | {search_time:.1f}s |")
    if errors:
        lines.append(f"| 错误 | {len(errors)} 个 |")
    lines.append("")

    # 邮箱情报
    email_data = data.get("email")
    if email_data:
        lines.append("## 2. 邮箱情报")
        lines.append("")
        fmt = email_data.get("format", {})
        lines.append("| 项目 | 结果 |")
        lines.append("|------|------|")
        lines.append(f"| 语法有效 | {'✓' if fmt.get('syntax_valid') else '✗'} |")
        lines.append(f"| MX 记录 | {'✓' if fmt.get('has_mx') else '✗'} |")
        lines.append(f"| 临时邮箱 | {'✓' if fmt.get('disposable') else '✗'} |")
        lines.append(f"| 域名 | {fmt.get('domain', '')} |")
        lines.append("")

        rep = email_data.get("reputation")
        if rep:
            lines.append("### EmailRep.io 信誉")
            lines.append("")
            lines.append(f"- 信誉等级: {rep.get('reputation', '(无)')}")
            lines.append(f"- 可疑: {'✓' if rep.get('suspicious') else '✗'}")
            lines.append(f"- 黑名单: {'✓' if rep.get('blacklisted') else '✗'}")
            lines.append("")

        hibp = email_data.get("hibp")
        if hibp:
            lines.append("### HaveIBeenPwned 泄露记录")
            lines.append("")
            lines.append(f"泄露次数: {hibp.get('total_breaches', 0)}")
            for b in hibp.get("breaches", []):
                lines.append(f"- **{b.get('title')}** ({b.get('breach_date')})")
                lines.append(f"  - 域名: {b.get('domain')}")
                lines.append(f"  - 泄露数据: {', '.join(b.get('data_classes', []))}")
                lines.append(f"  - 受影响账户: {b.get('pwn_count', 0)}")
            lines.append("")

        hunter = email_data.get("hunter")
        if hunter:
            lines.append("### Hunter.io 验证")
            lines.append("")
            lines.append(f"- 置信度: {hunter.get('score', 0)}/100")
            lines.append(f"- 姓名: {hunter.get('first_name', '')} {hunter.get('last_name', '')}")
            lines.append(f"- 职位: {hunter.get('position', '(未知)')}")
            lines.append(f"- 临时邮箱: {'✓' if hunter.get('disposable') else '✗'}")
            lines.append("")

        guessed = email_data.get("guessed_patterns", [])
        if guessed:
            lines.append("### 猜测邮箱")
            lines.append("")
            for g in guessed[:10]:
                lines.append(f"- `{g}`")
            lines.append("")

    # 用户名搜索
    username_data = data.get("username")
    if username_data:
        lines.append("## 3. 跨平台用户名搜索")
        lines.append("")
        lines.append(f"用户名: `{username_data.get('username', '')}`")
        lines.append(f"检查平台: {username_data.get('total_checked', 0)} 个")
        lines.append(f"发现: {username_data.get('total_found', 0)} 个")
        lines.append("")
        lines.append("| 平台 | 状态 | URL |")
        lines.append("|------|------|-----|")
        for pr in username_data.get("found_on", []):
            lines.append(f"| {pr.get('platform')} | ✓ 存在 | {pr.get('profile_url')} |")
        for pr in username_data.get("not_found_on", []):
            if pr.get("error"):
                lines.append(f"| {pr.get('platform')} | ⚠ {pr.get('error')} | {pr.get('profile_url')} |")
        lines.append("")

    # 域名情报
    domain_data = data.get("domain")
    if domain_data:
        lines.append("## 4. 域名情报")
        lines.append("")
        lines.append(f"域名: `{domain_data.get('domain', '')}`")
        lines.append("")

        whois = domain_data.get("whois")
        if whois:
            lines.append("### WHOIS 注册信息")
            lines.append("")
            lines.append(f"- 注册商: {whois.get('registrar', '(未知)')}")
            lines.append(f"- 创建日期: {whois.get('creation_date', '(未知)')}")
            lines.append(f"- 过期日期: {whois.get('expiration_date', '(未知)')}")
            lines.append(f"- 组织: {whois.get('registrant_org', '(未公开)')}")
            if whois.get('registrant_email'):
                lines.append(f"- 注册人邮箱: {whois.get('registrant_email')}")
            lines.append("")

        dns_records = domain_data.get("dns_records", [])
        if dns_records:
            lines.append("### DNS 记录")
            lines.append("")
            by_type: dict[str, list[str]] = {}
            for r in dns_records:
                by_type.setdefault(r.get("type", ""), []).append(r.get("value", ""))
            for t, vals in sorted(by_type.items()):
                for v in vals[:5]:
                    lines.append(f"- [{t}] {v}")
                if len(vals) > 5:
                    lines.append(f"  ... 还有 {len(vals) - 5} 条")
            lines.append("")

        certs = domain_data.get("certificates", [])
        if certs:
            lines.append("### 证书透明度 (crt.sh)")
            lines.append("")
            lines.append(f"发现 {len(certs)} 张证书")
            for c in certs[:5]:
                lines.append(f"- CN: {c.get('common_name', '')}")
            lines.append("")

        wayback = domain_data.get("wayback_snapshots", [])
        if wayback:
            lines.append("### Wayback Machine 历史快照")
            lines.append("")
            for w in wayback[:5]:
                lines.append(f"- [{w.get('status_code')}] {w.get('snapshot_url', '')}")
            lines.append("")

    # 社交媒体情报
    social_data = data.get("social")
    if social_data:
        lines.append("## 5. 社交媒体情报")
        lines.append("")

        gh = social_data.get("github")
        if gh:
            lines.append("### GitHub 用户资料")
            lines.append("")
            lines.append(f"- 登录: {gh.get('login', '')}")
            lines.append(f"- 名称: {gh.get('name', '(未设置)')}")
            lines.append(f"- 邮箱: {gh.get('email', '(未公开)')}")
            lines.append(f"- 公司: {gh.get('company', '-')}")
            lines.append(f"- 位置: {gh.get('location', '-')}")
            lines.append(f"- 简介: {gh.get('bio', '-')}")
            lines.append(f"- 仓库: {gh.get('public_repos', 0)} 个")
            lines.append(f"- 关注者: {gh.get('followers', 0)}")
            if gh.get("organizations"):
                lines.append(f"- 组织: {', '.join(gh['organizations'])}")
            lines.append(f"- 创建: {gh.get('created_at', '')}")
            lines.append(f"- 链接: {gh.get('html_url', '')}")
            lines.append("")

            repos = gh.get("repos", [])
            if repos:
                lines.append("#### 最近仓库")
                lines.append("")
                for r in repos[:5]:
                    lines.append(f"- [{r.get('language', '?')}] {r.get('name', '')} ★{r.get('stars', 0)}")
                    lines.append(f"  {r.get('description', '(无描述)')}")
                lines.append("")

        commits = social_data.get("email_in_commits", [])
        if commits:
            lines.append("### GitHub 提交关联")
            lines.append("")
            for c in commits[:5]:
                lines.append(f"- [{c.get('repo', '')}] {c.get('message', '')[:80]}")
                lines.append(f"  {c.get('url', '')}")
            lines.append("")

    # 数据泄露
    breach_data = data.get("breach")
    if breach_data:
        lines.append("## 6. 数据泄露")
        lines.append("")
        if breach_data.get("error"):
            lines.append(f"状态: {breach_data['error']}")
        else:
            lines.append(f"来源: {breach_data.get('source', '(未知)')}")
            lines.append(f"泄露次数: {breach_data.get('total_breaches', 0)}")
            lines.append("")
            if breach_data.get("breaches"):
                lines.append("| 泄露事件 | 日期 | 数据类型 | 影响账户 |")
                lines.append("|----------|------|----------|----------|")
                for b in breach_data["breaches"]:
                    lines.append(
                        f"| {b.get('title', '')} | {b.get('breach_date', '')} | "
                        f"{', '.join(b.get('data_classes', [])[:3])} | {b.get('pwn_count', 0)} |"
                    )
        lines.append("")

    # 页脚
    lines.append("---")
    lines.append("*由 FrogHacker osint 模块生成*")
    lines.append("")

    return "\n".join(lines)
