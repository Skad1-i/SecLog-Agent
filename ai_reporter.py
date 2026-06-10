import os

import requests


DEEPSEEK_API_URL = "https://api.deepseek.com/chat/completions"
DEEPSEEK_MODEL = "deepseek-v4-flash"


def build_report_prompt(basic_stats, attack_stats, ip_risk_list, suspicious_logs):
    """把日志分析结果整理成适合大模型研判的提示词。"""
    top_evidence = sorted(suspicious_logs, key=lambda item: item.get("risk_score", 0), reverse=True)[:8]

    evidence_lines = []
    for item in top_evidence:
        evidence_lines.append(
            {
                "ip": item.get("ip"),
                "time": item.get("time"),
                "method": item.get("method"),
                "url": item.get("url"),
                "status": item.get("status"),
                "attack_types": item.get("attack_types", []),
                "risk_score": item.get("risk_score", 0),
                "user_agent": item.get("user_agent"),
            }
        )

    return f"""
你是一名蓝队 SOC 安全分析师，请根据 Web access.log 的本地分析结果生成安全研判。

注意：
1. 这是防守侧日志分析工具，不要提供攻击真实目标、漏洞利用、扫描、爆破、getshell 等操作步骤。
2. 输出内容要适合作为安全分析报告的一部分。
3. 请使用中文 Markdown，包含：研判结论、关键证据、应急排查建议、安全加固建议。
4. 直接输出报告正文，不要出现“好的”“根据您提供的”等寒暄语。
5. 建议要具体，但不要指导攻击；处置建议使用临时封禁、限速、观察、核查等审慎表述，不要默认建议永久封禁。

基础统计：
{basic_stats}

攻击类型统计：
{attack_stats}

可疑 IP 风险排名：
{ip_risk_list[:10]}

关键可疑请求证据：
{evidence_lines}
""".strip()


def call_deepseek_report(prompt):
    """调用 DeepSeek API 生成研判报告。

    安全说明：
    - API Key 只从环境变量 DEEPSEEK_API_KEY 读取；
    - 不要把真实 Key 写入代码、README 或 Git 仓库；
    - 如果没有配置 Key，程序会自动回退到本地模板报告。
    """
    api_key = os.getenv("DEEPSEEK_API_KEY", "").strip()
    if not api_key:
        return None

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": DEEPSEEK_MODEL,
        "messages": [
            {
                "role": "system",
                "content": "你是一个专业、谨慎的蓝队日志分析助手，只输出防守侧研判和处置建议。直接输出报告正文，不要寒暄。",
            },
            {
                "role": "user",
                "content": prompt,
            },
        ],
        "temperature": 0.2,
        "max_tokens": 1200,
    }

    try:
        response = requests.post(DEEPSEEK_API_URL, headers=headers, json=payload, timeout=30)
        response.raise_for_status()
        result = response.json()
        return result["choices"][0]["message"]["content"].strip()
    except requests.RequestException as error:
        return f"### AI 研判生成失败\n\nDeepSeek API 调用失败，已保留本地模板研判。错误信息：`{error}`"
    except (KeyError, IndexError, TypeError) as error:
        return f"### AI 研判生成失败\n\nDeepSeek API 返回格式异常，已保留本地模板研判。错误信息：`{error}`"


def generate_template_report(basic_stats, attack_stats, ip_risk_list, suspicious_logs):
    """没有配置 DeepSeek API Key 时，使用本地模板生成研判报告。"""
    total_count = basic_stats.get("total_count", 0)
    suspicious_count = basic_stats.get("suspicious_count", 0)
    suspicious_ratio = suspicious_count / total_count * 100 if total_count else 0

    top_attack = "暂无明显攻击类型"
    if attack_stats:
        top_attack = max(attack_stats.items(), key=lambda item: item[1])[0]

    high_risk_ips = [item for item in ip_risk_list if item.get("风险等级") == "高危"]
    medium_risk_ips = [item for item in ip_risk_list if item.get("风险等级") == "中危"]

    if high_risk_ips:
        risk_judgement = f"发现 {len(high_risk_ips)} 个高危 IP，建议优先封禁或加入重点观察名单。"
    elif medium_risk_ips:
        risk_judgement = f"发现 {len(medium_risk_ips)} 个中危 IP，建议结合 WAF、主机日志继续确认。"
    else:
        risk_judgement = "暂未发现高危 IP，但仍建议持续观察异常状态码和访问频率。"

    evidence_text = "暂无明显可疑请求证据。"
    if suspicious_logs:
        top_evidence = sorted(suspicious_logs, key=lambda item: item.get("risk_score", 0), reverse=True)[:3]
        evidence_lines = []
        for item in top_evidence:
            evidence_lines.append(
                f"- {item.get('ip')} 请求 `{item.get('url')}`，命中 {', '.join(item.get('attack_types', []))}，风险分 {item.get('risk_score', 0)}。"
            )
        evidence_text = "\n".join(evidence_lines)

    return f"""
### 研判结论

本次共分析 `{total_count}` 条 Web 访问日志，其中发现 `{suspicious_count}` 条可疑请求，占比约 `{suspicious_ratio:.2f}%`。当前最主要的风险类型是 **{top_attack}**。{risk_judgement}

### 关键证据

{evidence_text}

### 应急建议

1. 优先核查高危 IP 的访问时间线，确认是否存在持续探测、批量扫描或漏洞利用尝试。
2. 对命中 SQL 注入、命令执行、Webshell 探测的请求，结合应用日志和主机日志确认是否触发真实漏洞。
3. 检查相关 URL 对应业务是否存在未授权访问、调试文件泄露、上传目录执行脚本等风险。
4. 对明显扫描器 User-Agent 和高频异常请求，可在 WAF、Nginx 或安全网关侧进行限速与拦截。

### 安全加固建议

1. 关闭不必要的后台入口和测试页面，避免 `/phpmyadmin`、`/.git/config`、`/.env` 等路径暴露。
2. 对输入参数启用服务端校验和参数化查询，降低 SQL 注入与 XSS 风险。
3. 上传目录禁止脚本执行，并对上传文件类型、后缀和内容做白名单校验。
4. 将日志接入集中化平台，保留足够时间窗口，便于安全事件回溯。
""".strip()


def generate_ai_report(basic_stats, attack_stats, ip_risk_list, suspicious_logs):
    """优先使用 DeepSeek 生成研判报告，未配置 Key 时自动使用本地模板。"""
    template_report = generate_template_report(basic_stats, attack_stats, ip_risk_list, suspicious_logs)
    prompt = build_report_prompt(basic_stats, attack_stats, ip_risk_list, suspicious_logs)
    deepseek_report = call_deepseek_report(prompt)

    if not deepseek_report:
        return template_report

    if deepseek_report.startswith("### AI 研判生成失败"):
        return f"{deepseek_report}\n\n---\n\n{template_report}"

    return deepseek_report
