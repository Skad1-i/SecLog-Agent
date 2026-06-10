from datetime import datetime
from pathlib import Path


def format_attack_stats(attack_stats):
    """将攻击类型统计转为 Markdown 表格。"""
    if not attack_stats:
        return "未发现命中规则的攻击类型。\n"

    lines = ["| 攻击类型 | 命中次数 |", "| --- | ---: |"]
    for attack_type, count in sorted(attack_stats.items(), key=lambda item: item[1], reverse=True):
        lines.append(f"| {attack_type} | {count} |")
    return "\n".join(lines)


def format_ip_risk(ip_risk_list):
    """将 IP 风险排名转为 Markdown 表格。"""
    if not ip_risk_list:
        return "未发现可疑 IP。\n"

    lines = ["| IP | 风险等级 | 累计风险分 | 命中次数 | 攻击类型 |", "| --- | --- | ---: | ---: | --- |"]
    for item in ip_risk_list:
        lines.append(
            f"| {item.get('IP')} | {item.get('风险等级')} | {item.get('累计风险分')} | {item.get('命中次数')} | {item.get('攻击类型')} |"
        )
    return "\n".join(lines)


def format_evidence(suspicious_logs, limit=10):
    """选取风险分最高的可疑请求作为报告证据。"""
    if not suspicious_logs:
        return "暂无关键可疑请求证据。\n"

    sorted_logs = sorted(suspicious_logs, key=lambda item: item.get("risk_score", 0), reverse=True)[:limit]
    lines = [
        "| IP | 时间 | 方法 | URL | 状态码 | 攻击类型 | 风险分 |",
        "| --- | --- | --- | --- | ---: | --- | ---: |",
    ]
    for item in sorted_logs:
        attack_types = ", ".join(item.get("attack_types", []))
        lines.append(
            f"| {item.get('ip')} | {item.get('time')} | {item.get('method')} | `{item.get('url')}` | {item.get('status')} | {attack_types} | {item.get('risk_score', 0)} |"
        )
    return "\n".join(lines)


def generate_markdown_report(source_name, basic_stats, attack_stats, ip_risk_list, suspicious_logs, ai_summary):
    """生成完整 Markdown 安全分析报告。"""
    now_text = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    return f"""# SecLog-Agent Web 日志安全分析报告

生成时间：{now_text}

日志来源：`{source_name}`

## 一、分析概况

| 指标 | 数值 |
| --- | ---: |
| 总请求数 | {basic_stats.get("total_count", 0)} |
| 成功解析数量 | {basic_stats.get("parsed_count", 0)} |
| 解析失败数量 | {basic_stats.get("failed_count", 0)} |
| 可疑请求数量 | {basic_stats.get("suspicious_count", 0)} |

## 二、攻击类型统计

{format_attack_stats(attack_stats)}

## 三、可疑 IP 风险排名

{format_ip_risk(ip_risk_list)}

## 四、关键可疑请求证据

{format_evidence(suspicious_logs)}

## 五、AI 研判总结

{ai_summary}

## 六、应急排查建议

1. 按风险分从高到低核查可疑 IP 的访问轨迹。
2. 对命中命令执行、SQL 注入、Webshell 探测的请求，检查应用日志、错误日志和主机审计日志。
3. 核查被访问的敏感路径是否真实存在，确认是否发生配置文件、源码目录或后台入口暴露。
4. 对高频扫描 IP 进行临时封禁、限速或 WAF 策略拦截。

## 七、安全加固建议

1. 对输入参数使用白名单校验和参数化查询。
2. 禁止上传目录执行脚本，限制上传文件类型。
3. 隐藏或限制后台管理入口，只允许可信来源访问。
4. 禁止 Web 目录暴露 `.git`、`.env`、备份文件等敏感资源。
5. 建立日志留存、告警分级和定期复盘机制。
"""


def save_markdown_report(markdown_text, output_path="reports/security_report.md"):
    """保存 Markdown 报告，目录不存在时自动创建。"""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(markdown_text, encoding="utf-8")
    return path
