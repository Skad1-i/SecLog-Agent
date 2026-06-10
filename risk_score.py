from collections import defaultdict


def get_risk_level(score):
    """根据累计分数划分 IP 风险等级。"""
    if score >= 80:
        return "高危"
    if score >= 35:
        return "中危"
    return "低危"


def calculate_ip_risk(suspicious_logs):
    """按 IP 聚合命中次数、攻击类型和累计风险分。"""
    ip_stats = defaultdict(
        lambda: {
            "IP": "",
            "命中次数": 0,
            "攻击类型": set(),
            "累计风险分": 0,
            "风险等级": "低危",
        }
    )

    for item in suspicious_logs:
        ip = item.get("ip", "-")
        score = int(item.get("risk_score", 0))
        stat = ip_stats[ip]
        stat["IP"] = ip
        stat["命中次数"] += 1
        stat["累计风险分"] += score
        stat["攻击类型"].update(item.get("attack_types", []))

    results = []
    for stat in ip_stats.values():
        # 命中次数越多，越可能是持续探测或批量攻击，因此增加一个轻量级频次加权。
        stat["累计风险分"] += max(0, stat["命中次数"] - 1) * 5
        stat["风险等级"] = get_risk_level(stat["累计风险分"])
        stat["攻击类型"] = ", ".join(sorted(stat["攻击类型"]))
        results.append(stat)

    return sorted(results, key=lambda item: item["累计风险分"], reverse=True)


def filter_high_risk_ips(ip_risk_list):
    """筛选高危 IP，供报告模块复用。"""
    return [item for item in ip_risk_list if item.get("风险等级") == "高危"]
