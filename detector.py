import re
from collections import Counter
from pathlib import Path
from urllib.parse import unquote_plus

import yaml


def load_rules(rule_path="rules.yaml"):
    """从 rules.yaml 加载检测规则，后续新增规则只需要改配置文件。"""
    path = Path(rule_path)
    with path.open("r", encoding="utf-8") as file:
        return yaml.safe_load(file) or {}


def normalize_text(text):
    """对 URL、Referer、User-Agent 做简单归一化，提升规则命中率。"""
    if text is None:
        return ""
    decoded_text = unquote_plus(str(text))
    return decoded_text.lower()


def match_single_rule(log_item, rule):
    """判断单条日志是否命中某个规则。"""
    target_fields = rule.get("fields", ["url"])
    patterns = rule.get("patterns", [])

    for field in target_fields:
        field_text = normalize_text(log_item.get(field, ""))
        for pattern in patterns:
            if re.search(pattern, field_text, re.IGNORECASE):
                return True
    return False


def detect_attacks(log_item, rules):
    """检测单条日志命中的攻击类型和规则名称。"""
    if not log_item.get("parsed"):
        return []

    matched_results = []
    for rule in rules.get("rules", []):
        if match_single_rule(log_item, rule):
            matched_results.append(
                {
                    "attack_type": rule.get("attack_type", "未知风险"),
                    "rule_name": rule.get("name", "未命名规则"),
                    "severity": rule.get("severity", "低危"),
                    "score": int(rule.get("score", 10)),
                    "description": rule.get("description", ""),
                }
            )

    return matched_results


def analyze_logs(parsed_logs, rules):
    """批量分析日志，返回可疑请求列表和攻击类型统计。"""
    suspicious_logs = []
    attack_counter = Counter()

    for log_item in parsed_logs:
        matched_rules = detect_attacks(log_item, rules)
        if not matched_rules:
            continue

        attack_types = sorted({item["attack_type"] for item in matched_rules})
        rule_names = [item["rule_name"] for item in matched_rules]
        risk_score = sum(item["score"] for item in matched_rules)

        enriched_log = dict(log_item)
        enriched_log.update(
            {
                "matched_rules": matched_rules,
                "attack_types": attack_types,
                "rule_names": rule_names,
                "risk_score": risk_score,
            }
        )
        suspicious_logs.append(enriched_log)

        for attack_type in attack_types:
            attack_counter[attack_type] += 1

    return suspicious_logs, dict(attack_counter)
