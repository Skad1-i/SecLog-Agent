import os
from pathlib import Path

import pandas as pd
import streamlit as st

from ai_reporter import generate_ai_report
from detector import analyze_logs, load_rules
from log_parser import parse_log_lines
from report_generator import generate_markdown_report, save_markdown_report
from risk_score import calculate_ip_risk


BASE_DIR = Path(__file__).resolve().parent
SAMPLE_LOG_PATH = BASE_DIR / "samples" / "access.log"
REPORT_PATH = BASE_DIR / "reports" / "security_report.md"
RULES_PATH = BASE_DIR / "rules.yaml"


def read_uploaded_file(uploaded_file):
    """读取 Streamlit 上传的日志文件，并按行返回文本内容。"""
    content = uploaded_file.read().decode("utf-8", errors="ignore")
    return content.splitlines()


def read_sample_log():
    """读取项目自带的示例日志，方便用户第一次运行时直接体验。"""
    return SAMPLE_LOG_PATH.read_text(encoding="utf-8").splitlines()


def build_basic_stats(parsed_logs, suspicious_logs):
    """汇总页面和报告都需要使用的基础统计数据。"""
    total_count = len(parsed_logs)
    parsed_count = sum(1 for item in parsed_logs if item.get("parsed"))
    suspicious_count = len(suspicious_logs)

    return {
        "total_count": total_count,
        "parsed_count": parsed_count,
        "failed_count": total_count - parsed_count,
        "suspicious_count": suspicious_count,
    }


def logs_to_dataframe(logs):
    """将日志列表转成 DataFrame，便于 Streamlit 表格和图表展示。"""
    if not logs:
        return pd.DataFrame()
    return pd.DataFrame(logs)


def suspicious_to_dataframe(suspicious_logs):
    """整理可疑请求字段，避免页面表格过宽、信息太分散。"""
    rows = []
    for item in suspicious_logs:
        rows.append(
            {
                "IP": item.get("ip", "-"),
                "时间": item.get("time", "-"),
                "方法": item.get("method", "-"),
                "URL": item.get("url", "-"),
                "状态码": item.get("status", "-"),
                "攻击类型": ", ".join(item.get("attack_types", [])),
                "命中规则": ", ".join(item.get("rule_names", [])),
                "风险分": item.get("risk_score", 0),
                "User-Agent": item.get("user_agent", "-"),
            }
        )
    return pd.DataFrame(rows)


def show_bar_chart(title, data):
    """统一绘制简单柱状图，空数据时给出友好提示。"""
    st.subheader(title)
    if data.empty:
        st.info("暂无数据")
        return
    st.bar_chart(data)


def main():
    """Streamlit 页面入口。"""
    st.set_page_config(
        page_title="SecLog-Agent",
        page_icon="🛡️",
        layout="wide",
    )

    st.title("SecLog-Agent")
    st.caption("AI 辅助 Web 日志安全分析与告警研判工具，面向 SOC、蓝队值守和应急响应场景。")

    with st.sidebar:
        st.header("日志输入")
        uploaded_file = st.file_uploader("上传 Nginx / Apache access.log", type=["log", "txt"])
        use_sample = st.checkbox("使用内置示例日志", value=uploaded_file is None)
        st.divider()
        st.write("检测方式：规则匹配 + 正则表达式 + 风险评分")
        if os.getenv("DEEPSEEK_API_KEY"):
            st.success("DeepSeek AI 研判：已启用")
        else:
            st.warning("DeepSeek AI 研判：未配置，当前使用本地模板")
        st.write("说明：本工具只做防守侧日志分析，不包含自动化攻击或扫描功能。")

    if uploaded_file is not None:
        log_lines = read_uploaded_file(uploaded_file)
        source_name = uploaded_file.name
    elif use_sample:
        log_lines = read_sample_log()
        source_name = str(SAMPLE_LOG_PATH)
    else:
        st.warning("请上传日志文件，或在左侧选择使用内置示例日志。")
        return

    rules = load_rules(RULES_PATH)
    parsed_logs = parse_log_lines(log_lines)
    suspicious_logs, attack_stats = analyze_logs(parsed_logs, rules)
    ip_risk_list = calculate_ip_risk(suspicious_logs)
    basic_stats = build_basic_stats(parsed_logs, suspicious_logs)
    ai_summary = generate_ai_report(basic_stats, attack_stats, ip_risk_list, suspicious_logs)
    markdown_report = generate_markdown_report(
        source_name=source_name,
        basic_stats=basic_stats,
        attack_stats=attack_stats,
        ip_risk_list=ip_risk_list,
        suspicious_logs=suspicious_logs,
        ai_summary=ai_summary,
    )

    st.info(f"当前分析日志来源：{source_name}")

    metric_cols = st.columns(4)
    metric_cols[0].metric("总请求数", basic_stats["total_count"])
    metric_cols[1].metric("成功解析", basic_stats["parsed_count"])
    metric_cols[2].metric("解析失败", basic_stats["failed_count"])
    metric_cols[3].metric("可疑请求", basic_stats["suspicious_count"])

    all_df = logs_to_dataframe([item for item in parsed_logs if item.get("parsed")])
    suspicious_df = suspicious_to_dataframe(suspicious_logs)
    ip_risk_df = pd.DataFrame(ip_risk_list)

    chart_col1, chart_col2 = st.columns(2)
    with chart_col1:
        if not all_df.empty:
            top_ip = all_df["ip"].value_counts().head(10)
            show_bar_chart("访问次数 Top 10 IP", top_ip)
        else:
            show_bar_chart("访问次数 Top 10 IP", pd.Series(dtype=int))

    with chart_col2:
        if not all_df.empty:
            status_stats = all_df["status"].astype(str).value_counts().sort_index()
            show_bar_chart("HTTP 状态码统计", status_stats)
        else:
            show_bar_chart("HTTP 状态码统计", pd.Series(dtype=int))

    chart_col3, chart_col4 = st.columns(2)
    with chart_col3:
        attack_series = pd.Series(attack_stats, dtype=int).sort_values(ascending=False)
        show_bar_chart("攻击类型统计", attack_series)

    with chart_col4:
        if not all_df.empty:
            ua_stats = all_df["user_agent"].replace("", "-").value_counts().head(10)
            show_bar_chart("User-Agent Top 10", ua_stats)
        else:
            show_bar_chart("User-Agent Top 10", pd.Series(dtype=int))

    st.subheader("可疑 IP 风险排名")
    if ip_risk_df.empty:
        st.success("当前日志中未发现明显可疑 IP。")
    else:
        st.dataframe(ip_risk_df, use_container_width=True, hide_index=True)

    st.subheader("可疑请求详情")
    if suspicious_df.empty:
        st.success("未发现命中规则的可疑请求。")
    else:
        st.dataframe(suspicious_df, use_container_width=True, hide_index=True)

    st.subheader("AI 风格研判报告")
    st.markdown(ai_summary)

    st.subheader("报告导出")
    report_col1, report_col2 = st.columns([1, 2])
    with report_col1:
        if st.button("保存 Markdown 报告"):
            saved_path = save_markdown_report(markdown_report, REPORT_PATH)
            st.success(f"报告已保存：{saved_path}")
    with report_col2:
        st.download_button(
            label="下载 Markdown 报告",
            data=markdown_report,
            file_name="security_report.md",
            mime="text/markdown",
        )


if __name__ == "__main__":
    main()
