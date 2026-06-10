import re


# Nginx / Apache 常见 combined access log 格式：
# 127.0.0.1 - - [10/Jun/2026:10:00:00 +0800] "GET / HTTP/1.1" 200 123 "-" "Mozilla/5.0"
COMBINED_LOG_PATTERN = re.compile(
    r'(?P<ip>\S+)\s+'
    r'\S+\s+\S+\s+'
    r'\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<request>[^"]*)"\s+'
    r'(?P<status>\d{3})\s+'
    r'(?P<size>\S+)\s+'
    r'"(?P<referer>[^"]*)"\s+'
    r'"(?P<user_agent>[^"]*)"'
)


def parse_request(request_text):
    """解析请求行，拆出请求方法、URL 和协议版本。"""
    parts = request_text.split()
    if len(parts) >= 3:
        return parts[0], parts[1], parts[2]
    if len(parts) == 2:
        return parts[0], parts[1], "-"
    if len(parts) == 1:
        return parts[0], "-", "-"
    return "-", "-", "-"


def safe_int(value, default=0):
    """将字符串安全转换为整数，处理响应大小为 '-' 的情况。"""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def parse_log_line(line, line_number=0):
    """解析单行 access.log，解析失败时保留原始内容，方便排查格式问题。"""
    match = COMBINED_LOG_PATTERN.match(line.strip())
    if not match:
        return {
            "parsed": False,
            "line_number": line_number,
            "raw": line.rstrip("\n"),
        }

    data = match.groupdict()
    method, url, protocol = parse_request(data.get("request", ""))

    return {
        "parsed": True,
        "line_number": line_number,
        "raw": line.rstrip("\n"),
        "ip": data.get("ip", "-"),
        "time": data.get("time", "-"),
        "method": method,
        "url": url,
        "protocol": protocol,
        "status": safe_int(data.get("status")),
        "size": safe_int(data.get("size")),
        "referer": data.get("referer", "-"),
        "user_agent": data.get("user_agent", "-"),
    }


def parse_log_lines(lines):
    """批量解析日志内容，返回结构化日志列表。"""
    return [parse_log_line(line, index + 1) for index, line in enumerate(lines) if line.strip()]
