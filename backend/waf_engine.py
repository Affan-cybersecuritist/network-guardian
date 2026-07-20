"""
waf_engine.py
-------------
Web Application Firewall - HTTP attack pattern detection.

Detects:
- SQL Injection
- Cross-Site Scripting (XSS)
- Command Injection
- Path Traversal
- Malformed requests
- Rate limit abuse
"""
import re
from typing import Dict, List, Optional, Tuple

# SQL Injection patterns
SQL_INJECTION_PATTERNS = [
    r"' OR '1'='1",
    r"' OR 1=1",
    r"admin' --",
    r"' OR 'a'='a",
    r"UNION.*SELECT",
    r"DROP\s+TABLE",
    r"INSERT\s+INTO",
    r"DELETE\s+FROM",
    r"exec\s*\(",
    r"execute\s*\(",
    r"script\s*src",
]

# XSS patterns
XSS_PATTERNS = [
    r"<script[^>]*>",
    r"javascript:",
    r"onerror\s*=",
    r"onload\s*=",
    r"onclick\s*=",
    r"<iframe",
    r"<object",
    r"<embed",
    r"<img[^>]*src",
]

# Command Injection patterns
COMMAND_INJECTION_PATTERNS = [
    r";\s*rm\s+-rf",
    r";\s*cat\s+/etc",
    r";\s*whoami",
    r";\s*id",
    r"|\s*nc\s+-l",
    r"`\s*whoami",
    r"\$\(.*whoami",
    r"bash\s+-i",
    r"cmd\.exe",
]

# Path Traversal patterns
PATH_TRAVERSAL_PATTERNS = [
    r"\.\./",
    r"\.\./\.\./",
    r"%2e%2e/",
    r"\.\.\\",
    r"/etc/passwd",
    r"c:\\windows",
]


def detect_sql_injection(http_body: str) -> Tuple[bool, Optional[str]]:
    """
    Detect SQL injection attempts.

    Returns: (is_attack, pattern_matched)
    """
    for pattern in SQL_INJECTION_PATTERNS:
        if re.search(pattern, http_body, re.IGNORECASE):
            return True, f"SQL Injection: {pattern}"

    return False, None


def detect_xss(http_body: str) -> Tuple[bool, Optional[str]]:
    """
    Detect Cross-Site Scripting (XSS) attempts.

    Returns: (is_attack, pattern_matched)
    """
    for pattern in XSS_PATTERNS:
        if re.search(pattern, http_body, re.IGNORECASE):
            return True, f"XSS: {pattern}"

    return False, None


def detect_command_injection(http_body: str) -> Tuple[bool, Optional[str]]:
    """
    Detect Command Injection attempts.

    Returns: (is_attack, pattern_matched)
    """
    for pattern in COMMAND_INJECTION_PATTERNS:
        if re.search(pattern, http_body, re.IGNORECASE):
            return True, f"Command Injection: {pattern}"

    return False, None


def detect_path_traversal(url: str, http_body: str) -> Tuple[bool, Optional[str]]:
    """
    Detect path traversal / directory enumeration attempts.

    Returns: (is_attack, reason)
    """
    # Check URL
    for pattern in PATH_TRAVERSAL_PATTERNS:
        if re.search(pattern, url, re.IGNORECASE):
            return True, f"Path Traversal: {pattern}"

    # Check body
    for pattern in PATH_TRAVERSAL_PATTERNS:
        if re.search(pattern, http_body, re.IGNORECASE):
            return True, f"Path Traversal: {pattern}"

    # Check for suspicious URL depth
    if url.count("/") > 15:
        return True, "Suspicious URL depth (directory enumeration)"

    return False, None


def detect_malformed_request(http_headers: Dict, http_method: str) -> Tuple[bool, Optional[str]]:
    """
    Detect malformed or suspicious HTTP requests.

    Returns: (is_suspicious, reason)
    """
    # Check for missing essential headers
    if "host" not in [h.lower() for h in http_headers.keys()]:
        return True, "Missing Host header"

    # Check for suspicious User-Agent
    user_agent = http_headers.get("User-Agent", "")
    if not user_agent or "curl" in user_agent.lower():
        return True, "Suspicious User-Agent"

    # Check for unusual HTTP methods
    if http_method not in ["GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "PATCH"]:
        return True, f"Unusual HTTP method: {http_method}"

    return False, None


def detect_rate_abuse(request_count: int, timeframe_seconds: int = 60) -> Tuple[bool, Optional[str]]:
    """
    Detect abnormal request rates (DoS / scraping).

    Returns: (is_abuse, reason)
    """
    requests_per_second = request_count / timeframe_seconds

    if requests_per_second > 100:
        return True, f"Extreme rate abuse: {requests_per_second:.0f} req/sec"

    if requests_per_second > 50:
        return True, f"Rate abuse detected: {requests_per_second:.0f} req/sec"

    if requests_per_second > 10:
        return True, f"Suspicious rate: {requests_per_second:.0f} req/sec"

    return False, None


def detect_xxe_injection(http_body: str) -> Tuple[bool, Optional[str]]:
    """
    Detect XML External Entity (XXE) injection attempts.

    Returns: (is_attack, reason)
    """
    xxe_patterns = [
        r"<!ENTITY",
        r"SYSTEM\s+['\"]",
        r"PUBLIC\s+['\"]",
    ]

    for pattern in xxe_patterns:
        if re.search(pattern, http_body, re.IGNORECASE):
            return True, f"XXE Injection: {pattern}"

    return False, None


def analyze_http_request(
    url: str,
    http_method: str,
    http_headers: Dict,
    http_body: str,
    request_count: int = 1,
    timeframe_seconds: int = 60
) -> Dict:
    """
    Comprehensive HTTP request analysis.

    Returns: {risk_score, attacks_detected, recommendations}
    """
    analysis = {
        "risk_score": 0,
        "attacks_detected": [],
        "evidence": [],
        "recommendation": "ALLOW",
        "block": False
    }

    # Check 1: SQL Injection
    is_sqli, sqli_msg = detect_sql_injection(http_body)
    if is_sqli:
        analysis["risk_score"] += 80
        analysis["attacks_detected"].append("SQL Injection")
        analysis["evidence"].append(sqli_msg)

    # Check 2: XSS
    is_xss, xss_msg = detect_xss(http_body)
    if is_xss:
        analysis["risk_score"] += 70
        analysis["attacks_detected"].append("XSS")
        analysis["evidence"].append(xss_msg)

    # Check 3: Command Injection
    is_cmd, cmd_msg = detect_command_injection(http_body)
    if is_cmd:
        analysis["risk_score"] += 85
        analysis["attacks_detected"].append("Command Injection")
        analysis["evidence"].append(cmd_msg)

    # Check 4: Path Traversal
    is_path, path_msg = detect_path_traversal(url, http_body)
    if is_path:
        analysis["risk_score"] += 60
        analysis["attacks_detected"].append("Path Traversal")
        analysis["evidence"].append(path_msg)

    # Check 5: XXE
    is_xxe, xxe_msg = detect_xxe_injection(http_body)
    if is_xxe:
        analysis["risk_score"] += 75
        analysis["attacks_detected"].append("XXE Injection")
        analysis["evidence"].append(xxe_msg)

    # Check 6: Malformed request
    is_malformed, malformed_msg = detect_malformed_request(http_headers, http_method)
    if is_malformed:
        analysis["risk_score"] += 20
        analysis["evidence"].append(malformed_msg)

    # Check 7: Rate abuse
    is_rate_abuse, rate_msg = detect_rate_abuse(request_count, timeframe_seconds)
    if is_rate_abuse:
        analysis["risk_score"] += 50
        analysis["attacks_detected"].append("Rate Abuse / DoS")
        analysis["evidence"].append(rate_msg)

    # Cap at 100
    analysis["risk_score"] = min(100, analysis["risk_score"])

    # Determine action
    if analysis["risk_score"] >= 70:
        analysis["recommendation"] = "BLOCK"
        analysis["block"] = True
    elif analysis["risk_score"] >= 50:
        analysis["recommendation"] = "MONITOR"
    elif analysis["risk_score"] >= 20:
        analysis["recommendation"] = "LOG"
    else:
        analysis["recommendation"] = "ALLOW"

    return analysis
