"""
dns_analyzer.py
---------------
Advanced DNS packet analysis and threat detection.

Detects:
- DNS tunneling (data exfiltration via DNS)
- C2 communication patterns
- Domain reputation checking
- Query rate anomalies
- Suspicious query types (TXT record queries for data)
"""
import re
from typing import Dict, List, Tuple, Optional
from collections import defaultdict
import requests
import time

# Known DGA (Domain Generation Algorithm) indicators
DGA_INDICATORS = [
    r'[a-z]{10,}[0-9]{3,}\.com',  # Random letters + numbers
    r'[a-z]{15,}\.ru',             # Suspicious Russian domain
    r'generated|random|malware|botnet',  # Common keywords
]

# Known C2 domain patterns
C2_PATTERNS = [
    r'\.top$', r'\.cc$', r'\.ru$',  # Common C2 TLDs
    r'update[a-z]*\.',              # Update-themed domains
    r'config[a-z]*\.',              # Config-themed domains
]


def parse_dns_query(packet_payload: bytes) -> Dict:
    """
    Parse DNS query from packet payload.

    Returns: {qtype, queries, responses, anomalies}
    """
    try:
        # Simple DNS parsing (full implementation would use scapy)
        dns_data = {
            "queries": [],
            "responses": [],
            "query_types": [],
            "ttls": [],
            "anomalies": []
        }

        # Extract ASCII domains (simplified)
        domains = re.findall(rb'([a-zA-Z0-9.-]{5,255}\.(?:com|org|net|ru|cc|top|xyz))', packet_payload)

        for domain in domains:
            try:
                domain_str = domain.decode('utf-8', errors='ignore')
                dns_data["queries"].append(domain_str)
            except:
                pass

        return dns_data
    except:
        return {"queries": [], "responses": [], "anomalies": []}


def detect_dns_tunneling(queries: List[str], timeframe_seconds: int = 300) -> Tuple[int, Optional[str]]:
    """
    Detect DNS-based data exfiltration.

    High query rates + unusual patterns = likely tunneling.
    Returns: (risk_score, reason)
    """
    if len(queries) < 10:
        return 0, None

    query_rate = len(queries) / (timeframe_seconds / 60)

    # Indicator 1: Extremely high query rate
    if query_rate > 100:  # 100+ queries per minute
        return 70, f"Possible DNS tunneling: {query_rate:.0f} queries/min"

    # Indicator 2: Many unique subdomains on same domain
    domain_counts = defaultdict(int)
    for query in queries:
        # Extract base domain
        parts = query.split('.')
        if len(parts) >= 2:
            base = '.'.join(parts[-2:])
            domain_counts[base] += 1

    for domain, count in domain_counts.items():
        if count > 50:
            return 60, f"Excessive subdomains on {domain}: {count} queries"

    # Indicator 3: Unusual character patterns in subdomains
    suspicious = 0
    for query in queries:
        parts = query.split('.')
        if len(parts) >= 3:
            subdomain = parts[0]
            # Very long or all-numeric subdomain
            if len(subdomain) > 30 or subdomain.isdigit():
                suspicious += 1

    if suspicious > len(queries) * 0.3:  # 30% suspicious
        return 50, f"Suspicious DNS patterns detected ({suspicious}/{len(queries)} queries)"

    return 0, None


def detect_dga_domains(queries: List[str]) -> Tuple[int, Optional[str]]:
    """
    Detect Domain Generation Algorithm (malware C2).

    Returns: (risk_score, reason)
    """
    for query in queries:
        for pattern in DGA_INDICATORS:
            if re.search(pattern, query, re.IGNORECASE):
                return 75, f"Detected possible DGA domain: {query}"

    return 0, None


def detect_c2_communication(queries: List[str]) -> Tuple[int, Optional[str]]:
    """
    Detect malware Command & Control communication patterns.

    Returns: (risk_score, reason)
    """
    for query in queries:
        for pattern in C2_PATTERNS:
            if re.search(pattern, query, re.IGNORECASE):
                return 65, f"Detected possible C2 domain: {query}"

    return 0, None


def check_domain_reputation(domain: str) -> Dict:
    """
    Check domain reputation against threat databases.

    Returns: {is_malicious, score, source}
    """
    # Simulate checking against multiple sources
    # In production, would call real APIs

    reputation = {
        "domain": domain,
        "is_malicious": False,
        "reputation_score": 0,
        "sources": []
    }

    # Check for known malicious TLDs
    malicious_tlds = ['.ru', '.cc', '.top', '.xyz', '.ren']
    if any(domain.endswith(tld) for tld in malicious_tlds):
        reputation["reputation_score"] += 30

    # Check for suspicious keywords
    suspicious_keywords = ['malware', 'botnet', 'exploit', 'phishing', 'c2']
    if any(keyword in domain.lower() for keyword in suspicious_keywords):
        reputation["reputation_score"] += 50
        reputation["is_malicious"] = True

    # Check domain age (very new domains more suspicious)
    # In production would call whois API
    # For now, just check length patterns
    if len(domain) > 30:
        reputation["reputation_score"] += 20

    return reputation


def detect_txt_record_abuse(queries: List[str]) -> Tuple[int, Optional[str]]:
    """
    Detect TXT record queries (often used for DNS exfiltration).

    Returns: (risk_score, reason)
    """
    txt_queries = [q for q in queries if 'txt' in str(q).lower() or 'TXT' in str(q)]

    if len(txt_queries) > 10:
        return 50, f"Excessive TXT record queries detected ({len(txt_queries)} queries)"

    return 0, None


def analyze_dns_connection(queries: List[str], timeframe_seconds: int = 300) -> Dict:
    """
    Comprehensive DNS analysis of a connection.

    Returns: {risk_score, threats_detected, evidence}
    """
    analysis = {
        "query_count": len(queries),
        "queries_sample": queries[:10],
        "risk_score": 0,
        "threats_detected": [],
        "evidence": [],
        "recommendation": "normal"
    }

    # Check 1: Tunneling
    tunnel_risk, tunnel_reason = detect_dns_tunneling(queries, timeframe_seconds)
    if tunnel_risk > 0:
        analysis["risk_score"] = max(analysis["risk_score"], tunnel_risk)
        analysis["threats_detected"].append("DNS Tunneling")
        analysis["evidence"].append(tunnel_reason)

    # Check 2: DGA
    dga_risk, dga_reason = detect_dga_domains(queries)
    if dga_risk > 0:
        analysis["risk_score"] = max(analysis["risk_score"], dga_risk)
        analysis["threats_detected"].append("DGA/Malware")
        analysis["evidence"].append(dga_reason)

    # Check 3: C2
    c2_risk, c2_reason = detect_c2_communication(queries)
    if c2_risk > 0:
        analysis["risk_score"] = max(analysis["risk_score"], c2_risk)
        analysis["threats_detected"].append("C2 Communication")
        analysis["evidence"].append(c2_reason)

    # Check 4: Domain reputation
    malicious_domains = []
    for query in queries[:20]:  # Sample check
        rep = check_domain_reputation(query)
        if rep["is_malicious"]:
            malicious_domains.append(query)

    if malicious_domains:
        analysis["risk_score"] = max(analysis["risk_score"], 70)
        analysis["threats_detected"].append("Known Malicious Domain")
        analysis["evidence"].append(f"Queried {len(malicious_domains)} known malicious domains")

    # Check 5: TXT record abuse
    txt_risk, txt_reason = detect_txt_record_abuse(queries)
    if txt_risk > 0:
        analysis["risk_score"] = max(analysis["risk_score"], txt_risk)
        analysis["threats_detected"].append("TXT Record Exfiltration")
        analysis["evidence"].append(txt_reason)

    # Recommendation
    if analysis["risk_score"] >= 70:
        analysis["recommendation"] = "BLOCK"
    elif analysis["risk_score"] >= 50:
        analysis["recommendation"] = "MONITOR"
    else:
        analysis["recommendation"] = "NORMAL"

    return analysis
