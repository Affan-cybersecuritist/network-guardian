"""
notifications.py
-----------------
Outbound webhook for high-risk detections, so you don't have to be staring at
the dashboard to find out something bad happened. Works with anything that
accepts a JSON POST -- Slack incoming webhooks, Discord webhooks, Microsoft
Teams, or a custom endpoint you write yourself.

Opt-in only: nothing is ever sent unless the user configures a URL themselves
via POST /settings/webhook (see main.py) -- this module never guesses or
hardcodes a destination.

Batched, not per-connection: a single attack scenario can produce 100+ flagged
rows in one scoring pass (see the demo brute-force scenario). Firing a webhook
per row would flood Slack/Discord and likely get rate-limited. Instead this
sends ONE message per scoring batch summarizing the count plus a handful of
the highest-risk examples.
"""
import requests

import db as db_store

WEBHOOK_TIMEOUT = 4  # seconds -- must never let a slow/dead webhook stall scoring
MAX_EXAMPLES = 5


def is_configured():
    url = db_store.get_setting("webhook_url")
    enabled = db_store.get_setting("webhook_enabled") == "1"
    return bool(url) and enabled


def _build_payload(high_risk_results, source):
    n = len(high_risk_results)
    top = sorted(high_risk_results, key=lambda r: r["risk_score"], reverse=True)[:MAX_EXAMPLES]
    lines = [f"*Network Guardian*: {n} high-risk connection(s) detected (source: {source})"]
    for r in top:
        bf = " [brute-force]" if any("brute-force" in x for x in r.get("reasons", [])) else ""
        lines.append(
            f"- risk {r['risk_score']:.0f} · {r.get('src_ip', '?')} → "
            f"{r.get('dst_ip', '?')}:{r.get('dst_port', '?')} ({r.get('service', '?')}){bf}"
        )
    text = "\n".join(lines)
    # Slack/Discord/Teams incoming webhooks all understand a top-level "text" field;
    # a custom endpoint gets the structured data too.
    return {
        "text": text,
        "count": n,
        "source": source,
        "connections": [
            {
                "risk_score": round(r["risk_score"], 1),
                "src_ip": r.get("src_ip"),
                "dst_ip": r.get("dst_ip"),
                "dst_port": r.get("dst_port"),
                "service": r.get("service"),
                "reasons": r.get("reasons", []),
            }
            for r in top
        ],
    }


def notify_high_risk(results, source, threshold=70):
    """Best-effort: called from main.score_feature_rows after every real
    scoring pass. Never raises -- a dead/misconfigured webhook must not break
    scoring or live capture."""
    if not is_configured():
        return
    high_risk = [
        r for r in results
        if r.get("risk_score", 0) >= threshold or any("brute-force" in x for x in r.get("reasons", []))
    ]
    if not high_risk:
        return
    url = db_store.get_setting("webhook_url")
    try:
        requests.post(url, json=_build_payload(high_risk, source), timeout=WEBHOOK_TIMEOUT)
    except Exception:
        pass


def send_test(url):
    """Fires a single test payload at the given URL immediately -- used by the
    'Send test notification' button so the user can verify their webhook works
    without waiting for a real detection. Raises on failure so the caller can
    surface the error to the UI."""
    payload = {
        "text": "*Network Guardian*: this is a test notification. If you can see this, your webhook is configured correctly.",
        "count": 0,
        "source": "test",
        "connections": [],
    }
    resp = requests.post(url, json=payload, timeout=WEBHOOK_TIMEOUT)
    resp.raise_for_status()
    return resp.status_code
