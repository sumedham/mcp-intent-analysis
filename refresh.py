#!/usr/bin/env python3
"""
Refresh MCP Intent Analysis site with live data from Datadog.

Usage:
    python refresh.py              # Pull last 3 weeks, regenerate index.html
    python refresh.py --days 7     # Custom time range
    python refresh.py --publish    # Also update the GitHub gist
"""

import argparse
import json
import os
import re
import subprocess
import sys
import urllib.request
import urllib.error
from datetime import datetime, timezone, timedelta
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent
TEMPLATE = SCRIPT_DIR / "template.html"
OUTPUT = SCRIPT_DIR / "index.html"
GIST_ID = "519468439d1b64b8e153df5e7a8a5bcf"

DD_SITE = "https://api.datadoghq.com"
LOG_QUERY = "service:mcp @ddsource:audit @metadata.tool.arguments.telemetry.intent:*"
INTENT_FACET = "@metadata.tool.arguments.telemetry.intent"
OUTLIER_THRESHOLD = 500

# ── Datadog API ──────────────────────────────────────────────────────────────

def dd_headers():
    api_key = os.environ.get("DD_API_KEY")
    app_key = os.environ.get("DD_APP_KEY")
    if not api_key or not app_key:
        print("Error: DD_API_KEY and DD_APP_KEY must be set", file=sys.stderr)
        sys.exit(1)
    return {
        "DD-API-KEY": api_key,
        "DD-APPLICATION-KEY": app_key,
        "Content-Type": "application/json",
    }


def fetch_intents(days=21):
    """Pull all unique intents with counts from Datadog logs analytics."""
    now = datetime.now(timezone.utc)
    from_ts = (now - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    to_ts = now.strftime("%Y-%m-%dT%H:%M:%SZ")

    all_intents = []
    page_cursor = None
    page_num = 0

    while True:
        body = {
            "filter": {
                "query": LOG_QUERY,
                "from": from_ts,
                "to": to_ts,
            },
            "group_by": [
                {
                    "facet": INTENT_FACET,
                    "limit": 1000,
                    "sort": {"aggregation": "count", "order": "desc"},
                    "total": False,
                }
            ],
            "compute": [{"aggregation": "count"}],
            "page": {"limit": 1000},
        }
        if page_cursor:
            body["page"]["cursor"] = page_cursor

        data = json.dumps(body).encode()
        req = urllib.request.Request(
            f"{DD_SITE}/api/v2/logs/analytics/aggregate",
            data=data,
            headers=dd_headers(),
            method="POST",
        )

        try:
            with urllib.request.urlopen(req) as resp:
                result = json.loads(resp.read())
        except urllib.error.HTTPError as e:
            err_body = e.read().decode() if e.fp else ""
            print(f"Datadog API error {e.code}: {err_body}", file=sys.stderr)
            sys.exit(1)

        buckets = result.get("data", {}).get("buckets", [])
        if not buckets:
            break

        for b in buckets:
            by_vals = b.get("by", {})
            intent = by_vals.get(INTENT_FACET, "")
            count = b.get("computes", {}).get("c0", 0)
            if intent:
                all_intents.append((count, intent))

        page_num += 1
        print(f"  Page {page_num}: {len(buckets)} intents (total so far: {len(all_intents)})")

        # Check for next page
        next_cursor = result.get("meta", {}).get("page", {}).get("after")
        if not next_cursor or len(buckets) < 1000:
            break
        page_cursor = next_cursor

    all_intents.sort(key=lambda x: -x[0])
    print(f"Fetched {len(all_intents)} unique intents, {sum(c for c,_ in all_intents)} total calls")
    return all_intents


# ── Semantic Clustering ──────────────────────────────────────────────────────

CLUSTERS = [
    ("Alert & Incident Management", "Find alerting monitors",
     r"(?:alert(?:ing)?|triggered)\s+monitor|monitor.*(?:alert|warn|trigger)|alert.*(?:state|status|active)|find.*monitor.*alert|search.*monitor.*alert"),
    ("Alert & Incident Management", "Investigate incidents",
     r"incident|outage|page(?:rduty)?|oncall|on-call|escalat"),
    ("Alert & Incident Management", "Check monitor status",
     r"monitor.*(?:status|state|detail|config|threshold|evaluat|muted|silenced)|(?:status|state|detail).*monitor|retrieve.*monitor|get.*monitor"),
    ("Service Health", "Check provider activity",
     r"(?:actively\s+processing|is\s+active|transaction.*(?:volume|processing))|(?:provider|vendor|merchant|payment|loyalty|processor).*(?:active|running|processing|healthy)|check.*(?:paytronix|heartland|punchh|fiserv|nets|adyen|worldpay|stripe|braintree|square)"),
    ("Service Health", "Check service health",
     r"(?:health|heartbeat|alive|up|uptime|availability|readiness|liveness)\s+(?:check|status|endpoint|probe)|(?:service|host|node|pod|container|cluster).*(?:health|status|running|alive|up\b|down\b)|is.*(?:service|host).*(?:running|healthy|up\b|down\b)"),
    ("Service Health", "Check deployment status",
     r"deploy(?:ment)?.*(?:status|progress|success|fail|roll)|(?:release|version|canary|rollout|rollback).*(?:status|progress)|(?:status|progress).*deploy"),
    ("Error Investigation", "Check service error logs",
     r"(?:error|5xx|exception|failure|crash|broken|critical)\s+log|error.*(?:log|message|trace)|log.*error|check.*error|search.*error.*log|(?:service|app)\S*\s+error"),
    ("Error Investigation", "Check error spans/traces",
     r"error.*(?:span|trace)|(?:span|trace).*error|failed.*(?:span|request|call)|exception.*trace"),
    ("Error Investigation", "Investigate 5xx/4xx errors",
     r"[45]xx|status.?code.*[45]\d\d|http.*error|(?:bad\s+)?(?:gateway|request)|timeout|connection.*(?:refused|reset|error)|(?:500|502|503|504|400|401|403|404|429)\b"),
    ("Service Architecture", "Discover services/resources",
     r"(?:kube_namespace|namespace|cluster|pod|container|node|replica|deployment)\s+(?:for|of)|find.*(?:service|endpoint|resource|namespace|host)|discover.*(?:service|endpoint|dep)|list.*(?:service|endpoint)"),
    ("Service Architecture", "Map service dependencies",
     r"(?:dependency|dependencies|upstream|downstream|call(?:s|ing|ed)|invoke|depend).*(?:service|endpoint|api)|service.*(?:map|graph|topology|diagram|architecture|depend)"),
    ("Database Monitoring", "DBM query analysis",
     r"(?:dbm|database|db)\s+(?:query|queries|slow|sample|plan|explain|execution)|query.*(?:sample|plan|explain|performance)|slow.*query|(?:postgres|mysql|mongo|redis|sql).*(?:query|performance|slow)"),
    ("Database Monitoring", "Database health",
     r"(?:database|db|postgres|mysql|mongo|redis|dynamo|rds|aurora).*(?:health|status|connection|replicat|lag|cpu|memory|disk|iops)"),
    ("Metrics & Dashboards", "Search dashboards",
     r"dashboard|widget|graph.*(?:metric|query)|metric.*dashboard|find.*dashboard|search.*dashboard"),
    ("Metrics & Dashboards", "Query metrics",
     r"metric.*(?:query|search|find|get|retrieve|value|data|timeseries)|query.*metric|search.*metric|(?:cpu|memory|disk|latency|throughput|p99|p95|p50).*metric"),
    ("Performance", "Investigate latency",
     r"latency|slow(?:ness|er)?|p99|p95|p50|percentile|response.*time|duration.*(?:high|increase|spike)|performance.*(?:degrad|issue|problem)"),
    ("Performance", "Resource utilization",
     r"(?:cpu|memory|disk|network|bandwidth|iops|gpu).*(?:usage|utiliz|consumption|high|spike|saturat)"),
    ("Log Analysis", "Search application logs",
     r"(?:search|find|get|retrieve|check|look|grep)\s+.*log|log.*(?:search|query|filter|find|pattern)|application.*log|prod(?:uction)?\s+log"),
    ("Log Analysis", "Log patterns/anomalies",
     r"log.*(?:pattern|anomal|unusual|spike|volume|trend|aggregate)|(?:pattern|anomal).*log"),
    ("CI/CD & Pipelines", "Pipeline status",
     r"(?:pipeline|ci|cd|build|test|deploy).*(?:status|fail|pass|result|run|job)|(?:github|gitlab|jenkins|circleci|actions).*(?:status|fail|run|workflow)"),
    ("CI/CD & Pipelines", "Test results",
     r"(?:test|spec|suite).*(?:result|fail|pass|flak|broken|status|run)|(?:fail|broken|flak).*test"),
    ("Workflow & Automation", "Automated tasks",
     r"(?:automat|schedul|cron|batch|job|task|workflow|runbook).*(?:status|result|run|fail|trigger)|(?:run|trigger|execute).*(?:workflow|runbook|automation)"),
    ("Cost & Usage", "Cost analysis",
     r"cost|billing|spend|expens|pricing|budget|charg|invoice|(?:cloud|aws|gcp|azure).*(?:cost|spend|bill)"),
    ("Cost & Usage", "Usage/quota tracking",
     r"(?:usage|quota|limit|rate.?limit|throttl|capacity|consumption).*(?:track|check|monitor|current|remaining)"),
    ("Data Extraction", "Export/extract data",
     r"(?:export|extract|download|dump|csv|fetch.*(?:all|data|detail)|pull\s+data|collect)"),
    ("Security", "Security investigation",
     r"(?:security|threat|attack|intrusion|breach|malware|vulnerability|cve|exploit|suspicious|anomal).*(?:log|event|alert|detect|investigat)"),
    ("Testing & QA", "Test environment checks",
     r"(?:staging|dev|test|qa|sandbox|preprod|pre-prod).*(?:environment|env|check|status|verify)|verify.*(?:staging|dev|test)"),
    ("Notebooks & Documentation", "Search notebooks",
     r"notebook|documentation|runbook|playbook|postmortem|post-mortem|blameless|retro"),
    ("RUM & Frontend", "Frontend monitoring",
     r"(?:rum|real.?user|frontend|browser|web.?vital|core.?vital|lcp|fid|cls|inp|page.*load|client.?side)"),
]

WRITE_PATTERNS = [
    r"^(?:create|update|edit|delete|remove|add|modify|set|enable|disable|mute|unmute|assign|transition|close|resolve|acknowledge|restart|reboot|kill|stop|start|scale|deploy|rollback|trigger|execute|run|send|post|patch|put)\b",
]

RW_LABELS = {
    "Alert & Incident Management": "Alert Triage",
    "Service Health": "Health Check",
    "Error Investigation": "Troubleshoot",
    "Service Architecture": "Observe",
    "Database Monitoring": "Observe",
    "Metrics & Dashboards": "Observe",
    "Performance": "Observe",
    "Log Analysis": "Observe",
    "CI/CD & Pipelines": "Observe",
    "Cost & Usage": "Observe",
    "Data Extraction": "Observe",
    "Security": "Observe",
    "Testing & QA": "Observe",
    "Workflow & Automation": "Observe",
    "Notebooks & Documentation": "Observe",
    "RUM & Frontend": "Observe",
    "Other": "Observe",
}


def classify_intent(text):
    for theme, usecase, pattern in CLUSTERS:
        if re.search(pattern, text, re.I):
            return theme, usecase
    return "Other", "Uncategorized"


def classify_rw(text, theme):
    for p in WRITE_PATTERNS:
        if re.match(p, text.strip(), re.I):
            return "Write"
    return RW_LABELS.get(theme, "Observe")


# ── Build data structure ─────────────────────────────────────────────────────

# Verb grouping (same as JS version)
VERB_GROUPS = {
    "find": "Find", "search": "Find", "discover": "Find", "look": "Find", "locate": "Find", "identify": "Find",
    "get": "Get", "retrieve": "Get", "fetch": "Get", "obtain": "Get", "pull": "Get", "read": "Get", "show": "Get", "list": "Get", "view": "Get",
    "check": "Check", "verify": "Check", "validate": "Check", "confirm": "Check", "ensure": "Check", "test": "Check",
    "investigate": "Investigate", "debug": "Investigate", "diagnose": "Investigate", "troubleshoot": "Investigate", "trace": "Investigate", "inspect": "Investigate",
    "analyze": "Analyze", "examine": "Analyze", "evaluate": "Analyze", "assess": "Analyze", "review": "Analyze", "audit": "Analyze", "compare": "Analyze",
    "count": "Count", "calculate": "Count", "sum": "Count", "total": "Count", "aggregate": "Count",
    "extract": "Extract", "export": "Extract", "download": "Extract", "dump": "Extract", "collect": "Extract",
    "monitor": "Monitor", "watch": "Monitor", "observe": "Monitor", "track": "Monitor", "follow": "Monitor",
    "determine": "Determine", "figure": "Determine", "understand": "Determine", "learn": "Determine",
    "explore": "Explore", "browse": "Explore", "scan": "Explore", "survey": "Explore",
}

CATEGORY_PATTERNS = [
    (r"\bmonitor\b", "Monitors"), (r"\blog(?:s|ging)?\b", "Logs"), (r"\bincident", "Incidents"),
    (r"\bmetric", "Metrics"), (r"\bservice|depend|upstream|downstream", "Services"),
    (r"\bdashboard|widget", "Dashboards"), (r"\bspan|trace|apm\b", "Traces"),
    (r"\bevent\b", "Events"), (r"\bnotebook|runbook", "Notebooks"), (r"\bhost|infra", "Infrastructure"),
    (r"\bdatabase|db\b|query.*(?:sample|plan)|dbm", "Database"), (r"\bpipeline|ci|cd|deploy|build|test", "CI/CD"),
    (r"\bcost|billing|spend", "Cost"), (r"\bsecurity|threat|attack", "Security"),
    (r"\brum\b|frontend|browser", "RUM"),
]


def get_verb(text):
    w = text.strip().split()[0].lower() if text.strip() else "other"
    return VERB_GROUPS.get(w, w.title())


def get_category(text):
    t = text.lower()
    for pat, cat in CATEGORY_PATTERNS:
        if re.search(pat, t):
            return cat
    return "Other"


def build_data(raw_intents, days):
    """Build the ALL_DATA structure from raw (count, intent) pairs."""
    # Filter outliers
    intents = [(c, i) for c, i in raw_intents if c < OUTLIER_THRESHOLD]

    # Classify each intent
    classified = []
    for count, text in intents:
        theme, usecase = classify_intent(text)
        rw = classify_rw(text, theme)
        classified.append({
            "count": count,
            "intent": text,
            "theme": theme,
            "usecase": usecase,
            "rw_class": rw,
        })

    # Build semantic clusters
    from collections import defaultdict
    theme_data = defaultdict(lambda: defaultdict(lambda: {"count": 0, "examples": []}))
    for item in classified:
        t, u = item["theme"], item["usecase"]
        theme_data[t][u]["count"] += item["count"]
        if len(theme_data[t][u]["examples"]) < 5:
            theme_data[t][u]["examples"].append({"intent": item["intent"], "count": item["count"]})

    clusters = []
    for theme, usecases in sorted(theme_data.items(), key=lambda x: -sum(u["count"] for u in x[1].values())):
        total = sum(u["count"] for u in usecases.values())
        ucs = []
        for uc_name, uc_data in sorted(usecases.items(), key=lambda x: -x[1]["count"]):
            ucs.append({"name": uc_name, "count": uc_data["count"], "top_examples": uc_data["examples"]})
        clusters.append({"theme": theme, "total_count": total, "use_cases": ucs})

    # RW breakdown
    rw_counts = defaultdict(int)
    for item in classified:
        rw_counts[item["rw_class"]] += item["count"]
    total_calls = sum(rw_counts.values())
    rw_breakdown = {k: {"count": v, "pct": round(v / total_calls * 100, 1) if total_calls else 0} for k, v in rw_counts.items()}

    now = datetime.now(timezone.utc)
    from_date = (now - timedelta(days=days)).strftime("%b %d")
    to_date = now.strftime("%b %d, %Y")

    return {
        "intents": classified,
        "semantic_clusters": clusters,
        "rw_breakdown": rw_breakdown,
        "meta": {
            "date_range": f"{from_date} - {to_date}",
            "total_unique": len(classified),
            "total_calls": sum(i["count"] for i in classified),
            "days": days,
        },
    }


# ── HTML generation ──────────────────────────────────────────────────────────

def render_html(data):
    if not TEMPLATE.exists():
        print(f"Error: template not found at {TEMPLATE}", file=sys.stderr)
        sys.exit(1)

    template = TEMPLATE.read_text()
    data_json = json.dumps(data, ensure_ascii=False)
    html = template.replace("/*__DATA__*/", data_json)
    OUTPUT.write_text(html)
    print(f"Written {len(html) // 1024}KB to {OUTPUT}")


def publish():
    try:
        subprocess.run(
            ["gh", "gist", "edit", GIST_ID, "-f", "index.html", str(OUTPUT)],
            check=True,
        )
        print(f"Published to gist {GIST_ID}")
    except FileNotFoundError:
        print("Warning: gh CLI not found, skipping publish", file=sys.stderr)
    except subprocess.CalledProcessError as e:
        print(f"Warning: gist publish failed: {e}", file=sys.stderr)


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Refresh MCP Intent Analysis site")
    parser.add_argument("--days", type=int, default=21, help="Lookback period in days (default: 21)")
    parser.add_argument("--publish", action="store_true", help="Also update the GitHub gist")
    parser.add_argument("--open", action="store_true", help="Open index.html in browser after generation")
    args = parser.parse_args()

    print(f"Fetching intents from last {args.days} days...")
    raw_intents = fetch_intents(args.days)

    print("Building semantic clusters...")
    data = build_data(raw_intents, args.days)
    meta = data["meta"]
    print(f"  {meta['total_unique']} unique intents, {meta['total_calls']} total calls")
    print(f"  {len(data['semantic_clusters'])} themes")

    print("Generating HTML...")
    render_html(data)

    if args.publish:
        print("Publishing to GitHub gist...")
        publish()

    if args.open:
        subprocess.run(["open", str(OUTPUT)])

    print("Done!")


if __name__ == "__main__":
    main()
