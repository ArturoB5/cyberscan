from typing import Any


def classify_risk(stats: dict[str, int] | None) -> str:
    if not stats:
        return "UNKNOWN"

    malicious = int(stats.get("malicious", 0))
    suspicious = int(stats.get("suspicious", 0))

    if malicious >= 5 or suspicious >= 10:
        return "HIGH RISK"
    if malicious >= 1 or suspicious >= 3:
        return "MEDIUM RISK"
    if suspicious >= 1:
        return "LOW RISK"
    return "SAFE"


def extract_stats(vt_data: dict[str, Any]) -> dict[str, int]:
    attributes = vt_data.get("data", {}).get("attributes", {})
    return attributes.get("last_analysis_stats") or attributes.get("stats") or {}


def analyze_result(vt_data: dict[str, Any]) -> str:
    return classify_risk(extract_stats(vt_data))
