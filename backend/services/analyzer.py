def analyze_result(vt_data):
    try:
        stats = vt_data["data"]["attributes"]["last_analysis_stats"]
        malicious = stats["malicious"]
        if malicious > 5:
            return "HIGH RISK"
        elif malicious > 0:
            return "MEDIUM RISK"
        else:
            return "LOW RISK"
    except:
        return "UNKNOWN"