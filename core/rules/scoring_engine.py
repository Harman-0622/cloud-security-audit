def calculate_scores(findings):
    """
    Calculates the global compliance score and NIST pillar sub-scores
    based on the severity weights (High=3, Medium=2, Low=1).
    """
    scores = {
        "global_score": 0.0,
        "identify_score": 0.0,
        "protect_score": 0.0,
        "detect_score": 0.0,
        "total_rules": len(findings),
        "passed_rules": sum(1 for f in findings if f["status"] == "PASS"),
        "failed_rules": sum(1 for f in findings if f["status"] == "FAIL"),
    }
    
    def calc_percentage(subset):
        total_weight = sum(f["weight"] for f in subset)
        passed_weight = sum(f["weight"] for f in subset if f["status"] == "PASS")
        return round((passed_weight / total_weight) * 100, 2) if total_weight > 0 else 100.0

    # Calculate percentages
    scores["global_score"] = calc_percentage(findings)
    scores["identify_score"] = calc_percentage([f for f in findings if f["nist_function"] == "IDENTIFY"])
    scores["protect_score"] = calc_percentage([f for f in findings if f["nist_function"] == "PROTECT"])
    scores["detect_score"] = calc_percentage([f for f in findings if f["nist_function"] == "DETECT"])
    
    return scores