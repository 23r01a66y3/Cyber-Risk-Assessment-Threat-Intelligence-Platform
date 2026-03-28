def calculate_risk(vulns):
    results = []

    for v in vulns:
        if "Insecure" in v["issue"]:
            score = 9
        elif "Not Secure" in v["issue"]:
            score = 7
        else:
            score = 5

        results.append({
            "port": v["port"],
            "issue": v["issue"],
            "risk_score": score
        })

    return results
