SEVERITY_WEIGHTS = {
    "critical": 40,
    "high": 22,
    "medium": 10,
    "low": 4,
    "info": 0,
}

CATEGORY_CAPS = {
    "identity": 35,
    "entropy": 15,
    "pe": 45,
    "yara": 65,
}

VERDICT_THRESHOLDS = {
    "clean": 20,
    "suspicious": 50,
}


def _sum_findings(findings, cap):
    total = 0
    for finding in findings or []:
        total += SEVERITY_WEIGHTS.get(finding.get("severity", "info"), 0)
        if finding.get("code") == "find.type_ok":
            total -= SEVERITY_WEIGHTS["info"]
    return min(cap, total)


def compute_risk(identity, entropy, pe, yara, virustotal):
    breakdown = []

    identity_findings = [f for f in identity.get("findings", []) if f.get("code") != "find.type_ok"]
    identity_pts = _sum_findings(identity_findings, CATEGORY_CAPS["identity"])
    if identity_pts:
        breakdown.append({"key": "risk.identity", "points": identity_pts})

    entropy_pts = 0
    level = entropy.get("level")
    family = identity.get("family")
    if level == "high" and family in ("executable", "archive"):
        entropy_pts = CATEGORY_CAPS["entropy"]
    elif level == "elevated" and family == "executable":
        entropy_pts = 8
    if entropy_pts:
        breakdown.append({"key": "risk.entropy", "points": entropy_pts})

    pe_findings = [f for f in pe.get("findings", []) if f.get("code") != "pe.not_pe"]
    pe_pts = _sum_findings(pe_findings, CATEGORY_CAPS["pe"])
    if pe_pts:
        breakdown.append({"key": "risk.pe", "points": pe_pts})

    yara_findings = [f for f in yara.get("findings", []) if f.get("code") == "yara.match"]
    yara_pts = _sum_findings(yara_findings, CATEGORY_CAPS["yara"])
    if yara_pts:
        breakdown.append({"key": "risk.yara", "points": yara_pts})

    vt_pts = 0
    if virustotal.get("status") == "found":
        malicious = virustotal.get("malicious", 0)
        suspicious = virustotal.get("suspicious", 0)
        total = max(virustotal.get("total_engines", 1), 1)
        if malicious > 0:
            ratio = malicious / total
            vt_pts = min(55, 20 + int(ratio * 100 * 0.6))
        elif suspicious > 0:
            vt_pts = 8
    if vt_pts:
        breakdown.append({"key": "risk.virustotal", "points": vt_pts})

    score = min(100, identity_pts + entropy_pts + pe_pts + yara_pts + vt_pts)

    if score >= VERDICT_THRESHOLDS["suspicious"]:
        verdict = "malicious"
    elif score >= VERDICT_THRESHOLDS["clean"]:
        verdict = "suspicious"
    else:
        verdict = "clean"

    return {
        "score": score,
        "verdict": verdict,
        "breakdown": breakdown,
    }
