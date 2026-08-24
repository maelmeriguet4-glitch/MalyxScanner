import json
from datetime import datetime

VERDICT_ICONS = {
    "clean": "[OK]",
    "suspicious": "[!!]",
    "malicious": "[XX]",
}


def _translate_finding(t, finding):
    code = finding.get("code", "")
    params = finding.get("params", {}) or {}
    text = t.t(code, **params)
    severity = t.t(f"severity.{finding.get('severity', 'info')}")
    return f"[{severity}] {text}"


def render_txt(result, t):
    lines = []
    verdict = result["risk"]["verdict"]
    score = result["risk"]["score"]

    lines.append("=" * 66)
    lines.append(f"  {t.t('app.title')} — {t.t('app.subtitle')}")
    lines.append("=" * 66)
    lines.append("")
    lines.append(f"{t.t('field.name')} : {result.get('file', {}).get('name', '?')}")
    lines.append(f"{t.t('field.path')} : {result.get('file', {}).get('path', '?')}")
    lines.append(f"{t.t('field.size')} : {result.get('file', {}).get('size_human', '?')} ({result.get('file', {}).get('size', 0)} octets)")
    lines.append(f"{t.t('field.modified')} : {result.get('file', {}).get('modified', '?')}")
    lines.append(f"{t.t('field.sha256')} : {result.get('hashes', {}).get('sha256', '?')}")
    lines.append(f"{t.t('field.md5')} : {result.get('hashes', {}).get('md5', '?')}")
    if result.get('hashes', {}).get('imphash'):
        lines.append(f"{t.t('field.imphash')} : {result['hashes']['imphash']}")
    lines.append("")
    icon = VERDICT_ICONS.get(verdict, "[??]")
    lines.append(f"  {icon} {t.t('verdict.' + verdict)} — {t.t('score.label')} : {score}/100")
    lines.append(f"  {t.t('verdict.desc_' + verdict)}")
    lines.append("")

    # Threat & Execution Advice
    threat_key = result.get("threat", {}).get("type", "clean")
    lines.append("-" * 66)
    lines.append(f"  {t.t('threat.title')} : {t.t('threat.type.' + threat_key)}")
    lines.append("-" * 66)
    lines.append(f"  {t.t('threat.desc.' + threat_key)}")
    lines.append("")
    
    advice = result.get("execution_advice", {})
    adv_status = advice.get("advice_status", "safe")
    lines.append(f"  [{t.t('execution.status.' + adv_status)}]")
    lines.append(f"  {t.t(advice.get('message_key', 'execution.safe_message'))}")
    lines.append("")
    
    risks = advice.get("risks", [])
    if risks and threat_key != "clean":
        lines.append("  " + t.t("execution.risks_title"))
        for r_key in risks:
            lines.append(f"    * {t.t(r_key)}")
        lines.append("")

    actions = advice.get("actions", [])
    if actions:
        lines.append("  " + t.t("execution.actions_title"))
        for a_key in actions:
            lines.append(f"    * {t.t(a_key)}")
        lines.append("")

    # Identity
    lines.append("-" * 66)
    lines.append(t.t("tabs.identity"))
    lines.append("-" * 66)
    identity = result.get("identity", {})
    lines.append(f"{t.t('field.type_declared')} : {identity.get('extension') or '?'}")
    real = identity.get("human_type") or identity.get("mime") or t.t("misc.unknown")
    lines.append(f"{t.t('field.type_real')} : {real}")
    lines.append(f"{t.t('field.sha512')} : {result.get('hashes', {}).get('sha512', '?')}")
    lines.append(f"{t.t('field.sha1')} : {result.get('hashes', {}).get('sha1', '?')}")
    lines.append(f"{t.t('field.crc32')} : {result.get('hashes', {}).get('crc32', '?')}")
    for finding in identity.get("findings", []):
        if finding.get("code") != "find.type_ok":
            lines.append(f"  * {_translate_finding(t, finding)}")
    lines.append("")

    # Entropy
    lines.append("-" * 66)
    lines.append(t.t("tabs.entropy"))
    lines.append("-" * 66)
    ent_data = result.get("entropy", {})
    if ent_data.get("global") is not None:
        lines.append(f"Entropie globale : {ent_data['global']}/8.00 ({ent_data.get('level', 'normal')})")
        blocks = ent_data.get("blocks", {})
        if blocks.get("total_blocks"):
            lines.append(f"Blocs totaux : {blocks['total_blocks']} (Min: {blocks['min']}, Max: {blocks['max']}, Moyenne: {blocks['avg']})")
            lines.append(f"Blocs hautement entropiques (> 7.2) : {blocks['high_count']}")
    lines.append("")

    # PE
    pe = result.get("pe", {})
    if pe.get("applicable"):
        lines.append("-" * 66)
        lines.append(t.t("tabs.pe"))
        lines.append("-" * 66)
        if not pe.get("parsed"):
            lines.append(_translate_finding(t, {"code": "pe.parse_failed", "severity": "medium", "params": {}}))
        else:
            info = pe.get("info", {})
            if info.get("machine"):
                lines.append(f"{t.t('pe_info.machine')} : {info['machine']}")
            if info.get("subsystem"):
                lines.append(f"{t.t('pe_info.subsystem')} : {info['subsystem']}")
            lines.append(f"{t.t('pe_info.signed')} : {t.t('misc.yes') if info.get('is_signed') else t.t('misc.no')}")
            lines.append(f"{t.t('pe_info.dotnet')} : {t.t('misc.yes') if info.get('is_dotnet') else t.t('misc.no')}")
            if info.get("pdb_path"):
                lines.append(f"{t.t('pe_info.pdb')} : {info['pdb_path']}")
            if info.get("compiled"):
                lines.append(f"{t.t('pe_info.timestamp')} : {info['compiled']}")
            
            sections = info.get("sections", [])
            if sections:
                lines.append(f"{t.t('pe_info.sections')} ({len(sections)}) :")
                for section in sections:
                    flags = f" [{section['flags']}]" if section.get("flags") else ""
                    lines.append(f"  - {section['name']} — {section['size']} o — entropie {section['entropy']:.2f}{flags}")
            
            mitre_apis = info.get("mitre_apis", {})
            if mitre_apis:
                lines.append("Comportements d'APIs détectés :")
                for cat, apis in mitre_apis.items():
                    lines.append(f"  [{cat.upper()}] : {', '.join(apis)}")

            for finding in pe.get("findings", []):
                lines.append(f"  * {_translate_finding(t, finding)}")
        lines.append("")

    # Strings & IOCs
    strings_data = result.get("strings", {})
    if any(strings_data.get(k) for k in ("urls", "ips", "commands", "registry", "ransom")):
        lines.append("-" * 66)
        lines.append(t.t("tabs.strings"))
        lines.append("-" * 66)
        if strings_data.get("urls"):
            lines.append(f"URLs ({len(strings_data['urls'])}) :")
            for u in strings_data["urls"][:10]:
                lines.append(f"  - {u}")
        if strings_data.get("ips"):
            lines.append(f"IPs ({len(strings_data['ips'])}) :")
            for ip in strings_data["ips"][:10]:
                lines.append(f"  - {ip}")
        if strings_data.get("commands"):
            lines.append(f"Commandes système ({len(strings_data['commands'])}) :")
            for cmd in strings_data["commands"][:10]:
                lines.append(f"  - {cmd}")
        if strings_data.get("ransom"):
            lines.append(f"Indicateurs Ransomware ({len(strings_data['ransom'])}) :")
            for r in strings_data["ransom"][:10]:
                lines.append(f"  - {r}")
        lines.append("")

    # YARA
    lines.append("-" * 66)
    lines.append(t.t("tabs.yara"))
    lines.append("-" * 66)
    yara_res = result.get("yara", {})
    if not yara_res.get("available"):
        lines.append(t.t("yara.disabled"))
    else:
        matches = yara_res.get("matches", [])
        if matches:
            for match in matches:
                lines.append(f"  * {_translate_finding(t, {'code': 'yara.match', 'severity': match['severity'], 'params': {'rule': match['rule'], 'desc': match['description']}})}")
        else:
            lines.append(t.t("yara.none"))
    lines.append("")

    # VirusTotal
    lines.append("-" * 66)
    lines.append(t.t("tabs.vt"))
    lines.append("-" * 66)
    vt = result.get("virustotal", {})
    status = vt.get("status")
    if status == "disabled":
        lines.append(t.t("vt.disabled"))
    elif status == "not_found":
        lines.append(t.t("vt.not_found"))
    elif status == "found":
        malicious = vt.get("malicious", 0)
        total = vt.get("total_engines", 0)
        ratio = round(100 * malicious / total) if total else 0
        if malicious:
            lines.append(t.t("vt.found", malicious=malicious, total=total))
        else:
            lines.append(t.t("vt.found_none", total=total))
        lines.append(t.t("vt.ratio", ratio=ratio))
        flagged = vt.get("flagged_by", [])
        if flagged:
            lines.append(t.t("vt.flagged_by"))
            for engine in flagged[:15]:
                lines.append(f"  - {engine['engine']} : {engine['result']}")
    elif status == "error_auth":
        lines.append(t.t("vt.error_auth"))
    elif status == "error_rate":
        lines.append(t.t("vt.error_rate"))
    elif status == "error_network":
        lines.append(t.t("vt.error_network"))
    lines.append("")

    if result.get("ai_report"):
        lines.append("-" * 66)
        lines.append(f"  {t.t('tabs.ai_report')}")
        lines.append("-" * 66)
        lines.append(result["ai_report"])
        lines.append("")

    lines.append("-" * 66)
    lines.append(t.t("tabs.privacy"))
    lines.append("-" * 66)
    lines.append(t.t("privacy.line1"))
    lines.append(t.t("privacy.line2"))
    lines.append(t.t("privacy.telemetry"))
    lines.append("")
    lines.append(f"— {t.t('app.title')} · {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    return "\n".join(lines)


def save_json(result, path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)


def save_txt(text, path):
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
