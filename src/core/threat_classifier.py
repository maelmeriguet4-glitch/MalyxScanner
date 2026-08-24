"""
MalyxScanner — Threat Classification & Execution Advice Engine
Heuristically classifies threats (Ransomware, Trojan, InfoStealer, Cryptominer, Dropper, etc.)
and generates plain-language, actionable execution guidance to protect users.
"""


def classify_threat(identity, entropy, pe, yara, virustotal, strings, risk):
    score = risk.get("score", 0)
    verdict = risk.get("verdict", "clean")
    family = identity.get("family", "other")
    
    # Extract signals
    yara_matches = yara.get("matches", [])
    yara_texts = " ".join([m.get("rule", "") + " " + m.get("description", "") for m in yara_matches]).lower()
    
    mitre_apis = pe.get("info", {}).get("mitre_apis", {})
    has_injection = bool(mitre_apis.get("injection"))
    has_network = bool(mitre_apis.get("network"))
    has_execution = bool(mitre_apis.get("execution"))
    has_persistence = bool(mitre_apis.get("persistence"))
    has_hooking = bool(mitre_apis.get("hooking"))
    has_antidebug = bool(mitre_apis.get("antidebug"))
    has_crypto = bool(mitre_apis.get("crypto"))

    strings_ransom = bool(strings.get("ransom"))
    strings_cmds = strings.get("commands", [])
    cmd_text = " ".join(strings_cmds).lower()
    
    vt_malicious = virustotal.get("malicious", 0)
    vt_flagged_text = " ".join([f.get("result", "") for f in virustotal.get("flagged_by", [])]).lower()
    
    # Hard indicators
    has_hard_ransom = strings_ransom or "vssadmin" in cmd_text or "ransom" in yara_texts or "ransom" in vt_flagged_text
    has_hard_miner = "miner" in yara_texts or "coinminer" in vt_flagged_text or "stratum+tcp" in cmd_text or "xmrig" in cmd_text or "monero" in cmd_text
    has_hard_stealer = "stealer" in yara_texts or "stealer" in vt_flagged_text or "spyware" in vt_flagged_text or ("discord" in cmd_text and "token" in cmd_text)
    has_hard_dropper = "dropper" in yara_texts or "downloader" in yara_texts or "downloader" in vt_flagged_text
    has_hard_trojan = "trojan" in yara_texts or "rat" in yara_texts or "backdoor" in yara_texts or "trojan" in vt_flagged_text

    # 1. Evaluate Threat Type
    threat_type = "clean"
    
    # If the file is evaluated as CLEAN with a low score (< 20) and no hard evidence, it's CLEAN
    if verdict == "clean" and score < 20 and not (has_hard_ransom or has_hard_miner or has_hard_stealer or has_hard_dropper or has_hard_trojan):
        threat_type = "clean"
    # Ransomware check
    elif has_hard_ransom or (has_crypto and (has_persistence or has_injection) and score >= 40):
        threat_type = "ransomware"
    # Cryptominer check
    elif has_hard_miner or ("stratum" in cmd_text and score >= 30):
        threat_type = "cryptominer"
    # InfoStealer / Spyware check
    elif has_hard_stealer or (has_hooking and (has_network or has_persistence) and score >= 35):
        threat_type = "infostealer"
    # Dropper / Downloader check
    elif has_hard_dropper or (has_network and has_execution and score >= 35):
        threat_type = "dropper"
    # Trojan / RAT / Backdoor check
    elif has_hard_trojan or (has_injection and score >= 35) or (has_antidebug and has_network and score >= 45) or score >= 50:
        threat_type = "trojan"
    # Dangerous Script check
    elif family in ("code", "executable") and identity.get("extension") in (".bat", ".cmd", ".ps1", ".vbs", ".wsf") and (score >= 20 or strings_cmds):
        threat_type = "dangerous_script"
    # Suspicious binary / untrusted check
    elif score >= 20:
        threat_type = "untrusted_pe" if family == "executable" else "suspicious_file"
    else:
        threat_type = "clean"

    # 2. Determine Execution Advice & Concrete Risks
    potential_risks = []
    actions = []
    
    if score >= 50 or (threat_type in ("ransomware", "trojan", "infostealer", "cryptominer", "dropper") and score >= 30):
        advice_status = "danger"
        title = "danger_title"
        message = "danger_message"
        
        if threat_type == "ransomware":
            potential_risks.extend([
                "risk.ransomware_encrypt",
                "risk.ransomware_backup",
                "risk.ransomware_extortion",
            ])
        elif threat_type == "infostealer":
            potential_risks.extend([
                "risk.stealer_passwords",
                "risk.stealer_banking",
                "risk.stealer_discord",
            ])
        elif threat_type == "cryptominer":
            potential_risks.extend([
                "risk.miner_cpu_gpu",
                "risk.miner_hardware_damage",
                "risk.miner_freeze",
            ])
        elif threat_type == "dropper":
            potential_risks.extend([
                "risk.dropper_secondary",
                "risk.dropper_backdoor",
                "risk.dropper_c2",
            ])
        else:  # Trojan / Generic high risk
            potential_risks.extend([
                "risk.trojan_takeover",
                "risk.trojan_spyware",
                "risk.trojan_injection",
                "risk.trojan_data_loss",
            ])
            
        actions.extend([
            "action.delete_immediately",
            "action.empty_trash",
            "action.do_not_run_admin",
            "action.run_antivirus_scan",
        ])

    elif score >= 20 or verdict == "suspicious" or threat_type in ("dangerous_script", "untrusted_pe", "suspicious_file"):
        advice_status = "caution"
        title = "caution_title"
        message = "caution_message"
        
        potential_risks.extend([
            "risk.caution_unsigned",
            "risk.caution_unexpected_behavior",
            "risk.caution_system_change",
        ])
        
        actions.extend([
            "action.verify_source",
            "action.use_windows_sandbox",
            "action.check_virustotal",
            "action.do_not_disable_defender",
        ])
    else:
        advice_status = "safe"
        title = "safe_title"
        message = "safe_message"
        potential_risks.append("risk.safe_no_threat")
        actions.append("action.safe_ok_to_open")

    return {
        "threat_type": threat_type,
        "advice_status": advice_status,
        "title_key": f"execution.{title}",
        "message_key": f"execution.{message}",
        "risks": potential_risks,
        "actions": actions,
    }
