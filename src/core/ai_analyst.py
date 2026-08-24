"""
MalyxScanner — AI Cybersecurity Analyst Engine
Connects to OpenRouter, Google Gemini, OpenAI, or Anthropic Claude
to generate tailored, deep, and non-repetitive threat intelligence reports.
"""

import json
import requests

DEFAULT_MODELS = {
    "openrouter": "google/gemini-2.0-flash-001",
    "google": "gemini-1.5-flash",
    "openai": "gpt-4o-mini",
    "anthropic": "claude-3-5-haiku-20241022",
}

PROVIDER_URLS = {
    "openrouter": "https://openrouter.ai/api/v1/chat/completions",
    "openai": "https://api.openai.com/v1/chat/completions",
    "anthropic": "https://api.anthropic.com/v1/messages",
}


def build_system_prompt(lang="fr"):
    if lang == "en":
        return (
            "You are an elite Senior Cybersecurity Analyst & Malware Reverse Engineer. "
            "Your role is to analyze the technical scan report provided by MalyxScanner and generate a clear, "
            "concrete, non-repetitive, and actionable analysis for the user.\n\n"
            "Format your response in structured Markdown with these exact sections:\n"
            "### 1. 📌 Nature & Exact Identity of the File\n"
            "(Explain what this file specifically is, beyond its declared name)\n\n"
            "### 2. ⚡ Concrete Powers & Technical Capabilities\n"
            "(Detail specifically what this file can do on the OS based on the imported APIs, commands, and IOCs)\n\n"
            "### 3. 🎯 Attack Vectors & Risks for the User\n"
            "(Explain the real consequences: data theft, backdoor access, encryption, persistence, hardware abuse)\n\n"
            "### 4. 🛡️ Tailored Security Recommendation\n"
            "(Clear verdict: can the user run it? If suspicious, what exact actions to take)"
        )
    return (
        "Tu es un expert Senior en Cybersécurité et Rétro-ingénierie de logiciels malveillants. "
        "Ton rôle est d'analyser le rapport technique fourni par MalyxScanner et de rédiger une explication "
        "concrète, vivante, personnalisée et NON répétitive pour l'utilisateur.\n\n"
        "Structure obligatoirement ta réponse en Markdown avec ces 4 sections claires :\n"
        "### 1. 📌 Nature & Identité Réelle du Fichier\n"
        "(Explique ce qu'est précisément ce fichier au-delà de son nom ou extension déclarée)\n\n"
        "### 2. ⚡ Pouvoirs & Capacités Techniques Concrètes\n"
        "(Détaille concrètement ce que ce fichier est capable de faire sur Windows d'après les APIs importées, commandes et IOCs)\n\n"
        "### 3. 🎯 Vecteurs d'Attaque & Risques pour l'Utilisateur\n"
        "(Explique les conséquences réelles : vol d'identifiants, porte dérobée, chiffrement, persistance au démarrage, etc.)\n\n"
        "### 4. 🛡️ Recommandation & Avis d'Exécution sur-mesure\n"
        "(Verdict clair : peut-on l'exécuter en sécurité ? Quelles actions précises effectuer)"
    )


def build_user_payload(result, lang="fr"):
    file_info = result.get("file", {})
    identity = result.get("identity", {})
    hashes = result.get("hashes", {})
    entropy = result.get("entropy", {})
    pe = result.get("pe", {})
    strings = result.get("strings", {})
    yara = result.get("yara", {})
    vt = result.get("virustotal", {})
    risk = result.get("risk", {})
    threat = result.get("threat", {})

    mitre = pe.get("info", {}).get("mitre_apis", {})
    sec_flags = pe.get("info", {}).get("security_flags", {})

    summary = {
        "filename": file_info.get("name"),
        "size": file_info.get("size_human"),
        "declared_ext": identity.get("extension"),
        "detected_family": identity.get("family"),
        "real_mime": identity.get("mime"),
        "real_human_type": identity.get("human_type"),
        "is_masquerading": identity.get("mismatch"),
        "sha256": hashes.get("sha256"),
        "imphash": hashes.get("imphash"),
        "entropy_global": entropy.get("global"),
        "entropy_level": entropy.get("level"),
        "risk_score": risk.get("score"),
        "risk_verdict": risk.get("verdict"),
        "threat_classification": threat.get("type"),
        "pe_authenticode_signed": sec_flags.get("has_digital_signature"),
        "pe_debug_pdb_path": pe.get("info", {}).get("debug_path"),
        "pe_subsystem": pe.get("info", {}).get("subsystem"),
        "pe_mitre_apis": {k: len(v) for k, v in mitre.items() if v},
        "extracted_commands": strings.get("commands", [])[:10],
        "extracted_urls": strings.get("urls", [])[:10],
        "extracted_ips": strings.get("ips", [])[:5],
        "extracted_registry_keys": strings.get("registry", [])[:5],
        "extracted_ransom_keywords": strings.get("ransom", [])[:5],
        "yara_matches": [m.get("rule") for m in yara.get("matches", [])],
        "virustotal_malicious_count": vt.get("malicious", 0),
    }

    txt_json = json.dumps(summary, indent=2, ensure_ascii=False)
    if lang == "en":
        return f"Please analyze this scan result and provide a comprehensive cybersecurity expert breakdown:\n\n```json\n{txt_json}\n```"
    return f"Voici les données techniques extraites par le scanner. Rédige ton analyse d'expert en cybersécurité :\n\n```json\n{txt_json}\n```"


def query_ai_analyst(result, ai_config, lang="fr"):
    provider = ai_config.get("provider", "openrouter").lower()
    api_key = ai_config.get("api_key", "").strip()
    model = ai_config.get("model", "").strip() or DEFAULT_MODELS.get(provider, "google/gemini-2.0-flash-001")

    if not api_key:
        raise ValueError("Clé API manquante pour l'analyste IA.")

    system_prompt = build_system_prompt(lang)
    user_prompt = build_user_payload(result, lang)

    # 1. OpenRouter
    if provider == "openrouter":
        headers = {
            "Authorization": f"Bearer {api_key}",
            "HTTP-Referer": "https://github.com/maelmeriguet4-glitch/MalyxScanner",
            "X-Title": "MalyxScanner",
            "Content-Type": "application/json",
        }
        body = {
            "model": model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": 0.3,
        }
        resp = requests.post(PROVIDER_URLS["openrouter"], headers=headers, json=body, timeout=45)
        if resp.status_code != 200:
            raise RuntimeError(f"Erreur OpenRouter ({resp.status_code}) : {resp.text}")
        data = resp.json()
        return data["choices"][0]["message"]["content"]

    # 2. Google Gemini API
    elif provider == "google":
        clean_model = model.replace("models/", "").strip()
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{clean_model}:generateContent?key={api_key}"
        headers = {"Content-Type": "application/json"}
        body = {
            "system_instruction": {"parts": [{"text": system_prompt}]},
            "contents": [{"parts": [{"text": user_prompt}]}],
            "generationConfig": {"temperature": 0.3},
        }
        resp = requests.post(url, headers=headers, json=body, timeout=45)
        if resp.status_code == 404 and clean_model != "gemini-1.5-flash":
            # Fallback to standard universal 1.5 flash
            fallback_url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={api_key}"
            resp = requests.post(fallback_url, headers=headers, json=body, timeout=45)
        if resp.status_code != 200:
            raise RuntimeError(f"Erreur Google Gemini ({resp.status_code}) : {resp.text}")
        data = resp.json()
        return data["candidates"][0]["content"]["parts"][0]["text"]

    # 3. OpenAI
    elif provider == "openai":
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }
        body = {
            "model": model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": 0.3,
        }
        resp = requests.post(PROVIDER_URLS["openai"], headers=headers, json=body, timeout=45)
        if resp.status_code != 200:
            raise RuntimeError(f"Erreur OpenAI ({resp.status_code}) : {resp.text}")
        data = resp.json()
        return data["choices"][0]["message"]["content"]

    # 4. Anthropic Claude
    elif provider == "anthropic":
        headers = {
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
        body = {
            "model": model,
            "max_tokens": 2048,
            "system": system_prompt,
            "messages": [{"role": "user", "content": user_prompt}],
            "temperature": 0.3,
        }
        resp = requests.post(PROVIDER_URLS["anthropic"], headers=headers, json=body, timeout=45)
        if resp.status_code != 200:
            raise RuntimeError(f"Erreur Anthropic ({resp.status_code}) : {resp.text}")
        data = resp.json()
        return data["content"][0]["text"]

    else:
        raise ValueError(f"Fournisseur IA inconnu : {provider}")
