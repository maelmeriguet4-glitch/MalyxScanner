"""
MalyxScanner — AI Cybersecurity Analyst Engine
Connects to OpenRouter, Google Gemini, OpenAI, or Anthropic Claude
to generate tailored, deep, and non-repetitive threat intelligence reports.
"""

import json
import requests

try:
    import truststore
    truststore.inject_into_ssl()
except Exception:
    pass

DEFAULT_MODELS = {
    "openrouter": "google/gemini-2.0-flash-001",
    "google": "gemini-3.6-flash",
    "openai": "gpt-4o-mini",
    "anthropic": "claude-3-5-haiku-20241022",
}

PROVIDER_URLS = {
    "openrouter": "https://openrouter.ai/api/v1/chat/completions",
    "openai": "https://api.openai.com/v1/chat/completions",
    "anthropic": "https://api.anthropic.com/v1/messages",
}


def _format_api_error(provider_name, status_code, raw_text):
    msg = ""
    try:
        data = json.loads(raw_text)
        if "error" in data:
            if isinstance(data["error"], dict):
                msg = data["error"].get("message", "")
            elif isinstance(data["error"], str):
                msg = data["error"]
    except Exception:
        msg = raw_text

    if status_code == 429:
        return (
            f"⚠️ Quota ou crédits épuisés ({provider_name} 429) :\n"
            f"{msg or 'Vos crédits/quotas chez ce fournisseur sont épuisés.'}\n\n"
            f"💡 Solutions :\n"
            f"  1. Rechargez vos crédits chez {provider_name}\n"
            f"  2. Ou utilisez OpenRouter avec un modèle gratuit (ex: deepseek/deepseek-r1:free ou meta-llama/llama-3.3-70b-instruct:free)"
        )
    elif status_code in (401, 403):
        return (
            f"🔑 Clé API invalide ou non autorisée ({provider_name} {status_code}) :\n"
            f"{msg or 'Vérifiez la clé API saisie dans les Réglages ⚙.'}"
        )
    elif status_code == 404:
        detail = msg or "Ce modèle n'est pas disponible sur votre compte."
        return (
            f"❌ Modèle introuvable ({provider_name} 404) :\n"
            f"{detail}\n"
            f"💡 Essayez un autre modèle dans les Réglages ⚙ (ex: gemini-3.6-flash ou gemini-flash-latest)."
        )
    return f"Erreur {provider_name} ({status_code}) : {msg or raw_text}"


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
        "Tu es un Analyste Senior en Cybersécurité et Ingénieur en Rétro-Ingénierie Malware de haut niveau. "
        "Ton rôle est d'analyser le rapport technique brut fourni par le scanner MalyxScanner et de produire "
        "une analyse humaine, vivante, personnalisée, concrète et NON RÉPÉTITIVE pour l'utilisateur.\n\n"
        "Ne récite pas de généralités. Base-toi précisément sur les APIs Windows extraites (MITRE ATT&CK), "
        "les hachages, l'entropie par bloc, les IOCs, les chaînes suspectes et les signatures pour expliquer les "
        "pouvoirs réels et les capacités techniques de ce binaire.\n\n"
        "Structure obligatoirement ta réponse avec ces 4 sections Markdown claires et détaillées :\n"
        "### 1. 📌 Nature & Identité Réelle du Fichier\n"
        "(Explique concrètement de quoi il s'agit, au-delà de son extension déclarée)\n\n"
        "### 2. ⚡ Pouvoirs & Capacités Techniques Concrètes\n"
        "(Détaille exactement ce que ce programme est techniquement capable de faire sur le système selon ses APIs et IOCs)\n\n"
        "### 3. 🎯 Vecteurs d'Attaque & Risques pour l'Utilisateur\n"
        "(Quels sont les impacts directs : vol de mots de passe, chiffrement, prise de contrôle à distance, surveillance, etc.)\n\n"
        "### 4. 🛡️ Recommandation & Avis d'Exécution sur-mesure\n"
        "(Donne un verdict franc et direct : l'utilisateur peut-il l'exécuter ? Quelles mesures immédiates doit-il prendre ?)"
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
        raise ValueError("Clé API manquante pour l'analyste IA. Saisissez votre clé dans les Réglages ⚙.")

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
        try:
            resp = requests.post(PROVIDER_URLS["openrouter"], headers=headers, json=body, timeout=45)
        except requests.exceptions.RequestException as exc:
            raise RuntimeError(f"Erreur de connexion OpenRouter : {exc}") from exc
        if resp.status_code != 200:
            raise RuntimeError(_format_api_error("OpenRouter", resp.status_code, resp.text))
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
        try:
            resp = requests.post(url, headers=headers, json=body, timeout=45)
        except requests.exceptions.RequestException as exc:
            raise RuntimeError(f"Erreur de connexion Google Gemini : {exc}") from exc

        if resp.status_code == 404 and clean_model != "gemini-3.6-flash":
            # Fallback to standard 3.6 flash
            fallback_url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-3.6-flash:generateContent?key={api_key}"
            try:
                resp = requests.post(fallback_url, headers=headers, json=body, timeout=45)
            except Exception:
                pass

        if resp.status_code != 200:
            raise RuntimeError(_format_api_error("Google Gemini", resp.status_code, resp.text))
        data = resp.json()
        try:
            return data["candidates"][0]["content"]["parts"][0]["text"]
        except (KeyError, IndexError) as exc:
            raise RuntimeError(f"Réponse inattendue de Gemini : {data}") from exc

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
        try:
            resp = requests.post(PROVIDER_URLS["openai"], headers=headers, json=body, timeout=45)
        except requests.exceptions.RequestException as exc:
            raise RuntimeError(f"Erreur de connexion OpenAI : {exc}") from exc
        if resp.status_code != 200:
            raise RuntimeError(_format_api_error("OpenAI", resp.status_code, resp.text))
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
        try:
            resp = requests.post(PROVIDER_URLS["anthropic"], headers=headers, json=body, timeout=45)
        except requests.exceptions.RequestException as exc:
            raise RuntimeError(f"Erreur de connexion Anthropic : {exc}") from exc
        if resp.status_code != 200:
            raise RuntimeError(_format_api_error("Anthropic", resp.status_code, resp.text))
        data = resp.json()
        return data["content"][0]["text"]

    else:
        raise ValueError(f"Fournisseur IA non reconnu : {provider}")
