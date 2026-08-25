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
    "openrouter": "stealth/ox-alpha",
    "google": "gemini-3.6-flash",
    "openai": "gpt-4o-mini",
    "anthropic": "claude-3-5-haiku-20241022",
}

OPENROUTER_FALLBACK_MODELS = [
    "stealth/ox-alpha",
    "poolside/laguna-s-2.1:free",
    "cohere/north-mini-code:free",
    "dots-studio/dots-3-note-preview:free",
]

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


def _safe_post(url, headers, json_data, timeout=35):
    # Strict TLS verification: truststore ensures system certificates are used without unsafe fallback
    return requests.post(url, headers=headers, json=json_data, timeout=timeout)


def clean_ai_output(text):
    if not text:
        return ""
    import re
    # 1. Remove XML-style reasoning/thinking blocks (<think>...</think>)
    text = re.sub(r"<think>[\s\S]*?</think>", "", text, flags=re.DOTALL)
    # 2. Strip any 'Thinking Process:' preamble before the first real section header
    match = re.search(r"(🎯|⚡|⚠️|🛡️|EN RÉSUMÉ|OVERVIEW)", text, flags=re.IGNORECASE)
    if match:
        text = text[match.start():]
    lines = []
    for line in text.splitlines():
        trimmed = line.strip()
        # Remove any leading markdown hashtags (#, ##, ###)
        if re.match(r"^#{1,6}\s*", trimmed):
            clean_h = re.sub(r"^#{1,6}\s*", "", trimmed)
            clean_h = re.sub(r"^\d+[\.\)]\s*", "", clean_h)
            lines.append("")
            lines.append(clean_h)
        else:
            lines.append(line)
    cleaned = "\n".join(lines)
    return re.sub(r"\n{3,}", "\n\n", cleaned).strip()


def build_system_prompt(lang="fr"):
    if lang == "en":
        return (
            "You are an elite Senior Cybersecurity Analyst. "
            "Analyze the technical data from MalyxScanner and generate a concise, visual, and highly readable executive brief.\n\n"
            "CRITICAL FORMAT RULES:\n"
            "- Start DIRECTLY with '🎯 OVERVIEW'. Never output thinking steps or 'Thinking Process:'.\n"
            "- Do NOT use any markdown hashtags (#, ##, ###).\n"
            "- Use clean bold headings with emojis, and bullet points (•).\n"
            "- Be concise and punchy. Maximum 200-250 words total.\n"
            "- No greeting, no introduction, no academic fluff.\n\n"
            "MANDATORY STRUCTURE:\n"
            "🎯 OVERVIEW\n"
            "• Real Identity : [Exact nature & purpose of this file]\n"
            "• Verdict : [Direct, unambiguous verdict in 1 sentence]\n\n"
            "⚡ CONCRETE TECHNICAL CAPABILITIES\n"
            "• 🌐 Network : [Connections, downloads or telemetry]\n"
            "• 🧠 Memory & Process : [Injection, execution or evasion behaviors]\n"
            "• ⚙️ System & Persistence : [Registry, autorun or system alterations]\n\n"
            "⚠️ REAL RISKS FOR YOU\n"
            "• [Key direct risk in 1 line]\n"
            "• [Secondary nuance in 1 line]\n\n"
            "🛡️ RECOMMENDED ACTION\n"
            "• [Clear, direct step-by-step guidance]"
        )
    return (
        "Tu es un Analyste Senior en Cybersécurité d'élite. "
        "Analyse les données techniques brutes de MalyxScanner et génère un brief d'expertise ultra-clair, visuel, direct et aéré.\n\n"
        "RÈGLES DE FORMATAGE OBLIGATOIRES :\n"
        "- Commence DIRECTEMENT par '🎯 EN RÉSUMÉ'. N'écris JAMAIS de 'Thinking Process' ou d'étapes de réflexion.\n"
        "- N'utilise AUCUN symbole hashtag (#, ##, ###).\n"
        "- Utilise uniquement des titres clairs en MAJUSCULES avec des emojis, et des puces (•).\n"
        "- Sois synthétique et percutant. 200 à 250 mots maximum au total.\n"
        "- Pas de bonjour, pas de blabla d'introduction ni de conclusion théorique.\n\n"
        "STRUCTURE OBLIGATOIRE :\n"
        "🎯 EN RÉSUMÉ\n"
        "• Nature réelle : [Identité exacte et finalité concrète du binaire]\n"
        "• Verdict : [Avis franc, direct et sans détour en 1 phrase]\n\n"
        "⚡ CAPACITÉS TECHNIQUES CONCRÈTES\n"
        "• 🌐 Réseau : [Téléchargements / Communications / Mises à jour]\n"
        "• 🧠 Mémoire & Processus : [Comportements d'injection / Exécution mémoire]\n"
        "• ⚙️ Système & Persistance : [Démarrage automatique / Clés de registre]\n\n"
        "⚠️ RISQUES RÉELS POUR VOUS\n"
        "• [Risque principal concret en 1 phrase simple]\n"
        "• [Risque secondaire ou nuance éventuelle en 1 phrase]\n\n"
        "🛡️ ACTION RECOMMANDÉE\n"
        "• [Conseil immédiat, clair et précis sur ce qu'il faut faire]"
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
        "pe_authenticode_signed": pe.get("info", {}).get("is_signed", sec_flags.get("has_digital_signature")),
        "pe_debug_pdb_path": pe.get("info", {}).get("pdb_path"),
        "pe_subsystem": pe.get("info", {}).get("subsystem"),
        "pe_mitre_apis": {k: len(v) for k, v in mitre.items() if v},
        "extracted_commands": strings.get("commands", [])[:8],
        "extracted_urls": strings.get("urls", [])[:8],
        "extracted_ips": strings.get("ips", [])[:4],
        "extracted_registry_keys": strings.get("registry", [])[:4],
        "extracted_ransom_keywords": strings.get("ransom", [])[:4],
        "yara_matches": [m.get("rule") for m in yara.get("matches", [])],
        "virustotal_malicious_count": vt.get("malicious", 0),
        "virustotal_total_engines": vt.get("total_engines", 0),
    }

    txt_json = json.dumps(summary, indent=2, ensure_ascii=False)
    if lang == "en":
        return f"Technical scan data:\n```json\n{txt_json}\n```\nProvide your concise executive analysis:"
    return f"Données techniques du scan :\n```json\n{txt_json}\n```\nRédige ton brief d'expertise synthétique et visuel :"


def query_ai_analyst(result, ai_config, lang="fr"):
    provider = ai_config.get("provider", "openrouter").lower()
    raw_api_key = ai_config.get("api_key", "")
    # Strict ASCII sanitization: remove bullets, smart quotes, zero-width spaces, and control characters
    api_key = "".join(c for c in str(raw_api_key).strip().strip("'\"“”‘’") if 32 < ord(c) < 127)
    model = ai_config.get("model", "").strip() or DEFAULT_MODELS.get(provider, "stealth/ox-alpha")

    if not api_key:
        raise ValueError("Clé API manquante ou invalide. Saisissez votre véritable clé API dans les Réglages ⚙ (ex: sk-or-v1-...).")

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

        # Build prioritized models list to guarantee a successful generation
        target_models = [model] if model else []
        for fb in OPENROUTER_FALLBACK_MODELS:
            if fb not in target_models:
                target_models.append(fb)

        last_error = None
        for m in target_models:
            body = {
                "model": m,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                "temperature": 0.2,
                "max_tokens": 1200,
            }
            try:
                resp = _safe_post(PROVIDER_URLS["openrouter"], headers, body, timeout=25)
            except requests.exceptions.RequestException as exc:
                last_error = f"Erreur de connexion OpenRouter : {exc}"
                continue

            if resp.status_code != 200:
                last_error = _format_api_error("OpenRouter", resp.status_code, resp.text)
                continue

            data = resp.json()
            choices = data.get("choices")
            if not choices:
                continue
            choice = choices[0]
            msg = choice.get("message", {})
            raw_content = msg.get("content") or choice.get("text") or msg.get("reasoning") or ""
            cleaned = clean_ai_output(raw_content)

            # Check for non-empty actual report (not a safety classifier stub like "User Safety: safe")
            if len(cleaned) < 80 or "User Safety:" in cleaned:
                continue

            return cleaned

        raise RuntimeError(last_error or "Impossible de générer le rapport IA. Veuillez vérifier vos réglages ou réessayer.")

    # 2. Google Gemini API
    elif provider == "google":
        clean_model = model.replace("models/", "").strip()
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{clean_model}:generateContent?key={api_key}"
        headers = {"Content-Type": "application/json"}
        body = {
            "system_instruction": {"parts": [{"text": system_prompt}]},
            "contents": [{"parts": [{"text": user_prompt}]}],
            "generationConfig": {"temperature": 0.2, "maxOutputTokens": 1000},
        }
        try:
            resp = _safe_post(url, headers, body, timeout=35)
        except requests.exceptions.RequestException as exc:
            raise RuntimeError(f"Erreur de connexion Google Gemini : {exc}") from exc

        if resp.status_code == 404 and clean_model != "gemini-3.6-flash":
            fallback_url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-3.6-flash:generateContent?key={api_key}"
            try:
                resp = _safe_post(fallback_url, headers, body, timeout=35)
            except Exception:
                pass

        if resp.status_code != 200:
            raise RuntimeError(_format_api_error("Google Gemini", resp.status_code, resp.text))
        data = resp.json()
        try:
            raw_text = data["candidates"][0]["content"]["parts"][0]["text"]
            return clean_ai_output(raw_text)
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
            "temperature": 0.2,
            "max_tokens": 1000,
        }
        try:
            resp = _safe_post(PROVIDER_URLS["openai"], headers, body, timeout=35)
        except requests.exceptions.RequestException as exc:
            raise RuntimeError(f"Erreur de connexion OpenAI : {exc}") from exc
        if resp.status_code != 200:
            raise RuntimeError(_format_api_error("OpenAI", resp.status_code, resp.text))
        data = resp.json()
        choices = data.get("choices")
        if not choices:
            raise RuntimeError("Réponse vide d'OpenAI.")
        content = choices[0].get("message", {}).get("content") or ""
        return clean_ai_output(content)

    # 4. Anthropic Claude
    elif provider == "anthropic":
        headers = {
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
        body = {
            "model": model,
            "max_tokens": 1000,
            "system": system_prompt,
            "messages": [{"role": "user", "content": user_prompt}],
            "temperature": 0.2,
        }
        try:
            resp = _safe_post(PROVIDER_URLS["anthropic"], headers, body, timeout=35)
        except requests.exceptions.RequestException as exc:
            raise RuntimeError(f"Erreur de connexion Anthropic : {exc}") from exc
        if resp.status_code != 200:
            raise RuntimeError(_format_api_error("Anthropic", resp.status_code, resp.text))
        data = resp.json()
        return clean_ai_output(data.get("content", [{}])[0].get("text", ""))

    else:
        raise ValueError(f"Fournisseur IA non reconnu : {provider}")
