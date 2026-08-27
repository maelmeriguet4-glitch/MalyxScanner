import json
import sys
import ctypes
import ctypes.wintypes
import base64
from pathlib import Path


def _config_dir():
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent


CONFIG_PATH = _config_dir() / "config.local.json"

DEFAULTS = {
    "language": "fr",
    "theme": "cyber_dark",
    "sound_alert": False,
    "sentinel": {
        "enabled": True,
        "watch_dir": "",
        "ram_limit_mb": 128,
        "stream_chunk_kb": 64,
        "toast_alert": True,
        "auto_dismiss_sec": 10,
    },
    "performance": {
        "profile": "balanced",  # "balanced", "low_ram", "max_speed"
        "max_file_size_mb": 200,
        "entropy_block_size_kb": 16,
        "enable_yara": True,
        "enable_strings_scan": True,
    },
    "virustotal": {
        "enabled": False,
        "api_key": "",
    },
    "ai_analyst": {
        "enabled": False,
        "provider": "openrouter",
        "api_key": "",
        "model": "stealth/ox-alpha",
        "auto_analyze": False,
    },
    "contact": {
        "developer_email": "maelmeriguet4@proton.me",
    },
}

# --- Chiffrement DPAPI natif (Windows) ---
class DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", ctypes.wintypes.DWORD),
                ("pbData", ctypes.POINTER(ctypes.c_char))]

def _encrypt_string(data_str: str) -> str:
    """Chiffre une chaîne de caractères via DPAPI et retourne du Base64."""
    if not data_str:
        return data_str
    try:
        data_bytes = data_str.encode('utf-8')
        blob_in = DATA_BLOB(len(data_bytes), ctypes.cast(ctypes.c_char_p(data_bytes), ctypes.POINTER(ctypes.c_char)))
        blob_out = DATA_BLOB()
        # 1 = CRYPTPROTECT_UI_FORBIDDEN (pas de popup à l'utilisateur)
        if ctypes.windll.crypt32.CryptProtectData(ctypes.byref(blob_in), None, None, None, None, 1, ctypes.byref(blob_out)):
            encrypted_bytes = ctypes.string_at(blob_out.pbData, blob_out.cbData)
            ctypes.windll.Kernel32.LocalFree(blob_out.pbData)
            return base64.b64encode(encrypted_bytes).decode('utf-8')
        return data_str
    except Exception:
        return data_str

def _decrypt_string(encrypted_b64: str) -> str:
    """Déchiffre une chaîne Base64 via DPAPI (retourne du texte clair)."""
    if not encrypted_b64:
        return encrypted_b64
    try:
        encrypted_bytes = base64.b64decode(encrypted_b64)
        blob_in = DATA_BLOB(len(encrypted_bytes), ctypes.cast(ctypes.c_char_p(encrypted_bytes), ctypes.POINTER(ctypes.c_char)))
        blob_out = DATA_BLOB()
        
        if ctypes.windll.crypt32.CryptUnprotectData(ctypes.byref(blob_in), None, None, None, None, 1, ctypes.byref(blob_out)):
            decrypted_bytes = ctypes.string_at(blob_out.pbData, blob_out.cbData)
            ctypes.windll.Kernel32.LocalFree(blob_out.pbData)
            return decrypted_bytes.decode('utf-8')
        return encrypted_b64
    except Exception:
        # En cas d'échec (ex: ancienne clé stockée en clair), on la retourne telle quelle
        return encrypted_b64


def load_config():
    cfg = json.loads(json.dumps(DEFAULTS))
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            user = json.load(f)
    except (OSError, json.JSONDecodeError):
        pass  # On gardera cfg avec ses DEFAULTS, mais on applique quand même le déchiffrement ci-dessous au cas où
    else:
        for k, v in user.items():
            if isinstance(v, dict) and isinstance(cfg.get(k), dict):
                cfg[k].update(v)
            else:
                cfg[k] = v

    # Sentinel Sanitization & Bounds Checking
    sentinel_cfg = cfg.setdefault("sentinel", {})
    if not isinstance(sentinel_cfg.get("enabled"), bool):
        sentinel_cfg["enabled"] = bool(sentinel_cfg.get("enabled", True))
    if not isinstance(sentinel_cfg.get("watch_dir"), str):
        sentinel_cfg["watch_dir"] = str(sentinel_cfg.get("watch_dir", ""))
    try:
        sentinel_cfg["ram_limit_mb"] = max(16, int(sentinel_cfg.get("ram_limit_mb", 128)))
    except (ValueError, TypeError):
        sentinel_cfg["ram_limit_mb"] = 128
    try:
        sentinel_cfg["stream_chunk_kb"] = max(16, int(sentinel_cfg.get("stream_chunk_kb", 64)))
    except (ValueError, TypeError):
        sentinel_cfg["stream_chunk_kb"] = 64
    if not isinstance(sentinel_cfg.get("toast_alert"), bool):
        sentinel_cfg["toast_alert"] = bool(sentinel_cfg.get("toast_alert", True))
    try:
        sentinel_cfg["auto_dismiss_sec"] = max(3, min(60, int(sentinel_cfg.get("auto_dismiss_sec", 10))))
    except (ValueError, TypeError):
        sentinel_cfg["auto_dismiss_sec"] = 10

    # Déchiffrer les clés API en mémoire pour l'application
    if cfg.get("virustotal", {}).get("api_key"):
        cfg["virustotal"]["api_key"] = _decrypt_string(cfg["virustotal"]["api_key"])
    if cfg.get("ai_analyst", {}).get("api_key"):
        cfg["ai_analyst"]["api_key"] = _decrypt_string(cfg["ai_analyst"]["api_key"])

    return cfg


def save_config(cfg):
    # Créer une copie profonde pour ne pas altérer la config en mémoire de l'application
    cfg_to_save = json.loads(json.dumps(cfg))
    
    # Chiffrer les clés API uniquement dans le fichier de sauvegarde
    if cfg_to_save["virustotal"].get("api_key"):
        cfg_to_save["virustotal"]["api_key"] = _encrypt_string(cfg_to_save["virustotal"]["api_key"])
    if cfg_to_save["ai_analyst"].get("api_key"):
        cfg_to_save["ai_analyst"]["api_key"] = _encrypt_string(cfg_to_save["ai_analyst"]["api_key"])

    try:
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(cfg_to_save, f, indent=2, ensure_ascii=False)
    except OSError:
        pass
