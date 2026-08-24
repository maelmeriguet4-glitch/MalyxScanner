import json
import sys
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
        "model": "openrouter/free",
        "auto_analyze": False,
    },
    "contact": {
        "developer_email": "maelmeriguet4@proton.me",
    },
}


def load_config():
    cfg = json.loads(json.dumps(DEFAULTS))
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            user = json.load(f)
    except (OSError, json.JSONDecodeError):
        return cfg
    for k, v in user.items():
        if isinstance(v, dict) and isinstance(cfg.get(k), dict):
            cfg[k].update(v)
        else:
            cfg[k] = v
    return cfg


def save_config(cfg):
    try:
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2, ensure_ascii=False)
    except OSError:
        pass
