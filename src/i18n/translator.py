import json
from pathlib import Path

I18N_DIR = Path(__file__).resolve().parent

_LANGS = None


def _i18n_dir():
    base = resource_base() / "src" / "i18n"
    if base.exists():
        return base
    return I18N_DIR


def available_languages():
    global _LANGS
    if _LANGS is None:
        directory = _i18n_dir()
        _LANGS = sorted(p.stem for p in directory.glob("*.json"))
    return list(_LANGS)


def resource_base():
    import sys

    if getattr(sys, "frozen", False):
        return Path(getattr(sys, "_MEIPASS", Path(sys.executable).resolve().parent))
    return Path(__file__).resolve().parents[1]


class Translator:
    def __init__(self, lang="fr"):
        self.lang = lang
        self._data = {}
        self._fallback = {}
        self._load()

    def _load(self):
        base = _i18n_dir()
        try:
            with open(base / f"{self.lang}.json", "r", encoding="utf-8") as f:
                self._data = json.load(f)
        except (OSError, json.JSONDecodeError):
            self._data = {}
        if self.lang != "en":
            try:
                with open(base / "en.json", "r", encoding="utf-8") as f:
                    self._fallback = json.load(f)
            except (OSError, json.JSONDecodeError):
                self._fallback = {}
        else:
            self._fallback = {}

    def t(self, key, **kwargs):
        value = self._get(self._data, key)
        if value is None:
            value = self._get(self._fallback, key)
        if value is None:
            return key
        if kwargs:
            try:
                return value.format(**kwargs)
            except (KeyError, IndexError, ValueError):
                return value
        return value

    @staticmethod
    def _get(data, key):
        node = data
        for part in key.split("."):
            if isinstance(node, dict) and part in node:
                node = node[part]
            else:
                return None
        return node if isinstance(node, str) else None
