"""
MalyxScanner — Theme Manager
Provides palettes and visual style presets for the CustomTkinter GUI.
"""

THEMES = {
    "cyber_dark": {
        "name": "Cyber Dark (Défaut SOC)",
        "bg": "#0d1117",
        "card": "#161b22",
        "subcard": "#0d1117",
        "header": "#161b22",
        "border": "#30363d",
        "accent": "#1f6feb",
        "accent_hover": "#1158c7",
        "text": "#f0f6fc",
        "subtext": "#8b949e",
        "code_text": "#58a6ff",
        "appearance_mode": "Dark",
    },
    "midnight_blue": {
        "name": "Midnight Blue (Nuit Profonde)",
        "bg": "#0b132b",
        "card": "#1c2541",
        "subcard": "#0b132b",
        "header": "#1c2541",
        "border": "#3a506b",
        "accent": "#0096c7",
        "accent_hover": "#023e8a",
        "text": "#edf2f4",
        "subtext": "#8d99ae",
        "code_text": "#48cae4",
        "appearance_mode": "Dark",
    },
    "oled_black": {
        "name": "OLED Black (Noir Pur)",
        "bg": "#000000",
        "card": "#121212",
        "subcard": "#000000",
        "header": "#121212",
        "border": "#27272a",
        "accent": "#3b82f6",
        "accent_hover": "#1d4ed8",
        "text": "#fafafa",
        "subtext": "#a1a1aa",
        "code_text": "#60a5fa",
        "appearance_mode": "Dark",
    },
    "matrix": {
        "name": "Matrix Emerald (Hacker Vert)",
        "bg": "#050d08",
        "card": "#0d1f14",
        "subcard": "#050d08",
        "header": "#0d1f14",
        "border": "#1b4d2e",
        "accent": "#00cc55",
        "accent_hover": "#009940",
        "text": "#e6ffe6",
        "subtext": "#66aa77",
        "code_text": "#33ff77",
        "appearance_mode": "Dark",
    },
    "light": {
        "name": "Light Mode (Clair Moderne)",
        "bg": "#f6f8fa",
        "card": "#ffffff",
        "subcard": "#f6f8fa",
        "header": "#ffffff",
        "border": "#d0d7de",
        "accent": "#0969da",
        "accent_hover": "#054da7",
        "text": "#1f2328",
        "subtext": "#656d76",
        "code_text": "#0969da",
        "appearance_mode": "Light",
    },
}


def get_theme(theme_name=None):
    if not theme_name or theme_name not in THEMES:
        return THEMES["cyber_dark"]
    return THEMES[theme_name]


def available_themes():
    return list(THEMES.keys())
