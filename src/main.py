import sys
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parent
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

try:
    import truststore
    truststore.inject_into_ssl()
except Exception:
    pass

import customtkinter as ctk

from app_config import load_config, save_config
from i18n.translator import Translator
from gui.app import MalyxApp


def create_root():
    try:
        import tkinterdnd2

        class DndRoot(ctk.CTk, tkinterdnd2.TkinterDnD.DnDWrapper):
            def __init__(self, **kwargs):
                super().__init__(**kwargs)
                self.TkdndVersion = tkinterdnd2.TkinterDnD._require(self)

        return DndRoot(), True
    except Exception:
        return ctk.CTk(), False


def _find_icon():
    candidates = [
        Path(getattr(sys, "_MEIPASS", "")) / "assets" / "icon.ico",
        SRC_DIR.parent / "assets" / "icon.ico",
        SRC_DIR / "assets" / "icon.ico",
        Path("assets/icon.ico"),
    ]
    for c in candidates:
        if c and c.is_file():
            return str(c)
    return None


def main():
    config = load_config()
    translator = Translator(config.get("language", "fr"))

    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("blue")

    root, _ = create_root()

    icon_path = _find_icon()
    if icon_path:
        try:
            root.iconbitmap(icon_path)
        except Exception:
            pass

    app = MalyxApp(root, translator, config, save_config)
    root.mainloop()


if __name__ == "__main__":
    main()
