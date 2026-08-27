"""
MalyxScanner — Custom Tkinter Toast Notification Engine
Provides a 100% native, borderless, non-blocking alert popup at the bottom-left of the screen
upon threat detection, with SOC-grade severity color coding and 1-click scanner activation.
"""

from __future__ import annotations

import logging
from pathlib import Path
import tkinter as tk
from typing import Callable, Optional, Union

try:
    import customtkinter as ctk
    _BaseToplevel = ctk.CTkToplevel
except ImportError:
    ctk = None
    _BaseToplevel = tk.Toplevel

logger = logging.getLogger("MalyxToast")

# --- Layout & Dimension Constants ---
TOAST_WIDTH: int = 380
TOAST_HEIGHT: int = 165
TASKBAR_OFFSET_Y: int = 70
SCREEN_MARGIN_X: int = 24
DEFAULT_AUTO_DISMISS_MS: int = 10000

# --- Severity Palettes ---
ALERT_THEMES = {
    "malicious": {
        "severity": "malicious",
        "accent": "#E11D48",          # Vivid Rose / Crimson Red
        "bg": "#1E1E2E",
        "card_bg": "#252538",
        "border": "#E11D48",
        "badge_bg": "#3D1424",
        "badge_fg": "#FF5252",
        "title_color": "#FF5252",
        "icon": "🚨",
        "title": "Alerte Menace Détectée",
        "btn_bg": "#E11D48",
        "btn_hover": "#BE123C",
        "btn_text": "#FFFFFF",
        "close_hover": "#FF5252",
    },
    "suspicious": {
        "severity": "suspicious",
        "accent": "#FF9800",          # Vivid Amber Orange
        "bg": "#1E1E2E",
        "card_bg": "#252538",
        "border": "#FF9800",
        "badge_bg": "#3D2B14",
        "badge_fg": "#FFA726",
        "title_color": "#FFA726",
        "icon": "⚠️",
        "title": "Fichier Suspect Détecté",
        "btn_bg": "#FF9800",
        "btn_hover": "#F57C00",
        "btn_text": "#1E1E2E",
        "close_hover": "#FFA726",
    },
}

THREAT_LABELS = {
    "ransomware": "Ransomware (Chiffreur)",
    "trojan": "Cheval de Troie (Trojan)",
    "infostealer": "Voleur de Mots de Passe (InfoStealer)",
    "cryptominer": "Mineur Crypto Furtif",
    "dropper": "Téléchargeur Malveillant (Dropper)",
    "dangerous_script": "Script Suspect Détecté",
    "untrusted_pe": "Exécutable Inconnu / Non Signé",
    "suspicious_file": "Fichier Suspect Détecté",
}


def truncate_filename(name: str, max_chars: int = 34) -> str:
    """Truncates long filenames with middle ellipsis to retain file extension."""
    if not name:
        return ""
    if len(name) <= max_chars:
        return name
    p = Path(name)
    suffix = p.suffix
    stem = p.stem
    if len(suffix) >= max_chars - 6:
        return f"{name[:max_chars - 3]}..."
    available_stem = max_chars - len(suffix) - 3
    if available_stem > 3:
        return f"{stem[:available_stem]}...{suffix}"
    return f"{name[:max_chars - 3]}..."


def calculate_geometry(
    screen_w: int,
    screen_h: int,
    width: int = TOAST_WIDTH,
    height: int = TOAST_HEIGHT,
) -> str:
    """Calculates bottom-left screen position for the toast window."""
    x = SCREEN_MARGIN_X
    y = max(10, screen_h - height - TASKBAR_OFFSET_Y)
    return f"{width}x{height}+{x}+{y}"


class SentinelToast(_BaseToplevel):
    """
    Borderless, non-blocking custom Tkinter toast popup positioned at the bottom-left of the screen.
    Displays threat summary and provides a 1-click action button to open MalyxScanner.
    """

    def __init__(
        self,
        master=None,
        file_path: Union[Path, str] = "",
        scan_result: Optional[dict] = None,
        on_open_scanner: Optional[Callable[[Path], None]] = None,
        auto_dismiss_ms: int = DEFAULT_AUTO_DISMISS_MS,
        **kwargs,
    ) -> None:
        self.file_path = Path(file_path) if file_path else Path()
        self.scan_result = dict(scan_result or {})
        self.on_open_scanner = on_open_scanner
        self.auto_dismiss_ms = int(auto_dismiss_ms)
        self._timer_id: Optional[str] = None
        self._is_dismissed: bool = False

        # 1. Determine severity and color coding
        risk = self.scan_result.get("risk", {})
        score = risk.get("score", 0)
        if "risk_score" in self.scan_result:
            score = max(score, self.scan_result["risk_score"])
        verdict = str(risk.get("verdict", "")).lower()
        if not verdict and "verdict" in self.scan_result:
            verdict = str(self.scan_result["verdict"]).lower()

        threat_info = self.scan_result.get("execution_advice", {})
        threat_type = self.scan_result.get("threat", {}).get(
            "type", threat_info.get("threat_type", "suspicious_file")
        )
        advice_status = threat_info.get(
            "advice_status", "caution" if score < 50 else "danger"
        )

        if (
            score >= 50
            or verdict in ("malicious", "danger", "critical")
            or threat_type in ("ransomware", "trojan", "infostealer", "cryptominer", "dropper")
            or advice_status == "danger"
        ):
            self.severity: str = "malicious"
            self.theme_data: dict = ALERT_THEMES["malicious"]
        else:
            self.severity: str = "suspicious"
            self.theme_data: dict = ALERT_THEMES["suspicious"]

        self.accent_color: str = self.theme_data["accent"]

        # 2. Initialize Base Toplevel (CTkToplevel / Toplevel)
        super().__init__(master, **kwargs)

        # 3. Configure window behavior & styling
        try:
            self.withdraw()
            self.overrideredirect(True)
            self.attributes("-topmost", True)
            if hasattr(self, "configure"):
                self.configure(fg_color=self.theme_data["bg"])
        except Exception as exc:
            logger.debug("Toplevel attribute setup warning: %s", exc)

        # 4. Build UI
        try:
            self._build_ui(score, threat_type)
        except Exception as exc:
            logger.debug("UI build warning: %s", exc)

        # 5. Bind hover pause events
        try:
            self.bind("<Enter>", self._on_mouse_enter)
            self.bind("<Leave>", self._on_mouse_leave)
        except Exception as exc:
            logger.debug("Binding warning: %s", exc)

    def _build_ui(self, score: int, threat_type: str) -> None:
        """Constructs the visual components of the toast card."""
        theme = self.theme_data

        if ctk is None:
            self._build_ui_tk(score, threat_type)
            return

        # Outer card container
        self.card = ctk.CTkFrame(
            self,
            fg_color=theme["bg"],
            corner_radius=12,
            border_width=2,
            border_color=theme["border"],
        )
        self.card.pack(fill="both", expand=True, padx=2, pady=2)

        # --- Header ---
        header_frame = ctk.CTkFrame(self.card, fg_color="transparent")
        header_frame.pack(fill="x", padx=12, pady=(10, 4))

        # Icon badge
        badge_box = ctk.CTkFrame(header_frame, fg_color=theme["badge_bg"], corner_radius=6)
        badge_box.pack(side="left", padx=(0, 8))
        ctk.CTkLabel(
            badge_box,
            text=theme["icon"],
            font=ctk.CTkFont(size=13),
            width=24,
            height=24,
        ).pack(padx=2, pady=1)

        # Title
        ctk.CTkLabel(
            header_frame,
            text=theme["title"],
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=theme["title_color"],
        ).pack(side="left")

        # Close button (X)
        self.close_btn = ctk.CTkButton(
            header_frame,
            text="✕",
            width=22,
            height=22,
            corner_radius=11,
            fg_color="transparent",
            hover_color=theme["close_hover"],
            text_color="#8B949E",
            font=ctk.CTkFont(size=11, weight="bold"),
            command=self.dismiss,
        )
        self.close_btn.pack(side="right")

        # --- Body ---
        body_frame = ctk.CTkFrame(self.card, fg_color="transparent")
        body_frame.pack(fill="x", padx=12, pady=(2, 4))

        # File name
        raw_name = self.file_path.name if self.file_path.name else "fichier_inconnu"
        truncated_name = truncate_filename(raw_name, max_chars=34)
        ctk.CTkLabel(
            body_frame,
            text=f"📄 {truncated_name}",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color="#F0F6FC",
            anchor="w",
        ).pack(fill="x")

        # Threat label & score
        label_text = THREAT_LABELS.get(threat_type, "Menace Potentielle")
        ctk.CTkLabel(
            body_frame,
            text=f"🏷️ {label_text} • Score : {score}/100",
            font=ctk.CTkFont(size=11),
            text_color=theme["badge_fg"],
            anchor="w",
        ).pack(fill="x", pady=(2, 0))

        # Action / Guidance prompt
        guidance = "Ne pas exécuter. Cliquez ci-dessous pour analyser en profondeur."
        ctk.CTkLabel(
            body_frame,
            text=guidance,
            font=ctk.CTkFont(size=10),
            text_color="#8B949E",
            anchor="w",
        ).pack(fill="x", pady=(1, 0))

        # --- Footer / Action Button ---
        footer_frame = ctk.CTkFrame(self.card, fg_color="transparent")
        footer_frame.pack(fill="x", padx=12, pady=(6, 10))

        self.action_btn = ctk.CTkButton(
            footer_frame,
            text="🔍 N'hésitez pas à scanner sur MalyxScanner",
            font=ctk.CTkFont(size=12, weight="bold"),
            fg_color=theme["btn_bg"],
            hover_color=theme["btn_hover"],
            text_color=theme["btn_text"],
            height=32,
            corner_radius=8,
            command=self._on_action_clicked,
        )
        self.action_btn.pack(fill="x")

    def _build_ui_tk(self, score: int, threat_type: str) -> None:
        """Fallback Tkinter UI when CTk is not available."""
        theme = self.theme_data
        self.card = tk.Frame(self, bg=theme["bg"], highlightbackground=theme["border"], highlightthickness=2)
        self.card.pack(fill="both", expand=True, padx=2, pady=2)

        header_frame = tk.Frame(self.card, bg=theme["bg"])
        header_frame.pack(fill="x", padx=12, pady=(10, 4))

        icon_lbl = tk.Label(header_frame, text=theme["icon"], bg=theme["badge_bg"], fg=theme["badge_fg"])
        icon_lbl.pack(side="left", padx=(0, 8))

        title_lbl = tk.Label(header_frame, text=theme["title"], bg=theme["bg"], fg=theme["title_color"], font=("Arial", 10, "bold"))
        title_lbl.pack(side="left")

        close_btn = tk.Button(header_frame, text="✕", bg=theme["bg"], fg="#8B949E", bd=0, command=self.dismiss)
        close_btn.pack(side="right")

        body_frame = tk.Frame(self.card, bg=theme["bg"])
        body_frame.pack(fill="x", padx=12, pady=(2, 4))

        raw_name = self.file_path.name if self.file_path.name else "fichier_inconnu"
        truncated_name = truncate_filename(raw_name, max_chars=34)
        file_lbl = tk.Label(body_frame, text=f"📄 {truncated_name}", bg=theme["bg"], fg="#F0F6FC", anchor="w", font=("Arial", 9, "bold"))
        file_lbl.pack(fill="x")

        label_text = THREAT_LABELS.get(threat_type, "Menace Potentielle")
        threat_lbl = tk.Label(body_frame, text=f"🏷️ {label_text} • Score : {score}/100", bg=theme["bg"], fg=theme["badge_fg"], anchor="w")
        threat_lbl.pack(fill="x")

        guidance_lbl = tk.Label(body_frame, text="Ne pas exécuter. Cliquez ci-dessous pour analyser.", bg=theme["bg"], fg="#8B949E", anchor="w", font=("Arial", 8))
        guidance_lbl.pack(fill="x")

        footer_frame = tk.Frame(self.card, bg=theme["bg"])
        footer_frame.pack(fill="x", padx=12, pady=(6, 10))

        action_btn = tk.Button(
            footer_frame,
            text="🔍 N'hésitez pas à scanner sur MalyxScanner",
            bg=theme["btn_bg"],
            fg=theme["btn_text"],
            font=("Arial", 9, "bold"),
            command=self._on_action_clicked,
        )
        action_btn.pack(fill="x")

    def show(self) -> None:
        """Calculates bottom-left geometry and displays the toast popup."""
        try:
            self.update_idletasks()
            screen_w = self.winfo_screenwidth()
            screen_h = self.winfo_screenheight()

            geom = calculate_geometry(screen_w, screen_h, TOAST_WIDTH, TOAST_HEIGHT)
            self.geometry(geom)
            self.deiconify()
            self.lift()
            self.attributes("-topmost", True)

            # Start auto-dismiss timer
            self._start_timer(self.auto_dismiss_ms)
        except Exception as exc:
            logger.warning("Error showing toast popup: %s", exc)

    def dismiss(self) -> None:
        """Safely dismisses the toast window and cancels pending timers."""
        if self._is_dismissed:
            return
        self._is_dismissed = True

        self._cancel_timer()
        try:
            self.destroy()
        except Exception as exc:
            logger.debug("Error destroying toast window: %s", exc)

    def _start_timer(self, delay_ms: int) -> None:
        """Starts the auto-dismiss timer."""
        self._cancel_timer()
        if delay_ms > 0:
            try:
                self._timer_id = self.after(delay_ms, self.dismiss)
            except Exception:
                pass

    def _cancel_timer(self) -> None:
        """Cancels any pending auto-dismiss timer."""
        if self._timer_id is not None:
            try:
                self.after_cancel(self._timer_id)
            except Exception:
                pass
            self._timer_id = None

    def _on_mouse_enter(self, _event=None) -> None:
        """Pauses the auto-dismiss timer when the user hovers over the toast."""
        self._cancel_timer()

    def _on_mouse_leave(self, _event=None) -> None:
        """Resumes auto-dismiss timer (5s countdown) when cursor leaves the toast."""
        if not self._is_dismissed:
            self._start_timer(5000)

    def _on_action_clicked(self) -> None:
        """Handles action button click: dismisses toast and triggers on_open_scanner callback."""
        file_path = self.file_path
        callback = self.on_open_scanner

        self.dismiss()

        if callback and callable(callback):
            try:
                callback(file_path)
            except Exception as exc:
                logger.error("Error in on_open_scanner callback: %s", exc, exc_info=True)
