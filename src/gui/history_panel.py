"""
MalyxScanner — Detection History UI Panel
Displays a scrollable list of past scans and Sentinel detections.
"""

from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional

import customtkinter as ctk

try:
    from core.history import get_history
except (ImportError, ValueError):
    from ..core.history import get_history

logger = logging.getLogger("MalyxHistoryPanel")

VERDICT_COLORS = {
    "clean": "#3fb950",
    "suspicious": "#e3b341",
    "malicious": "#f85149",
}

VERDICT_ICONS = {
    "clean": "✅",
    "suspicious": "⚠️",
    "malicious": "🚨",
}


class HistoryPanel(ctk.CTkFrame):
    """Scrollable panel showing detection history with color-coded verdict badges."""

    def __init__(
        self,
        master,
        theme: dict,
        translator=None,
        on_rescan: Optional[Callable[[str], None]] = None,
        **kwargs,
    ):
        super().__init__(master, fg_color=theme.get("bg", "#0d1117"), **kwargs)
        self.theme = theme
        self.t = translator
        self.on_rescan = on_rescan

        self._build_header()
        self._build_list()
        self.refresh()

    def _build_header(self):
        theme = self.theme
        is_en = self.t and getattr(self.t, "lang", "fr") == "en"

        header = ctk.CTkFrame(self, fg_color=theme.get("card", "#161b22"), corner_radius=10)
        header.pack(fill="x", padx=16, pady=(12, 6))

        h_inner = ctk.CTkFrame(header, fg_color="transparent")
        h_inner.pack(fill="x", padx=14, pady=10)

        ctk.CTkLabel(
            h_inner,
            text="📋 Detection History" if is_en else "📋 Historique des Détections",
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color=theme.get("text", "#e6edf3"),
        ).pack(side="left")

        self.count_label = ctk.CTkLabel(
            h_inner,
            text="",
            font=ctk.CTkFont(size=12),
            text_color=theme.get("subtext", "#8b949e"),
        )
        self.count_label.pack(side="left", padx=12)

        ctk.CTkButton(
            h_inner,
            text="🗑️ Clear History" if is_en else "🗑️ Effacer l'historique",
            width=140,
            height=30,
            font=ctk.CTkFont(size=11),
            fg_color="#21262d",
            hover_color="#da3633",
            text_color=theme.get("text", "#e6edf3"),
            command=self._on_clear,
        ).pack(side="right")

        ctk.CTkButton(
            h_inner,
            text="🔄 Refresh" if is_en else "🔄 Actualiser",
            width=100,
            height=30,
            font=ctk.CTkFont(size=11),
            fg_color="#21262d",
            hover_color="#30363d",
            text_color=theme.get("text", "#e6edf3"),
            command=self.refresh,
        ).pack(side="right", padx=6)

    def _build_list(self):
        self.scroll_frame = ctk.CTkScrollableFrame(
            self,
            fg_color=self.theme.get("bg", "#0d1117"),
            corner_radius=0,
        )
        self.scroll_frame.pack(fill="both", expand=True, padx=12, pady=(4, 12))

    def refresh(self):
        """Reloads and re-renders all history entries."""
        # Clear existing items
        for child in self.scroll_frame.winfo_children():
            child.destroy()

        is_en = self.t and getattr(self.t, "lang", "fr") == "en"
        entries = get_history().get_all()

        if is_en:
            count_str = f"({len(entries)} entr{'ies' if len(entries) != 1 else 'y'})"
        else:
            count_str = f"({len(entries)} entrée{'s' if len(entries) != 1 else ''})"

        self.count_label.configure(text=count_str)

        if not entries:
            empty_msg = (
                "No detection recorded yet.\nScan results and Sentinel alerts will appear here."
                if is_en
                else "Aucune détection enregistrée pour le moment.\nLes résultats de vos scans et alertes Sentinelle apparaîtront ici."
            )
            ctk.CTkLabel(
                self.scroll_frame,
                text=empty_msg,
                font=ctk.CTkFont(size=13),
                text_color=self.theme.get("subtext", "#8b949e"),
                justify="center",
            ).pack(pady=60)
            return

        for entry in entries:
            self._render_entry(entry, is_en=is_en)

    def _render_entry(self, entry: dict, is_en: bool = False):
        theme = self.theme
        verdict = entry.get("verdict", "clean")
        color = VERDICT_COLORS.get(verdict, "#8b949e")
        icon = VERDICT_ICONS.get(verdict, "❓")

        card = ctk.CTkFrame(
            self.scroll_frame,
            fg_color=theme.get("card", "#161b22"),
            corner_radius=8,
            border_width=1,
            border_color=color,
        )
        card.pack(fill="x", padx=4, pady=3)

        inner = ctk.CTkFrame(card, fg_color="transparent")
        inner.pack(fill="x", padx=12, pady=8)

        # Left side: icon + file info
        left = ctk.CTkFrame(inner, fg_color="transparent")
        left.pack(side="left", fill="x", expand=True)

        file_name = entry.get("file_name", "unknown" if is_en else "inconnu")
        score = entry.get("risk_score", 0)

        ctk.CTkLabel(
            left,
            text=f"{icon}  {file_name}",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=theme.get("text", "#e6edf3"),
            anchor="w",
        ).pack(fill="x")

        # Details row
        threat_type = entry.get("threat_type", "")
        if is_en:
            source_label = "🛡️ Sentinel" if entry.get("source") == "sentinel" else "🔍 Manual Scan"
        else:
            source_label = "🛡️ Sentinelle" if entry.get("source") == "sentinel" else "🔍 Scan manuel"

        size_mb = entry.get("file_size", 0) / (1024 * 1024)
        if is_en:
            size_str = f"{size_mb:.1f} MB" if size_mb >= 1 else f"{entry.get('file_size', 0) / 1024:.0f} KB"
        else:
            size_str = f"{size_mb:.1f} Mo" if size_mb >= 1 else f"{entry.get('file_size', 0) / 1024:.0f} Ko"

        detail_parts = [source_label, f"Score: {score}/100", size_str]
        if threat_type and threat_type != "clean":
            detail_parts.insert(1, threat_type)

        ctk.CTkLabel(
            left,
            text="  •  ".join(detail_parts),
            font=ctk.CTkFont(size=10),
            text_color=theme.get("subtext", "#8b949e"),
            anchor="w",
        ).pack(fill="x", pady=(2, 0))

        # Right side: timestamp + rescan button
        right = ctk.CTkFrame(inner, fg_color="transparent")
        right.pack(side="right", padx=(8, 0))

        timestamp = entry.get("timestamp", "")
        if timestamp:
            try:
                dt = datetime.fromisoformat(timestamp)
                ts_display = dt.strftime("%Y-%m-%d %H:%M")
            except (ValueError, TypeError):
                ts_display = str(timestamp)[:16]
        else:
            ts_display = ""

        ctk.CTkLabel(
            right,
            text=ts_display,
            font=ctk.CTkFont(size=10),
            text_color=theme.get("subtext", "#8b949e"),
        ).pack(side="left", padx=(0, 8))

        file_path = entry.get("file_path", "")
        if file_path and self.on_rescan:
            ctk.CTkButton(
                right,
                text="Re-scan" if is_en else "Re-scanner",
                width=80,
                height=26,
                font=ctk.CTkFont(size=11),
                fg_color="#21262d",
                hover_color="#30363d",
                text_color=theme.get("text", "#e6edf3"),
                command=lambda p=file_path: self.on_rescan(p),
            ).pack(side="left")

    def _on_clear(self):
        get_history().clear()
        self.refresh()
