"""
MalyxScanner — Quarantine Management UI Panel
Provides a full graphical interface to inspect, restore, or securely shred quarantined files.
"""

from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path
from tkinter import messagebox
from typing import Callable, Optional

import customtkinter as ctk

try:
    from core.remediation import (
        delete_quarantined_file,
        list_quarantined_files,
        purge_all_quarantine,
        restore_quarantined_file,
    )
except (ImportError, ValueError):
    from ..core.remediation import (
        delete_quarantined_file,
        list_quarantined_files,
        purge_all_quarantine,
        restore_quarantined_file,
    )

logger = logging.getLogger("MalyxQuarantinePanel")


class QuarantinePanel(ctk.CTkFrame):
    """Scrollable panel showing quarantined files with restoration and shredding controls."""

    def __init__(
        self,
        master,
        theme: dict,
        translator=None,
        on_restored: Optional[Callable[[str], None]] = None,
        **kwargs,
    ):
        super().__init__(master, fg_color=theme.get("bg", "#0d1117"), **kwargs)
        self.theme = theme
        self.t = translator
        self.on_restored = on_restored

        self._build_header()
        self._build_list()
        self.refresh()

    def _build_header(self):
        theme = self.theme
        header = ctk.CTkFrame(self, fg_color=theme.get("card", "#161b22"), corner_radius=10)
        header.pack(fill="x", padx=16, pady=(12, 6))

        h_inner = ctk.CTkFrame(header, fg_color="transparent")
        h_inner.pack(fill="x", padx=14, pady=10)

        ctk.CTkLabel(
            h_inner,
            text="🛡️ Espace de Quarantaine",
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
            text="🗑️ Vider la quarantaine",
            width=150,
            height=30,
            font=ctk.CTkFont(size=11),
            fg_color="#21262d",
            hover_color="#da3633",
            text_color=theme.get("text", "#e6edf3"),
            command=self._on_purge_all,
        ).pack(side="right")

        ctk.CTkButton(
            h_inner,
            text="🔄 Actualiser",
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
        """Reloads and re-renders all quarantined files."""
        for child in self.scroll_frame.winfo_children():
            child.destroy()

        items = list_quarantined_files()
        self.count_label.configure(text=f"({len(items)} élément{'s' if len(items) != 1 else ''} neutralisé{'s' if len(items) != 1 else ''})")

        if not items:
            ctk.CTkLabel(
                self.scroll_frame,
                text="🛡️ Aucun fichier en quarantaine.\n\nLes fichiers suspects ou dangereux que vous isolez seront neutralisés et listés ici.",
                font=ctk.CTkFont(size=13),
                text_color=self.theme.get("subtext", "#8b949e"),
                justify="center",
            ).pack(pady=60)
            return

        for item in items:
            self._render_item(item)

    def _render_item(self, item: dict):
        theme = self.theme
        score = item.get("scan_metadata", {}).get("risk", {}).get("score", 0)
        verdict = item.get("scan_metadata", {}).get("risk", {}).get("verdict", "malicious")

        border_color = "#f85149" if score >= 50 or verdict == "malicious" else "#e3b341"

        card = ctk.CTkFrame(
            self.scroll_frame,
            fg_color=theme.get("card", "#161b22"),
            corner_radius=8,
            border_width=1,
            border_color=border_color,
        )
        card.pack(fill="x", padx=4, pady=4)

        inner = ctk.CTkFrame(card, fg_color="transparent")
        inner.pack(fill="x", padx=12, pady=10)

        # Left Info Block
        left = ctk.CTkFrame(inner, fg_color="transparent")
        left.pack(side="left", fill="x", expand=True)

        original_name = item.get("original_name", "fichier_inconnu")
        ctk.CTkLabel(
            left,
            text=f"🔒 {original_name}",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=theme.get("text", "#e6edf3"),
            anchor="w",
        ).pack(fill="x")

        orig_path = item.get("original_path", "")
        ctk.CTkLabel(
            left,
            text=f"Emplacement d'origine : {orig_path}",
            font=ctk.CTkFont(size=10),
            text_color=theme.get("subtext", "#8b949e"),
            anchor="w",
        ).pack(fill="x", pady=(2, 0))

        size_kb = item.get("file_size", 0) / 1024
        size_str = f"{size_kb / 1024:.1f} Mo" if size_kb >= 1024 else f"{size_kb:.0f} Ko"
        q_date = item.get("quarantined_at", "")

        ctk.CTkLabel(
            left,
            text=f"Isolé le : {q_date}  •  Taille : {size_str}  •  Statut : Neutralisé (Chiffré XOR)",
            font=ctk.CTkFont(size=10),
            text_color="#3fb950",
            anchor="w",
        ).pack(fill="x", pady=(2, 0))

        # Right Action Buttons Block
        right = ctk.CTkFrame(inner, fg_color="transparent")
        right.pack(side="right", padx=(10, 0))

        qid = item.get("id")

        ctk.CTkButton(
            right,
            text="🔄 Restaurer",
            width=100,
            height=28,
            font=ctk.CTkFont(size=11),
            fg_color="#21262d",
            hover_color="#238636",
            text_color=theme.get("text", "#e6edf3"),
            command=lambda q=qid, name=original_name, p=orig_path: self._on_restore(q, name, p),
        ).pack(side="left", padx=3)

        ctk.CTkButton(
            right,
            text="🗑️ Supprimer",
            width=100,
            height=28,
            font=ctk.CTkFont(size=11),
            fg_color="#21262d",
            hover_color="#da3633",
            text_color=theme.get("text", "#e6edf3"),
            command=lambda q=qid, name=original_name: self._on_delete(q, name),
        ).pack(side="left", padx=3)

    def _on_restore(self, qid: str, file_name: str, orig_path: str):
        confirm = messagebox.askyesno(
            "Confirmer la Restauration",
            f"Voulez-vous vraiment restaurer le fichier suivant ?\n\n"
            f"Fichier : {file_name}\n"
            f"Destination : {orig_path}\n\n"
            f"⚠️ Attention : Si ce fichier était malveillant, il redeviendra exécutable sur votre système.",
        )
        if not confirm:
            return

        success, msg = restore_quarantined_file(qid)
        if success:
            messagebox.showinfo("Restauration Réussie", msg)
            self.refresh()
            if self.on_restored and orig_path:
                self.on_restored(orig_path)
        else:
            messagebox.showerror("Erreur de Restauration", msg)

    def _on_delete(self, qid: str, file_name: str):
        confirm = messagebox.askyesno(
            "Confirmer la Suppression Définitive",
            f"Voulez-vous détruire définitivement ce fichier de la quarantaine ?\n\n"
            f"Fichier : {file_name}\n\n"
            f"⚠️ Cette action effectuera un déchiquetage sécurisé (shredding) et sera irréversible.",
        )
        if not confirm:
            return

        success, msg = delete_quarantined_file(qid)
        if success:
            messagebox.showinfo("Suppression Réussie", msg)
            self.refresh()
        else:
            messagebox.showerror("Erreur de Suppression", msg)

    def _on_purge_all(self):
        items = list_quarantined_files()
        if not items:
            messagebox.showinfo("Quarantaine", "La quarantaine est déjà vide.")
            return

        confirm = messagebox.askyesno(
            "Vider toute la Quarantaine",
            f"Êtes-vous sûr de vouloir supprimer définitivement les {len(items)} fichier(s) de la quarantaine ?\n\n"
            f"⚠️ Tous les fichiers seront déchiquetés et irrécupérables.",
        )
        if not confirm:
            return

        deleted, failed = purge_all_quarantine()
        messagebox.showinfo(
            "Purge Terminée",
            f"Opération terminée :\n• {deleted} fichier(s) supprimé(s) définitivement.\n• {failed} échec(s).",
        )
        self.refresh()
