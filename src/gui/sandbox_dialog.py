"""
MalyxScanner — Windows Sandbox Activation Guide Dialog
Displays an intuitive visual walkthrough and provides 1-click system shortcuts
to enable Windows Sandbox on Windows 10/11 Pro.
"""

from __future__ import annotations

import logging
import os
import subprocess
import tkinter as tk
from tkinter import messagebox

import customtkinter as ctk

from .theme_manager import get_theme

logger = logging.getLogger("MalyxSandboxDialog")


class SandboxGuideDialog(ctk.CTkToplevel):
    """Modern modal window guiding the user to activate Windows Sandbox."""

    def __init__(self, master, theme: dict = None, **kwargs):
        super().__init__(master, **kwargs)
        self.theme = theme or get_theme("cyber_dark")

        self.title("⚡ Activation de Windows Sandbox")
        self.geometry("640x520")
        self.minsize(580, 480)
        self.transient(master)
        self.configure(fg_color=self.theme.get("bg", "#0d1117"))
        self.grab_set()

        self._build_ui()

    def _build_ui(self):
        theme = self.theme

        # Top Header
        top_header = ctk.CTkFrame(self, fg_color=theme.get("header", "#161b22"), corner_radius=0, border_width=1, border_color=theme.get("border", "#30363d"))
        top_header.pack(fill="x")

        h_inner = ctk.CTkFrame(top_header, fg_color="transparent")
        h_inner.pack(fill="x", padx=20, pady=14)

        ctk.CTkLabel(
            h_inner,
            text="⚡ Activation de Windows Sandbox",
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color=theme.get("text", "#e6edf3"),
        ).pack(anchor="w")

        ctk.CTkLabel(
            h_inner,
            text="Testez vos fichiers suspects dans un environnement virtuel 100% isolé et sécurisé.",
            font=ctk.CTkFont(size=12),
            text_color="#58a6ff",
        ).pack(anchor="w", pady=(2, 0))

        # Main Scrollable Content Card
        scroll = ctk.CTkScrollableFrame(self, fg_color=theme.get("card", "#161b22"), corner_radius=10)
        scroll.pack(fill="both", expand=True, padx=16, pady=(12, 10))

        # Status Info Card
        status_card = ctk.CTkFrame(scroll, fg_color="#332408", corner_radius=8, border_width=1, border_color="#d29922")
        status_card.pack(fill="x", padx=10, pady=(10, 12))
        s_inner = ctk.CTkFrame(status_card, fg_color="transparent")
        s_inner.pack(fill="x", padx=14, pady=10)

        ctk.CTkLabel(
            s_inner,
            text="ℹ️ La fonctionnalité « Bac à sable Windows » n'est pas encore activée.",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color="#e3b341",
            anchor="w",
        ).pack(fill="x")

        ctk.CTkLabel(
            s_inner,
            text="Votre système est compatible (Windows 11 Pro). Il vous suffit de cocher une case dans les fonctionnalités Windows pour l'activer.",
            font=ctk.CTkFont(size=11),
            text_color="#f0f6fc",
            wraplength=520,
            justify="left",
            anchor="w",
        ).pack(fill="x", pady=(3, 0))

        # Step-by-step instructions
        steps_card = ctk.CTkFrame(scroll, fg_color=theme.get("subcard", "#21262d"), corner_radius=8, border_width=1, border_color=theme.get("border", "#30363d"))
        steps_card.pack(fill="x", padx=10, pady=(0, 12))
        st_inner = ctk.CTkFrame(steps_card, fg_color="transparent")
        st_inner.pack(fill="x", padx=14, pady=12)

        ctk.CTkLabel(
            st_inner,
            text="📋 Procédure simple en 3 étapes :",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=theme.get("text", "#e6edf3"),
            anchor="w",
        ).pack(fill="x", pady=(0, 8))

        steps = [
            ("1.", "Cliquez sur le bouton bleu ci-dessous pour ouvrir la fenêtre des fonctionnalités Windows."),
            ("2.", "Dans la liste qui s'affiche, faites défiler et cochez la case : « Bac à sable Windows » (ou « Windows Sandbox »)."),
            ("3.", "Cliquez sur OK et redémarrez votre ordinateur quand Windows vous le demande."),
        ]

        for num, desc in steps:
            row = ctk.CTkFrame(st_inner, fg_color="transparent")
            row.pack(fill="x", pady=4)
            ctk.CTkLabel(
                row,
                text=num,
                font=ctk.CTkFont(size=13, weight="bold"),
                text_color="#1f6feb",
                width=24,
            ).pack(side="left", anchor="n")
            ctk.CTkLabel(
                row,
                text=desc,
                font=ctk.CTkFont(size=12),
                text_color="#e6edf3",
                wraplength=480,
                justify="left",
            ).pack(side="left", fill="x", expand=True)

        # Action Buttons inside card
        btn_row = ctk.CTkFrame(scroll, fg_color="transparent")
        btn_row.pack(fill="x", padx=10, pady=(0, 10))

        ctk.CTkButton(
            btn_row,
            text="🚀 Ouvrir les fonctionnalités Windows (Étape 1)",
            font=ctk.CTkFont(size=13, weight="bold"),
            fg_color="#1f6feb",
            hover_color="#388bfd",
            height=40,
            command=self._open_optional_features,
        ).pack(fill="x", pady=(0, 6))

        ctk.CTkButton(
            btn_row,
            text="📋 Copier la commande PowerShell (Alternative Admin)",
            font=ctk.CTkFont(size=11),
            fg_color="#21262d",
            hover_color="#30363d",
            text_color=theme.get("text", "#e6edf3"),
            height=32,
            command=self._copy_powershell_cmd,
        ).pack(fill="x")

        # Bottom Bar
        bottom = ctk.CTkFrame(self, fg_color="transparent")
        bottom.pack(side="bottom", fill="x", padx=20, pady=12)

        ctk.CTkButton(
            bottom,
            text="Fermer",
            width=120,
            height=36,
            font=ctk.CTkFont(size=12),
            fg_color="#21262d",
            hover_color="#30363d",
            command=self.destroy,
        ).pack(side="right")

    def _open_optional_features(self):
        """Launches the native Windows Optional Features dialogue directly."""
        try:
            subprocess.Popen(["optionalfeatures.exe"])
        except Exception as exc:
            logger.error("Failed to launch optionalfeatures.exe: %s", exc)
            messagebox.showerror(
                "Erreur",
                f"Impossible d'ouvrir automatiquement les fonctionnalités Windows :\n{exc}\n\n"
                "Ouvrez manuellement le menu Démarrer et tapez « Activer ou désactiver des fonctionnalités Windows ».",
            )

    def _copy_powershell_cmd(self):
        """Copies the PowerShell admin command to clipboard."""
        cmd = 'Enable-WindowsOptionalFeature -Online -FeatureName "Containers-DisposableClientVM" -All'
        self.clipboard_clear()
        self.clipboard_append(cmd)
        messagebox.showinfo(
            "Copié !",
            f"La commande suivante a été copiée dans votre presse-papiers :\n\n{cmd}\n\n"
            "Ouvrez PowerShell en mode Administrateur, collez la commande (Ctrl+V) et appuyez sur Entrée.",
        )
