import os
import threading
from tkinter import messagebox
import customtkinter as ctk

from core.ai_analyst import query_ai_analyst
from core.remediation import quarantine_file, delete_file_permanently
from core.sandbox import launch_in_windows_sandbox, is_windows_sandbox_available
from .sandbox_dialog import SandboxGuideDialog


SEVERITY_COLORS = {
    "critical": {"bg": "#3c1116", "fg": "#ff4d4f", "border": "#ff4d4f", "badge": "#ff4d4f"},
    "high": {"bg": "#3d220f", "fg": "#fa8c16", "border": "#fa8c16", "badge": "#fa8c16"},
    "medium": {"bg": "#3a3010", "fg": "#e5b810", "border": "#d4b106", "badge": "#e5b810"},
    "low": {"bg": "#11263c", "fg": "#40a9ff", "border": "#1890ff", "badge": "#40a9ff"},
    "info": {"bg": "#1f2430", "fg": "#8c9ba5", "border": "#30363d", "badge": "#8c9ba5"},
}

SEVERITY_ICONS = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
    "info": "ℹ️",
}

VERDICT_THEMES = {
    "clean": {"bg": "#0e2a1b", "border": "#238636", "text": "#3fb950", "badge_bg": "#238636", "badge_fg": "#ffffff"},
    "suspicious": {"bg": "#332408", "border": "#d29922", "text": "#e3b341", "badge_bg": "#bb8009", "badge_fg": "#ffffff"},
    "malicious": {"bg": "#3d1418", "border": "#da3633", "text": "#f85149", "badge_bg": "#da3633", "badge_fg": "#ffffff"},
}

ADVICE_THEMES = {
    "danger": {"bg": "#3c1116", "border": "#da3633", "title_color": "#ff4d4f", "icon": "🛑"},
    "caution": {"bg": "#332408", "border": "#d29922", "title_color": "#e3b341", "icon": "⚠️"},
    "safe": {"bg": "#0e2a1b", "border": "#238636", "title_color": "#3fb950", "icon": "🟢"},
}

THREAT_ICONS = {
    "ransomware": "🔒",
    "trojan": "🐎",
    "infostealer": "🕵️",
    "cryptominer": "⛏️",
    "dropper": "📦",
    "dangerous_script": "📜",
    "untrusted_pe": "⚠️",
    "suspicious_file": "❓",
    "clean": "🟢",
}


def section_header(parent, title, subtitle=None):
    container = ctk.CTkFrame(parent, fg_color="#161b22", corner_radius=6, border_width=1, border_color="#30363d")
    container.pack(fill="x", padx=4, pady=(12, 6))
    inner = ctk.CTkFrame(container, fg_color="transparent")
    inner.pack(fill="x", padx=12, pady=8)
    ctk.CTkLabel(inner, text=title, font=ctk.CTkFont(size=14, weight="bold"), text_color="#f0f6fc", anchor="w").pack(side="left")
    if subtitle:
        ctk.CTkLabel(inner, text=subtitle, font=ctk.CTkFont(size=12), text_color="#8b949e", anchor="e").pack(side="right")
    return container


def finding_card(parent, t, finding):
    sev = finding.get("severity", "info")
    theme = SEVERITY_COLORS.get(sev, SEVERITY_COLORS["info"])
    params = finding.get("params") or {}
    text = t.t(finding.get("code", ""), **params)
    sev_label = t.t(f"severity.{sev}")

    card = ctk.CTkFrame(
        parent,
        fg_color="#0d1117",
        corner_radius=6,
        border_width=1,
        border_color=theme["border"],
    )
    card.pack(fill="x", padx=4, pady=3)

    inner = ctk.CTkFrame(card, fg_color="transparent")
    inner.pack(fill="x", padx=10, pady=8)

    badge = ctk.CTkFrame(inner, fg_color=theme["bg"], corner_radius=4, border_width=1, border_color=theme["badge"])
    badge.pack(side="left", padx=(0, 10))
    ctk.CTkLabel(
        badge,
        text=f"{SEVERITY_ICONS.get(sev, 'ℹ️')} {sev_label.upper()}",
        font=ctk.CTkFont(size=11, weight="bold"),
        text_color=theme["fg"],
        padx=8,
        pady=2,
    ).pack()

    ctk.CTkLabel(
        inner,
        text=text,
        anchor="w",
        justify="left",
        wraplength=640,
        font=ctk.CTkFont(size=13),
        text_color="#e6edf3",
    ).pack(side="left", fill="x", expand=True)


def info_explanation_card(parent, title, text):
    card = ctk.CTkFrame(parent, fg_color="#0d1117", corner_radius=8, border_width=1, border_color="#21262d")
    card.pack(fill="x", padx=4, pady=(16, 8))

    inner = ctk.CTkFrame(card, fg_color="transparent")
    inner.pack(fill="x", padx=16, pady=12)

    ctk.CTkLabel(
        inner,
        text="💡 " + title,
        font=ctk.CTkFont(size=13, weight="bold"),
        text_color="#58a6ff",
        anchor="w",
    ).pack(anchor="w")

    ctk.CTkLabel(
        inner,
        text=text,
        font=ctk.CTkFont(size=12),
        text_color="#8b949e",
        wraplength=1050,
        justify="left",
        anchor="w",
    ).pack(anchor="w", pady=(6, 0))
    return card


class ResultView(ctk.CTkFrame):
    def __init__(self, master, result, translator, config=None, **kwargs):
        super().__init__(master, fg_color="#0d1117", **kwargs)
        self.result = result
        self.t = translator
        self.config = config or {}
        self.ai_loading = False
        self._build()

    def _build(self):
        t = self.t
        result = self.result
        verdict = result["risk"]["verdict"]
        score = result["risk"]["score"]
        vtheme = VERDICT_THEMES.get(verdict, VERDICT_THEMES["clean"])

        advice = result.get("execution_advice", {})
        adv_status = advice.get("advice_status", "safe" if verdict == "clean" else "danger")
        atheme = ADVICE_THEMES.get(adv_status, ADVICE_THEMES["safe"])

        threat_key = result.get("threat", {}).get("type", "clean")
        threat_name = t.t(f"threat.type.{threat_key}")
        threat_icon = THREAT_ICONS.get(threat_key, "🛡️")

        # --- Top Executive Verdict Banner ---
        banner = ctk.CTkFrame(
            self,
            fg_color=vtheme["bg"],
            corner_radius=10,
            border_width=1,
            border_color=vtheme["border"],
        )
        banner.pack(fill="x", padx=12, pady=(10, 6))

        b_inner = ctk.CTkFrame(banner, fg_color="transparent")
        b_inner.pack(fill="x", padx=16, pady=10)

        # Top row: Big Verdict & Score Box
        top_bar = ctk.CTkFrame(b_inner, fg_color="transparent")
        top_bar.pack(fill="x")

        verdict_badge = ctk.CTkFrame(top_bar, fg_color=vtheme["badge_bg"], corner_radius=6)
        verdict_badge.pack(side="left", padx=(0, 12))
        ctk.CTkLabel(
            verdict_badge,
            text=f"  {t.t('verdict.' + verdict)}  ",
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color=vtheme["badge_fg"],
            pady=4,
        ).pack()

        ctk.CTkLabel(
            top_bar,
            text=t.t("verdict.desc_" + verdict),
            font=ctk.CTkFont(size=13),
            text_color="#e6edf3",
            anchor="w",
        ).pack(side="left", fill="x", expand=True)

        score_box = ctk.CTkFrame(top_bar, fg_color="#0d1117", corner_radius=6, border_width=1, border_color="#30363d")
        score_box.pack(side="right")
        ctk.CTkLabel(
            score_box,
            text=f"  {t.t('score.label')} : {score} / 100  ",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color=vtheme["text"],
            pady=4,
        ).pack()

        # Score progress bar
        bar = ctk.CTkProgressBar(b_inner, height=7, corner_radius=4)
        bar.set(score / 100)
        bar.configure(progress_color=vtheme["badge_bg"], fg_color="#21262d")
        bar.pack(fill="x", pady=(8, 2))

        # --- Actionable Execution Banner ---
        exec_banner = ctk.CTkFrame(
            self,
            fg_color=atheme["bg"],
            corner_radius=8,
            border_width=1,
            border_color=atheme["border"],
        )
        exec_banner.pack(fill="x", padx=12, pady=(0, 8))

        e_inner = ctk.CTkFrame(exec_banner, fg_color="transparent")
        e_inner.pack(fill="x", padx=14, pady=8)

        adv_title = t.t(advice.get("title_key", "execution.safe_title"))
        adv_msg = t.t(advice.get("message_key", "execution.safe_message"))

        ctk.CTkLabel(
            e_inner,
            text=f"{atheme['icon']} {adv_title}",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color=atheme["title_color"],
        ).pack(anchor="w")

        ctk.CTkLabel(
            e_inner,
            text=adv_msg,
            font=ctk.CTkFont(size=12),
            text_color="#e6edf3",
            wraplength=780,
            justify="left",
        ).pack(anchor="w", pady=(2, 0))

        # --- Immediate Remediation Bar (for Moderate/Suspicious & Critical/Malicious files) ---
        file_path = result.get("file", {}).get("path")
        if (verdict in ("suspicious", "malicious") or score >= 40) and file_path:
            self._build_remediation_bar(file_path, verdict)

        # --- Four Metric KPI Cards ---
        cards_frame = ctk.CTkFrame(self, fg_color="transparent")
        cards_frame.pack(fill="x", padx=12, pady=(0, 8))
        cards_frame.grid_columnconfigure((0, 1, 2, 3), weight=1)

        # 1. Type
        ext_label = result.get("identity", {}).get("extension") or t.t("misc.unknown")
        c1 = ctk.CTkFrame(cards_frame, fg_color="#161b22", corner_radius=8, border_width=1, border_color="#30363d")
        c1.grid(row=0, column=0, sticky="ew", padx=(0, 4))
        ctk.CTkLabel(c1, text="📁 " + t.t("field.type_declared"), font=ctk.CTkFont(size=11), text_color="#8b949e").pack(anchor="w", padx=10, pady=(6, 0))
        ctk.CTkLabel(c1, text=ext_label, font=ctk.CTkFont(size=14, weight="bold"), text_color="#f0f6fc").pack(anchor="w", padx=10, pady=(0, 6))

        # 2. Threat Family
        c2 = ctk.CTkFrame(cards_frame, fg_color="#161b22", corner_radius=8, border_width=1, border_color="#30363d")
        c2.grid(row=0, column=1, sticky="ew", padx=4)
        ctk.CTkLabel(c2, text="🏷️ " + t.t("threat.title"), font=ctk.CTkFont(size=11), text_color="#8b949e").pack(anchor="w", padx=10, pady=(6, 0))
        ctk.CTkLabel(c2, text=f"{threat_icon} {threat_name}", font=ctk.CTkFont(size=12, weight="bold"), text_color="#f85149" if threat_key != "clean" else "#3fb950").pack(anchor="w", padx=10, pady=(0, 6))

        # 3. Global Entropy
        ent_val = result.get("entropy", {}).get("global")
        ent_str = f"{ent_val:.2f} / 8.0" if ent_val is not None else t.t("misc.unknown")
        ent_color = "#f85149" if ent_val and ent_val > 7.2 else ("#e3b341" if ent_val and ent_val > 6.5 else "#3fb950")
        c3 = ctk.CTkFrame(cards_frame, fg_color="#161b22", corner_radius=8, border_width=1, border_color="#30363d")
        c3.grid(row=0, column=2, sticky="ew", padx=4)
        ctk.CTkLabel(c3, text="📊 " + t.t("field.entropy"), font=ctk.CTkFont(size=11), text_color="#8b949e").pack(anchor="w", padx=10, pady=(6, 0))
        ctk.CTkLabel(c3, text=ent_str, font=ctk.CTkFont(size=14, weight="bold"), text_color=ent_color).pack(anchor="w", padx=10, pady=(0, 6))

        # 4. Total Anomalies count
        all_findings = []
        all_findings.extend(result.get("identity", {}).get("findings", []))
        if result.get("entropy", {}).get("finding"):
            all_findings.append(result["entropy"]["finding"])
        all_findings.extend(result.get("pe", {}).get("findings", []))
        all_findings.extend(result.get("yara", {}).get("findings", []))

        c4 = ctk.CTkFrame(cards_frame, fg_color="#161b22", corner_radius=8, border_width=1, border_color="#30363d")
        c4.grid(row=0, column=3, sticky="ew", padx=(4, 0))
        ctk.CTkLabel(c4, text="⚠️ " + t.t("tabs.findings"), font=ctk.CTkFont(size=11), text_color="#8b949e").pack(anchor="w", padx=10, pady=(6, 0))
        warn_cnt = len([f for f in all_findings if f.get("severity") in ("critical", "high", "medium")])
        c4_color = "#f85149" if warn_cnt > 2 else ("#e3b341" if warn_cnt > 0 else "#3fb950")
        ctk.CTkLabel(c4, text=f"{len(all_findings)} élément(s)", font=ctk.CTkFont(size=14, weight="bold"), text_color=c4_color).pack(anchor="w", padx=10, pady=(0, 6))

        # --- Main Tabview with Tabs ---
        self.tabs = ctk.CTkTabview(
            self,
            fg_color="#161b22",
            segmented_button_fg_color="#0d1117",
            segmented_button_selected_color="#1f6feb",
            segmented_button_unselected_color="#21262d",
            segmented_button_selected_hover_color="#1158c7",
        )
        self.tabs.pack(fill="both", expand=True, padx=12, pady=(0, 10))

        tab_keys = ["summary", "safety", "ai_report", "identity", "pe", "entropy", "strings", "yara", "vt", "privacy"]
        for key in tab_keys:
            self.tabs.add(t.t(f"tabs.{key}"))

        self._fill_summary(self.tabs.tab(t.t("tabs.summary")), t, result, all_findings, advice, threat_key)
        self._fill_safety(self.tabs.tab(t.t("tabs.safety")), t, result, advice, threat_key)
        self._fill_ai_report(self.tabs.tab(t.t("tabs.ai_report")), t, result)
        self._fill_identity(self.tabs.tab(t.t("tabs.identity")), t, result)
        self._fill_pe(self.tabs.tab(t.t("tabs.pe")), t, result)
        self._fill_entropy(self.tabs.tab(t.t("tabs.entropy")), t, result)
        self._fill_strings(self.tabs.tab(t.t("tabs.strings")), t, result)
        self._fill_yara(self.tabs.tab(t.t("tabs.yara")), t, result)
        self._fill_vt(self.tabs.tab(t.t("tabs.vt")), t, result)
        self._fill_privacy(self.tabs.tab(t.t("tabs.privacy")), t)

    def _build_remediation_bar(self, file_path, verdict):
        t = self.t
        is_malicious = verdict == "malicious"
        self.rem_frame = ctk.CTkFrame(
            self,
            fg_color="#161b22",
            corner_radius=8,
            border_width=1,
            border_color="#da3633" if is_malicious else "#d29922",
        )
        self.rem_frame.pack(fill="x", padx=12, pady=(0, 8))

        inner = ctk.CTkFrame(self.rem_frame, fg_color="transparent")
        inner.pack(fill="x", padx=14, pady=8)

        # Left title & subtitle
        left_box = ctk.CTkFrame(inner, fg_color="transparent")
        left_box.pack(side="left", fill="x", expand=True)

        ctk.CTkLabel(
            left_box,
            text=t.t("remediation.section_title"),
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color="#f85149" if is_malicious else "#e3b341",
        ).pack(anchor="w")

        ctk.CTkLabel(
            left_box,
            text="Fichier suspect/dangereux détecté. Isolez-le ou détruisez-le pour protéger votre système :",
            font=ctk.CTkFont(size=11),
            text_color="#8b949e",
        ).pack(anchor="w", pady=(1, 0))

        # Right buttons
        self.rem_btn_box = ctk.CTkFrame(inner, fg_color="transparent")
        self.rem_btn_box.pack(side="right")

        self.btn_sandbox = ctk.CTkButton(
            self.rem_btn_box,
            text="⚡ Windows Sandbox",
            font=ctk.CTkFont(size=12, weight="bold"),
            fg_color="#1f6feb",
            hover_color="#388bfd",
            height=34,
            command=lambda: self._handle_sandbox(file_path),
        )
        self.btn_sandbox.pack(side="left", padx=4)

        self.btn_quarantine = ctk.CTkButton(
            self.rem_btn_box,
            text=t.t("remediation.quarantine_btn"),
            font=ctk.CTkFont(size=12, weight="bold"),
            fg_color="#bb8009",
            hover_color="#9e6a03",
            height=34,
            command=lambda: self._handle_quarantine(file_path),
        )
        self.btn_quarantine.pack(side="left", padx=4)

        self.btn_delete = ctk.CTkButton(
            self.rem_btn_box,
            text=t.t("remediation.delete_btn"),
            font=ctk.CTkFont(size=12, weight="bold"),
            fg_color="#da3633",
            hover_color="#b62324",
            height=34,
            command=lambda: self._handle_delete(file_path),
        )
        self.btn_delete.pack(side="left", padx=4)

    def _handle_sandbox(self, file_path):
        available, _ = is_windows_sandbox_available()
        if not available:
            SandboxGuideDialog(master=self.winfo_toplevel(), theme=self.theme)
            return

        success, msg = launch_in_windows_sandbox(file_path)
        if success:
            messagebox.showinfo("Windows Sandbox", msg)
        else:
            messagebox.showwarning("Windows Sandbox", msg)

    def _handle_quarantine(self, file_path):
        t = self.t
        confirm = messagebox.askyesno(
            t.t("remediation.quarantine_confirm_title"),
            t.t("remediation.quarantine_confirm_msg"),
            icon="warning",
        )
        if not confirm:
            return

        success, msg, qpath = quarantine_file(file_path, metadata=self.result)
        if success:
            for child in self.rem_btn_box.winfo_children():
                child.destroy()
            badge = ctk.CTkFrame(self.rem_btn_box, fg_color="#0e2a1b", corner_radius=6, border_width=1, border_color="#238636")
            badge.pack(side="right")
            ctk.CTkLabel(
                badge,
                text=t.t("remediation.quarantined_success"),
                font=ctk.CTkFont(size=12, weight="bold"),
                text_color="#3fb950",
                padx=12,
                pady=5,
            ).pack()
            messagebox.showinfo("Quarantaine", t.t("remediation.quarantined_success"))
        else:
            messagebox.showerror("Erreur", t.t("remediation.action_failed", error=msg))

    def _handle_delete(self, file_path):
        t = self.t
        confirm = messagebox.askyesno(
            t.t("remediation.delete_confirm_title"),
            t.t("remediation.delete_confirm_msg"),
            icon="warning",
        )
        if not confirm:
            return

        success, msg = delete_file_permanently(file_path)
        if success:
            for child in self.rem_btn_box.winfo_children():
                child.destroy()
            badge = ctk.CTkFrame(self.rem_btn_box, fg_color="#0e2a1b", corner_radius=6, border_width=1, border_color="#238636")
            badge.pack(side="right")
            ctk.CTkLabel(
                badge,
                text=t.t("remediation.deleted_success"),
                font=ctk.CTkFont(size=12, weight="bold"),
                text_color="#3fb950",
                padx=12,
                pady=5,
            ).pack()
            messagebox.showinfo("Suppression", t.t("remediation.deleted_success"))
        else:
            messagebox.showerror("Erreur", t.t("remediation.action_failed", error=msg))

    def _scrollable(self, tab):
        return ctk.CTkScrollableFrame(tab, fg_color="#161b22")

    def _copy_to_clipboard(self, val, btn, t):
        try:
            self.clipboard_clear()
            self.clipboard_append(val)
            self.update()
            orig_text = btn.cget("text")
            btn.configure(text=t.t("misc.copied"), fg_color="#238636")
            self.after(1400, lambda: btn.configure(text=orig_text, fg_color="#21262d"))
        except Exception:
            pass

    # --- AI Report Tab ---
    def _fill_ai_report(self, tab, t, result):
        for child in tab.winfo_children():
            child.destroy()

        frame = self._scrollable(tab)
        frame.pack(fill="both", expand=True, padx=4, pady=4)

        from app_config import load_config
        live_cfg = load_config()
        self.config = live_cfg
        ai_cfg = live_cfg.get("ai_analyst", {})
        ai_enabled = bool(ai_cfg.get("enabled"))
        ai_key = ai_cfg.get("api_key", "").strip()
        provider = ai_cfg.get("provider", "openrouter")
        model = ai_cfg.get("model", "")

        section_header(frame, "🤖 Analyste Cybersécurité IA", f"{provider.upper()} ({model or 'Défaut'})")

        if result.get("ai_report") and result["ai_report"].strip():
            # Display Report
            rep_card = ctk.CTkFrame(frame, fg_color="#0d1117", corner_radius=10, border_width=1, border_color="#1f6feb")
            rep_card.pack(fill="both", expand=True, padx=4, pady=(0, 10))

            top_row = ctk.CTkFrame(rep_card, fg_color="transparent")
            top_row.pack(fill="x", padx=16, pady=12)

            ctk.CTkLabel(top_row, text="✨ Rapport d'Expertise IA", font=ctk.CTkFont(size=16, weight="bold"), text_color="#58a6ff").pack(side="left")

            btn_box = ctk.CTkFrame(top_row, fg_color="transparent")
            btn_box.pack(side="right")

            regen_btn = ctk.CTkButton(
                btn_box,
                text="🔄 Régénérer",
                width=130,
                height=34,
                font=ctk.CTkFont(size=12, weight="bold"),
                fg_color="#21262d",
                hover_color="#30363d",
                command=lambda: self._generate_ai(tab, t, result, ai_cfg),
            )
            regen_btn.pack(side="left", padx=4)

            c_btn = ctk.CTkButton(
                btn_box,
                text="📋 " + t.t("ai.copy_report"),
                width=160,
                height=34,
                font=ctk.CTkFont(size=12, weight="bold"),
                fg_color="#1f6feb",
                hover_color="#1158c7",
            )
            c_btn.configure(command=lambda v=result["ai_report"], b=c_btn: self._copy_to_clipboard(v, b, t))
            c_btn.pack(side="left", padx=4)

            text_box = ctk.CTkTextbox(
                rep_card,
                fg_color="#0d1117",
                text_color="#f0f6fc",
                font=ctk.CTkFont(size=14),
                wrap="word",
                height=520,
            )
            text_box.insert("1.0", result["ai_report"])
            text_box.configure(state="disabled")
            text_box.pack(fill="both", expand=True, padx=16, pady=(0, 16))

        else:
            # Show generate button if AI is enabled + key present; otherwise show setup instructions
            if not ai_enabled or not ai_key:
                # Config needed
                info_box = ctk.CTkFrame(frame, fg_color="#0d1117", corner_radius=10, border_width=1, border_color="#30363d")
                info_box.pack(fill="x", padx=4, pady=(0, 10))
                i_inner = ctk.CTkFrame(info_box, fg_color="transparent")
                i_inner.pack(fill="x", padx=20, pady=20)
                ctk.CTkLabel(
                    i_inner,
                    text="⚙️ Configuration requise pour l'Analyste IA",
                    font=ctk.CTkFont(size=16, weight="bold"),
                    text_color="#e3b341",
                ).pack(anchor="w")
                ctk.CTkLabel(
                    i_inner,
                    text=(
                        "L'Analyste IA n'est pas encore activé ou votre clé API est absente.\n\n"
                        "Pour l'activer en 30 secondes :\n"
                        "  1. Cliquez sur le bouton ⚙ Réglages en haut à droite\n"
                        "  2. Ouvrez l'onglet 🤖 Analyste IA et activez l'interrupteur\n"
                        "  3. Entrez votre clé API OpenRouter (modèles gratuits inclus)\n"
                        "  4. Enregistrez : le bouton d'analyse apparaîtra immédiatement ici !"
                    ),
                    font=ctk.CTkFont(size=13),
                    text_color="#8b949e",
                    wraplength=1000,
                    justify="left",
                ).pack(anchor="w", pady=(10, 0))
            else:
                # AI is configured — show the generate button
                gen_card = ctk.CTkFrame(frame, fg_color="#0d1117", corner_radius=10, border_width=1, border_color="#1f6feb")
                gen_card.pack(fill="x", padx=4, pady=(0, 10))
                g_inner = ctk.CTkFrame(gen_card, fg_color="transparent")
                g_inner.pack(fill="x", padx=20, pady=24)
                ctk.CTkLabel(
                    g_inner,
                    text="✨ Analyste Cybersécurité IA — Prêt",
                    font=ctk.CTkFont(size=16, weight="bold"),
                    text_color="#58a6ff",
                ).pack(anchor="w")
                ctk.CTkLabel(
                    g_inner,
                    text=(
                        f"Fournisseur : {provider.upper()}   |   Modèle : {model or 'Défaut'}\n\n"
                        "Cliquez sur le bouton ci-dessous pour générer une expertise cybersécurité approfondie "
                        "et synthétique par l'intelligence artificielle.\n"
                        "L'IA analysera la structure, les comportements réels (réseau, mémoire, persistance, chiffrement) "
                        "et vous fournira un verdict clair avec des recommandations concrètes d'action."
                    ),
                    font=ctk.CTkFont(size=13),
                    text_color="#8b949e",
                    wraplength=1000,
                    justify="left",
                ).pack(anchor="w", pady=(10, 20))
                ctk.CTkButton(
                    g_inner,
                    text="🤖 Générer l'Analyse IA Approfondie",
                    width=320,
                    height=46,
                    font=ctk.CTkFont(size=15, weight="bold"),
                    fg_color="#1f6feb",
                    hover_color="#1158c7",
                    command=lambda: self._generate_ai(tab, t, result, ai_cfg),
                ).pack(anchor="w")


    def _generate_ai(self, tab, t, result, ai_cfg=None):
        if self.ai_loading:
            return
        self.ai_loading = True

        from app_config import load_config
        live_cfg = load_config()
        self.config = live_cfg
        live_ai_cfg = live_cfg.get("ai_analyst", {})

        for child in tab.winfo_children():
            child.destroy()

        frame = self._scrollable(tab)
        frame.pack(fill="both", expand=True, padx=4, pady=4)

        section_header(frame, "🤖 Analyste Cybersécurité IA", "Génération en cours...")

        load_card = ctk.CTkFrame(frame, fg_color="#0d1117", corner_radius=8, border_width=1, border_color="#1f6feb")
        load_card.pack(fill="x", padx=4, pady=(10, 10))

        l_inner = ctk.CTkFrame(load_card, fg_color="transparent")
        l_inner.pack(fill="x", padx=16, pady=20)

        ctk.CTkLabel(l_inner, text="⏳ " + t.t("ai.loading"), font=ctk.CTkFont(size=14, weight="bold"), text_color="#58a6ff").pack(anchor="w")

        pbar = ctk.CTkProgressBar(l_inner, mode="indeterminate", progress_color="#1f6feb")
        pbar.pack(fill="x", pady=(10, 4))
        pbar.start()

        def _worker():
            try:
                lang = self.config.get("language", "fr")
                report = query_ai_analyst(result, live_ai_cfg, lang=lang)
                if not report or not report.strip():
                    raise RuntimeError("Le modèle n'a retourné aucun contenu texte. Essayez un autre modèle dans les Réglages ⚙.")
                result["ai_report"] = report
                self.after(0, lambda: self._on_ai_done(tab, t, result))
            except Exception as exc:
                err_msg = str(exc)
                self.after(0, lambda: self._on_ai_error(tab, t, result, err_msg, live_ai_cfg))
            finally:
                self.ai_loading = False

        threading.Thread(target=_worker, daemon=True).start()

    def _on_ai_done(self, tab, t, result):
        self._fill_ai_report(tab, t, result)

    def update_config(self, new_cfg):
        self.config = new_cfg
        ai_tab_label = self.t.t("tabs.ai_report")
        try:
            tab_widget = self.tabs.tab(ai_tab_label)
            self._fill_ai_report(tab_widget, self.t, self.result)
        except Exception:
            pass

    def _on_ai_error(self, tab, t, result, err_msg, ai_cfg):
        for child in tab.winfo_children():
            child.destroy()
        frame = self._scrollable(tab)
        frame.pack(fill="both", expand=True, padx=4, pady=4)
        section_header(frame, "🤖 Analyste Cybersécurité IA", "Erreur")
        e_card = ctk.CTkFrame(frame, fg_color="#3c1116", corner_radius=8, border_width=1, border_color="#da3633")
        e_card.pack(fill="x", padx=4, pady=10)
        ctk.CTkLabel(e_card, text="❌ " + t.t("ai.error_title"), font=ctk.CTkFont(size=14, weight="bold"), text_color="#ff4d4f").pack(padx=16, pady=(12, 4), anchor="w")
        ctk.CTkLabel(e_card, text=err_msg, font=ctk.CTkFont(size=12), text_color="#f85149", wraplength=700, justify="left").pack(padx=16, pady=(0, 12), anchor="w")
        ctk.CTkButton(
            frame,
            text="🔄 Réessayer",
            font=ctk.CTkFont(size=12, weight="bold"),
            fg_color="#1f6feb",
            hover_color="#1158c7",
            command=lambda: self._generate_ai(tab, t, result, ai_cfg),
        ).pack(anchor="w", padx=6, pady=6)

    # --- 1. Summary Tab ---
    def _fill_summary(self, tab, t, result, all_findings, advice, threat_key):
        frame = self._scrollable(tab)
        frame.pack(fill="both", expand=True, padx=4, pady=4)

        # Threat classification card
        threat_name = t.t(f"threat.type.{threat_key}")
        threat_desc = t.t(f"threat.desc.{threat_key}")
        threat_icon = THREAT_ICONS.get(threat_key, "🛡️")

        section_header(frame, "Typologie de la menace & Recommandation")
        t_card = ctk.CTkFrame(frame, fg_color="#0d1117", corner_radius=6, border_width=1, border_color="#30363d")
        t_card.pack(fill="x", padx=4, pady=(0, 10))

        t_row = ctk.CTkFrame(t_card, fg_color="transparent")
        t_row.pack(fill="x", padx=12, pady=(10, 4))
        ctk.CTkLabel(t_row, text=f"{threat_icon} {threat_name}", font=ctk.CTkFont(size=15, weight="bold"), text_color="#f85149" if threat_key != "clean" else "#3fb950").pack(side="left")

        ctk.CTkLabel(t_card, text=threat_desc, font=ctk.CTkFont(size=12), text_color="#e6edf3", wraplength=720, justify="left").pack(padx=12, pady=(0, 8), anchor="w")

        # Potential risks list
        risks = advice.get("risks", [])
        if risks and threat_key != "clean":
            ctk.CTkLabel(t_card, text="⚠️ " + t.t("execution.risks_title"), font=ctk.CTkFont(size=12, weight="bold"), text_color="#fa8c16").pack(padx=12, pady=(4, 2), anchor="w")
            for r_key in risks:
                ctk.CTkLabel(t_card, text=f"  • {t.t(r_key)}", font=ctk.CTkFont(size=12), text_color="#f0883e", wraplength=700, justify="left").pack(padx=16, pady=1, anchor="w")

        # Actions list
        actions = advice.get("actions", [])
        if actions:
            ctk.CTkLabel(t_card, text="🛡️ " + t.t("execution.actions_title"), font=ctk.CTkFont(size=12, weight="bold"), text_color="#58a6ff").pack(padx=12, pady=(8, 2), anchor="w")
            for a_key in actions:
                ctk.CTkLabel(t_card, text=f"  ✓ {t.t(a_key)}", font=ctk.CTkFont(size=12), text_color="#e6edf3", wraplength=700, justify="left").pack(padx=16, pady=1, anchor="w")

        ctk.CTkFrame(t_card, height=6, fg_color="transparent").pack()

        # Findings list
        section_header(frame, t.t("tabs.findings"), f"{len(all_findings)} élément(s)")
        if not all_findings:
            ctk.CTkLabel(frame, text=t.t("misc.none"), font=ctk.CTkFont(size=12), text_color="#8b949e").pack(anchor="w", padx=8, pady=4)
        else:
            for f in all_findings:
                finding_card(frame, t, f)

        # Risk score breakdown
        breakdown = result.get("risk", {}).get("breakdown", [])
        if breakdown:
            section_header(frame, "Décomposition du score de risque")
            b_card = ctk.CTkFrame(frame, fg_color="#0d1117", corner_radius=6, border_width=1, border_color="#30363d")
            b_card.pack(fill="x", padx=4, pady=(0, 8))
            for item in breakdown:
                row = ctk.CTkFrame(b_card, fg_color="transparent")
                row.pack(fill="x", padx=12, pady=4)
                comp_name = t.t(item["key"]) if "key" in item else item.get("component", "?")
                ctk.CTkLabel(row, text=f"• {comp_name}", font=ctk.CTkFont(size=12), text_color="#e6edf3").pack(side="left")
                pts = item.get("points", 0)
                pts_color = "#f85149" if pts > 20 else ("#e3b341" if pts > 0 else "#3fb950")
                ctk.CTkLabel(row, text=f"+{pts} pts", font=ctk.CTkFont(size=12, weight="bold"), text_color=pts_color).pack(side="right")

    # --- 2. Safety & Execution Tab ---
    def _fill_safety(self, tab, t, result, advice, threat_key):
        frame = self._scrollable(tab)
        frame.pack(fill="both", expand=True, padx=4, pady=4)

        verdict = result["risk"]["verdict"]
        score = result["risk"]["score"]
        atheme = ADVICE_THEMES.get(advice.get("advice_status", "safe" if verdict == "clean" else "danger"), ADVICE_THEMES["safe"])

        section_header(frame, "🛡️ " + t.t("tabs.safety"), f"Score de risque : {score}/100")

        # Large Executive Guidance Card
        g_card = ctk.CTkFrame(frame, fg_color=atheme["bg"], corner_radius=8, border_width=1, border_color=atheme["border"])
        g_card.pack(fill="x", padx=4, pady=(0, 12))

        g_inner = ctk.CTkFrame(g_card, fg_color="transparent")
        g_inner.pack(fill="x", padx=16, pady=12)

        ctk.CTkLabel(
            g_inner,
            text=f"{atheme['icon']} {t.t(advice.get('title_key', 'execution.safe_title'))}",
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color=atheme["title_color"],
        ).pack(anchor="w")

        ctk.CTkLabel(
            g_inner,
            text=t.t(advice.get('message_key', 'execution.safe_message')),
            font=ctk.CTkFont(size=13),
            text_color="#e6edf3",
            wraplength=720,
            justify="left",
        ).pack(anchor="w", pady=(6, 4))

        # Risk breakdown details
        risks = advice.get("risks", [])
        if risks and threat_key != "clean":
            section_header(frame, "⚠️ Risques potentiels pour votre ordinateur et vos données")
            r_card = ctk.CTkFrame(frame, fg_color="#0d1117", corner_radius=6, border_width=1, border_color="#30363d")
            r_card.pack(fill="x", padx=4, pady=(0, 10))
            for r_key in risks:
                r_row = ctk.CTkFrame(r_card, fg_color="transparent")
                r_row.pack(fill="x", padx=12, pady=6)
                ctk.CTkLabel(r_row, text="❌", font=ctk.CTkFont(size=12)).pack(side="left", padx=(0, 8))
                ctk.CTkLabel(r_row, text=t.t(r_key), font=ctk.CTkFont(size=12, weight="bold"), text_color="#fa8c16", wraplength=680, justify="left").pack(side="left")

        # Action Recommendations
        actions = advice.get("actions", [])
        if actions:
            section_header(frame, "🛡️ Mesures de protection et actions recommandées")
            a_card = ctk.CTkFrame(frame, fg_color="#0d1117", corner_radius=6, border_width=1, border_color="#30363d")
            a_card.pack(fill="x", padx=4, pady=(0, 10))
            for a_key in actions:
                a_row = ctk.CTkFrame(a_card, fg_color="transparent")
                a_row.pack(fill="x", padx=12, pady=6)
                ctk.CTkLabel(a_row, text="✓", font=ctk.CTkFont(size=13, weight="bold"), text_color="#3fb950").pack(side="left", padx=(0, 8))
                ctk.CTkLabel(a_row, text=t.t(a_key), font=ctk.CTkFont(size=12), text_color="#e6edf3", wraplength=680, justify="left").pack(side="left")

        # Remediation Action Box in Safety Tab
        file_path = result.get("file", {}).get("path")
        if (verdict in ("suspicious", "malicious") or score >= 40) and file_path:
            section_header(frame, t.t("remediation.section_title"))
            rem_c = ctk.CTkFrame(frame, fg_color="#0d1117", corner_radius=6, border_width=1, border_color="#da3633" if verdict == "malicious" else "#d29922")
            rem_c.pack(fill="x", padx=4, pady=(0, 10))

            r_inner = ctk.CTkFrame(rem_c, fg_color="transparent")
            r_inner.pack(fill="x", padx=12, pady=10)

            ctk.CTkButton(
                r_inner,
                text="⚡ Tester dans Windows Sandbox",
                font=ctk.CTkFont(size=12, weight="bold"),
                fg_color="#1f6feb",
                hover_color="#388bfd",
                height=36,
                command=lambda: self._handle_sandbox(file_path),
            ).pack(side="left", padx=(0, 6))

            ctk.CTkButton(
                r_inner,
                text=t.t("remediation.quarantine_btn"),
                font=ctk.CTkFont(size=12, weight="bold"),
                fg_color="#bb8009",
                hover_color="#9e6a03",
                height=36,
                command=lambda: self._handle_quarantine(file_path),
            ).pack(side="left", padx=(0, 6))

            ctk.CTkButton(
                r_inner,
                text=t.t("remediation.delete_btn"),
                font=ctk.CTkFont(size=12, weight="bold"),
                fg_color="#da3633",
                hover_color="#b62324",
                height=36,
                command=lambda: self._handle_delete(file_path),
            ).pack(side="left")

    # --- 3. Identity & Hashes Tab ---
    def _fill_identity(self, tab, t, result):
        frame = self._scrollable(tab)
        frame.pack(fill="both", expand=True, padx=4, pady=4)

        f_info = result.get("file", {})
        identity = result.get("identity", {})
        hashes = result.get("hashes", {})

        section_header(frame, "Identité du fichier & Système de fichiers")
        id_card = ctk.CTkFrame(frame, fg_color="#0d1117", corner_radius=6, border_width=1, border_color="#30363d")
        id_card.pack(fill="x", padx=4, pady=(0, 10))

        self._kv_row(id_card, t.t("field.name"), f_info.get("name", "?"), t)
        self._kv_row(id_card, t.t("field.path"), f_info.get("path", "?"), t, copyable=True)
        self._kv_row(id_card, t.t("field.size"), f"{f_info.get('size_human', '?')} ({f_info.get('size', 0):,} octets)".replace(",", " "), t)
        self._kv_row(id_card, t.t("field.type_declared"), identity.get("extension") or "?", t)
        real_type = identity.get("human_type") or identity.get("mime") or t.t("misc.unknown")
        self._kv_row(id_card, t.t("field.type_real"), str(real_type), t)
        self._kv_row(id_card, t.t("field.created"), f_info.get("created", "?"), t)
        self._kv_row(id_card, t.t("field.modified"), f_info.get("modified", "?"), t)
        self._kv_row(id_card, t.t("field.accessed"), f_info.get("accessed", "?"), t)
        attrs = ", ".join(f_info.get("attributes", ["Normal"]))
        self._kv_row(id_card, t.t("field.attributes"), attrs, t)

        section_header(frame, "Empreintes Cryptographiques (Hachages)")
        h_card = ctk.CTkFrame(frame, fg_color="#0d1117", corner_radius=6, border_width=1, border_color="#30363d")
        h_card.pack(fill="x", padx=4, pady=(0, 10))

        self._kv_row(h_card, "SHA-256", hashes.get("sha256", "?"), t, copyable=True, mono=True)
        self._kv_row(h_card, "SHA-512", hashes.get("sha512", "?"), t, copyable=True, mono=True)
        self._kv_row(h_card, "SHA-1", hashes.get("sha1", "?"), t, copyable=True, mono=True)
        self._kv_row(h_card, "MD5", hashes.get("md5", "?"), t, copyable=True, mono=True)
        self._kv_row(h_card, "CRC32", hashes.get("crc32", "?"), t, copyable=True, mono=True)
        if hashes.get("imphash"):
            self._kv_row(h_card, "Imphash", hashes["imphash"], t, copyable=True, mono=True)

        info_explanation_card(
            frame,
            t.t("explainer.identity_title"),
            t.t("explainer.identity_text"),
        )

    # --- 4. PE Structure Tab ---
    def _fill_pe(self, tab, t, result):
        frame = self._scrollable(tab)
        frame.pack(fill="both", expand=True, padx=4, pady=4)

        pe = result.get("pe", {})
        if not pe.get("applicable") or not pe.get("parsed"):
            ctk.CTkLabel(frame, text=t.t("pe.not_pe"), font=ctk.CTkFont(size=13), text_color="#8b949e").pack(padx=12, pady=16, anchor="w")
            info_explanation_card(
                frame,
                t.t("explainer.pe_title"),
                t.t("explainer.pe_text"),
            )
            return

        info = pe.get("info", {})

        # Header Info
        section_header(frame, "En-tête & Propriétés Générales")
        h_card = ctk.CTkFrame(frame, fg_color="#0d1117", corner_radius=6, border_width=1, border_color="#30363d")
        h_card.pack(fill="x", padx=4, pady=(0, 10))
        # Bug #1 fixed: "machine" (not "architecture")
        self._kv_row(h_card, t.t("field.architecture"), info.get("machine", "?"), t)
        self._kv_row(h_card, t.t("field.subsystem"), info.get("subsystem", "?"), t)
        ep_val = hex(info["entry_point"]) if isinstance(info.get("entry_point"), int) else str(info.get("entry_point") or "?")
        ib_val = hex(info["image_base"]) if isinstance(info.get("image_base"), int) else str(info.get("image_base") or "?")
        self._kv_row(h_card, t.t("field.entry_point"), ep_val, t, mono=True)
        self._kv_row(h_card, t.t("field.image_base"), ib_val, t, mono=True)
        # Bug #2 fixed: "pdb_path" (not "debug_path")
        if info.get("pdb_path"):
            self._kv_row(h_card, t.t("field.pdb_path"), info["pdb_path"], t, copyable=True, mono=True)

        # Digital Signature — Bug #4 fixed: use info["is_signed"] directly (not security_flags.has_digital_signature)
        is_signed = bool(info.get("is_signed"))
        is_dotnet = bool(info.get("is_dotnet"))
        sig_color = "#3fb950" if is_signed else "#8b949e"
        sig_text = "Oui (Présente)" if is_signed else "Non signée"
        self._kv_row(h_card, t.t("field.signature"), sig_text, t, custom_color=sig_color)
        if is_dotnet:
            self._kv_row(h_card, ".NET / Managed", "Oui", t, custom_color="#58a6ff")
        compiled = info.get("compiled")
        if compiled:
            self._kv_row(h_card, "Compilé le", compiled, t)
        overlay_mb = info.get("overlay_mb")
        if overlay_mb is not None:
            self._kv_row(h_card, "Overlay (données après fin PE)", f"{overlay_mb} Mo", t,
                         custom_color="#e3b341" if overlay_mb > 1 else "#e6edf3")
        self._kv_row(h_card, "Imports", f"{info.get('imports_count', 0)} fonctions importées", t)
        self._kv_row(h_card, "Exports", f"{info.get('exports_count', 0)} fonctions exportées", t)

        # MITRE APIs
        mitre = info.get("mitre_apis", {})
        if any(mitre.values()):
            section_header(frame, "Catégorisation des APIs Windows (MITRE ATT&CK)")
            m_card = ctk.CTkFrame(frame, fg_color="#0d1117", corner_radius=6, border_width=1, border_color="#30363d")
            m_card.pack(fill="x", padx=4, pady=(0, 10))
            labels = {
                "injection": ("Injection de code / Mémoire", "#f85149"),
                "persistence": ("Persistance (Registre / Services)", "#fa8c16"),
                "network": ("Connexions réseau / Téléchargement", "#58a6ff"),
                "execution": ("Exécution de processus", "#e5b810"),
                "hooking": ("Interception de frappes / Messages (Hooking)", "#f85149"),
                "antidebug": ("Anti-Débogage / Évasion", "#e5b810"),
                "crypto": ("Chiffrement / Hachage", "#8b949e"),
                "privilege": ("Élévation de privilèges", "#fa8c16"),
            }
            for cat, apis in mitre.items():
                if apis:
                    clabel, ccolor = labels.get(cat, (cat.title(), "#e6edf3"))
                    crow = ctk.CTkFrame(m_card, fg_color="transparent")
                    crow.pack(fill="x", padx=12, pady=4)
                    ctk.CTkLabel(crow, text=f"• {clabel} :", font=ctk.CTkFont(size=12, weight="bold"), text_color=ccolor).pack(anchor="w")
                    ctk.CTkLabel(crow, text="   " + ", ".join(apis[:8]) + (f" (+{len(apis)-8} autres)" if len(apis) > 8 else ""), font=ctk.CTkFont(family="Consolas", size=11), text_color="#8b949e").pack(anchor="w")

        # Sections table
        sections = info.get("sections", [])
        if sections:
            section_header(frame, t.t("pe.sections"), f"{len(sections)} sections")
            s_card = ctk.CTkFrame(frame, fg_color="#0d1117", corner_radius=6, border_width=1, border_color="#30363d")
            s_card.pack(fill="x", padx=4, pady=(0, 10))
            for s in sections:
                srow = ctk.CTkFrame(s_card, fg_color="transparent")
                srow.pack(fill="x", padx=12, pady=3)
                sname = s.get("name", "?")
                sent = s.get("entropy", 0.0)
                sz = s.get("virtual_size", 0)
                flags_str = s.get("flags", "")
                # Bug #3 fixed: use "flags" string (not is_writable/is_executable keys that don't exist)
                is_wx = "W" in flags_str and "X" in flags_str
                badge_txt = " [W+X ⚠️]" if is_wx else ""
                flags_display = f" [{flags_str}]" if flags_str and not is_wx else ""
                col = "#f85149" if is_wx or sent > 7.2 else ("#e3b341" if sent > 6.5 else "#e6edf3")
                ctk.CTkLabel(srow, text=f"{sname:8s} | Entropie: {sent:.2f} | {sz:,} o{flags_display}{badge_txt}", font=ctk.CTkFont(family="Consolas", size=12), text_color=col).pack(side="left")

        info_explanation_card(
            frame,
            t.t("explainer.pe_title"),
            t.t("explainer.pe_text"),
        )

    # --- 5. Entropy & Blocks Tab ---
    def _fill_entropy(self, tab, t, result):
        frame = self._scrollable(tab)
        frame.pack(fill="both", expand=True, padx=4, pady=4)

        entropy_data = result.get("entropy", {})
        g_ent = entropy_data.get("global", 0.0)
        blocks_data = entropy_data.get("blocks", {})

        section_header(frame, "Entropie Globale de Shannon")
        e_card = ctk.CTkFrame(frame, fg_color="#0d1117", corner_radius=6, border_width=1, border_color="#30363d")
        e_card.pack(fill="x", padx=4, pady=(0, 10))

        e_row = ctk.CTkFrame(e_card, fg_color="transparent")
        e_row.pack(fill="x", padx=12, pady=10)
        ctk.CTkLabel(e_row, text=f"Entropie : {g_ent:.3f} / 8.000", font=ctk.CTkFont(size=16, weight="bold"), text_color="#f0f6fc").pack(side="left")

        bar = ctk.CTkProgressBar(e_card, height=10)
        bar.set((g_ent or 0.0) / 8.0)
        bar.configure(progress_color="#f85149" if g_ent > 7.2 else ("#e3b341" if g_ent > 6.5 else "#3fb950"), fg_color="#21262d")
        bar.pack(fill="x", padx=12, pady=(0, 12))

        # Block entropy breakdown
        if blocks_data and blocks_data.get("samples"):
            section_header(frame, "Analyse d'Entropie par Blocs (16 Ko)", f"{blocks_data.get('total_blocks', 0)} blocs")
            b_card = ctk.CTkFrame(frame, fg_color="#0d1117", corner_radius=6, border_width=1, border_color="#30363d")
            b_card.pack(fill="x", padx=4, pady=(0, 10))

            b_stats = ctk.CTkFrame(b_card, fg_color="transparent")
            b_stats.pack(fill="x", padx=12, pady=8)
            ctk.CTkLabel(b_stats, text=f"Min: {blocks_data.get('min', 0)} | Max: {blocks_data.get('max', 0)} | Moyenne: {blocks_data.get('avg', 0)} | Blocs très élevés (>7.2): {blocks_data.get('high_count', 0)}", font=ctk.CTkFont(size=12), text_color="#8b949e").pack(side="left")

            # Samples preview bar
            samples = blocks_data.get("samples", [])
            s_frame = ctk.CTkFrame(b_card, fg_color="transparent")
            s_frame.pack(fill="x", padx=12, pady=(0, 12))
            for i, val in enumerate(samples):
                bcol = "#f85149" if val > 7.2 else ("#e3b341" if val > 6.5 else "#3fb950")
                col_box = ctk.CTkFrame(s_frame, width=16, height=36, fg_color=bcol, corner_radius=2)
                col_box.pack(side="left", padx=1)

        info_explanation_card(
            frame,
            t.t("explainer.entropy_title"),
            t.t("explainer.entropy_text"),
        )

    # --- 6. Strings & IOCs Tab ---
    def _fill_strings(self, tab, t, result):
        frame = self._scrollable(tab)
        frame.pack(fill="both", expand=True, padx=4, pady=4)

        strings = result.get("strings", {})
        total = strings.get("total_strings", 0)

        section_header(frame, "Indicateurs de Compromission (IOCs) & Chaînes", f"{total} chaînes scannées")

        cats = [
            ("Ransomware & Mots-clés de rançon", strings.get("ransom", []), "#f85149"),
            ("Commandes suspectes (PowerShell / CMD / Reg)", strings.get("commands", []), "#fa8c16"),
            ("URLs & Adresses web", strings.get("urls", []), "#58a6ff"),
            ("Adresses IP", strings.get("ips", []), "#58a6ff"),
            ("Clés de Registre Windows", strings.get("registry", []), "#e5b810"),
        ]

        found_any = False
        for title, items, color in cats:
            if items:
                found_any = True
                section_header(frame, title, f"{len(items)} trouvée(s)")
                card = ctk.CTkFrame(frame, fg_color="#0d1117", corner_radius=6, border_width=1, border_color="#30363d")
                card.pack(fill="x", padx=4, pady=(0, 8))
                for item in items:
                    irow = ctk.CTkFrame(card, fg_color="transparent")
                    irow.pack(fill="x", padx=10, pady=2)
                    ctk.CTkLabel(irow, text=f"• {item}", font=ctk.CTkFont(family="Consolas", size=11), text_color=color, wraplength=950, justify="left").pack(side="left")
                    c_btn = ctk.CTkButton(irow, text=t.t("misc.copy"), width=50, height=20, font=ctk.CTkFont(size=10), fg_color="#21262d", hover_color="#30363d")
                    c_btn.configure(command=lambda v=item, b=c_btn: self._copy_to_clipboard(v, b, t))
                    c_btn.pack(side="right")

        if not found_any:
            ctk.CTkLabel(frame, text="Aucun IOC ou commande suspecte détectée dans les chaînes.", font=ctk.CTkFont(size=13), text_color="#8b949e").pack(padx=12, pady=16, anchor="w")

        info_explanation_card(
            frame,
            t.t("explainer.strings_title"),
            t.t("explainer.strings_text"),
        )

    # --- 7. YARA Tab ---
    def _fill_yara(self, tab, t, result):
        frame = self._scrollable(tab)
        frame.pack(fill="both", expand=True, padx=4, pady=4)

        yara = result.get("yara", {})
        available = yara.get("available", False)
        matches = yara.get("matches", [])

        section_header(frame, t.t("tabs.yara"), f"{len(matches)} règle(s) déclenchée(s)")

        if not available:
            ctk.CTkLabel(frame, text="Le moteur YARA est désactivé ou indisponible.", font=ctk.CTkFont(size=13), text_color="#8b949e").pack(padx=12, pady=16, anchor="w")
            info_explanation_card(
                frame,
                t.t("explainer.yara_title"),
                t.t("explainer.yara_text"),
            )
            return

        if not matches:
            ctk.CTkLabel(frame, text="Aucune signature de malware YARA détectée dans ce fichier.", font=ctk.CTkFont(size=13), text_color="#3fb950").pack(padx=12, pady=16, anchor="w")
        else:
            for m in matches:
                m_card = ctk.CTkFrame(frame, fg_color="#0d1117", corner_radius=6, border_width=1, border_color="#da3633")
                m_card.pack(fill="x", padx=4, pady=3)
                m_inner = ctk.CTkFrame(m_card, fg_color="transparent")
                m_inner.pack(fill="x", padx=10, pady=8)
                ctk.CTkLabel(m_inner, text=f"🔴 Règle : {m.get('rule')}", font=ctk.CTkFont(size=13, weight="bold"), text_color="#f85149").pack(anchor="w")
                if m.get("description"):
                    ctk.CTkLabel(m_inner, text=m["description"], font=ctk.CTkFont(size=12), text_color="#e6edf3").pack(anchor="w", pady=(2, 0))

        info_explanation_card(
            frame,
            t.t("explainer.yara_title"),
            t.t("explainer.yara_text"),
        )

    # --- 8. VirusTotal Tab ---
    def _fill_vt(self, tab, t, result):
        frame = self._scrollable(tab)
        frame.pack(fill="both", expand=True, padx=4, pady=4)

        vt = result.get("virustotal", {})
        status = vt.get("status", "disabled")

        section_header(frame, "Réputation VirusTotal (Lookup SHA-256)")

        if status == "disabled":
            ctk.CTkLabel(
                frame,
                text="La vérification VirusTotal est désactivée. Vous pouvez l'activer dans les Réglages ⚙ avec votre clé API gratuite.",
                font=ctk.CTkFont(size=13),
                text_color="#8b949e",
                wraplength=700,
                justify="left",
            ).pack(padx=12, pady=16, anchor="w")
        elif status == "not_found":
            ctk.CTkLabel(
                frame,
                text="Ce fichier (empreinte SHA-256) n'a jamais été soumis à VirusTotal.",
                font=ctk.CTkFont(size=13),
                text_color="#8b949e",
            ).pack(padx=12, pady=16, anchor="w")
        elif status == "found":
            mal = vt.get("malicious", 0)
            susp = vt.get("suspicious", 0)
            tot = vt.get("total_engines") or vt.get("total", 0) or (mal + susp + vt.get("undetected", 0) + vt.get("harmless", 0)) or 1
            harmless = vt.get("harmless", 0)
            undetected = vt.get("undetected", 0)
            permalink = vt.get("permalink")
            flagged = vt.get("flagged_by", [])

            col = "#f85149" if mal > 0 else ("#e3b341" if susp > 0 else "#3fb950")
            vt_card = ctk.CTkFrame(frame, fg_color="#0d1117", corner_radius=6, border_width=1, border_color="#30363d")
            vt_card.pack(fill="x", padx=4, pady=8)
            v_inner = ctk.CTkFrame(vt_card, fg_color="transparent")
            v_inner.pack(fill="x", padx=14, pady=12)

            if mal > 0:
                header_txt = f"🚨 {mal} moteur(s) antivirus ont détecté ce fichier comme malveillant (sur {tot})"
            elif susp > 0:
                header_txt = f"⚠️ {susp} moteur(s) signalent ce fichier comme suspect (sur {tot})"
            else:
                header_txt = f"🟢 Aucun antivirus ne signale ce fichier (0/{tot} détections)"

            ctk.CTkLabel(v_inner, text=header_txt, font=ctk.CTkFont(size=15, weight="bold"), text_color=col).pack(anchor="w", pady=(0, 8))

            # Progress ratio bar
            ratio = (mal + susp) / max(1, tot)
            pbar = ctk.CTkProgressBar(v_inner, height=8, progress_color=col, fg_color="#21262d")
            pbar.pack(fill="x", pady=(0, 10))
            pbar.set(ratio)

            # Details stats
            s_row = ctk.CTkFrame(v_inner, fg_color="transparent")
            s_row.pack(fill="x", pady=(0, 4))
            ctk.CTkLabel(s_row, text=f"• Malveillants : {mal}", font=ctk.CTkFont(size=12, weight="bold"), text_color="#f85149").pack(side="left", padx=(0, 16))
            ctk.CTkLabel(s_row, text=f"• Suspects : {susp}", font=ctk.CTkFont(size=12), text_color="#e3b341").pack(side="left", padx=(0, 16))
            ctk.CTkLabel(s_row, text=f"• Sains / Indétectés : {undetected + harmless}", font=ctk.CTkFont(size=12), text_color="#3fb950").pack(side="left")

            # Flagged engines detail
            if flagged:
                section_header(frame, "Détail des détections antivirus", f"{len(flagged)} moteur(s)")
                f_card = ctk.CTkFrame(frame, fg_color="#0d1117", corner_radius=6, border_width=1, border_color="#30363d")
                f_card.pack(fill="x", padx=4, pady=(0, 10))
                for f_item in flagged:
                    eng = f_item.get("engine", "Antivirus")
                    res_name = f_item.get("result", "Malveillant")
                    frow = ctk.CTkFrame(f_card, fg_color="transparent")
                    frow.pack(fill="x", padx=12, pady=3)
                    ctk.CTkLabel(frow, text=f"🛡️ {eng}", font=ctk.CTkFont(size=12, weight="bold"), text_color="#f0f6fc", width=180, anchor="w").pack(side="left")
                    ctk.CTkLabel(frow, text=res_name, font=ctk.CTkFont(family="Consolas", size=11), text_color="#f85149", anchor="w").pack(side="left", fill="x", expand=True)

            # Online report link button
            if permalink:
                ctk.CTkButton(
                    frame,
                    text="🌐 Voir le rapport complet en direct sur VirusTotal.com",
                    font=ctk.CTkFont(size=12, weight="bold"),
                    height=34,
                    fg_color="#1f6feb",
                    hover_color="#1158c7",
                    command=lambda u=permalink: webbrowser.open(u),
                ).pack(anchor="w", padx=6, pady=8)

        else:
            ctk.CTkLabel(frame, text=f"Statut VirusTotal : {status}", font=ctk.CTkFont(size=13), text_color="#e3b341").pack(padx=12, pady=16, anchor="w")

    # --- 9. Privacy Tab ---
    def _fill_privacy(self, tab, t):
        frame = self._scrollable(tab)
        frame.pack(fill="both", expand=True, padx=4, pady=4)

        section_header(frame, "Garantie de Confidentialité & Vie Privée")
        p_card = ctk.CTkFrame(frame, fg_color="#0d1117", corner_radius=6, border_width=1, border_color="#30363d")
        p_card.pack(fill="x", padx=4, pady=8)

        p_inner = ctk.CTkFrame(p_card, fg_color="transparent")
        p_inner.pack(fill="x", padx=14, pady=12)

        items = [
            ("🔒 Analyse 100% Locale", "Tous les calculs (hachages, PE, chaînes, entropie, YARA) sont exécutés localement sur votre processeur."),
            ("🚫 Aucun Fichier Téléversé", "Le contenu de vos fichiers personnels ne quitte jamais votre ordinateur."),
            ("🌐 VirusTotal Sécurisé", "Si activé, seule l'empreinte SHA-256 (64 caractères) est envoyée pour vérifier sa réputation."),
            ("🤖 Analyste IA Privé", "Seules les métadonnées techniques abstraites (noms de fonctions, score) sont envoyées à l'IA."),
            ("⚡ Aucune Télémétrie", "MalyxScanner ne collecte aucun journal d'activité ni statistique d'usage."),
        ]
        for title, desc in items:
            ctk.CTkLabel(p_inner, text=title, font=ctk.CTkFont(size=13, weight="bold"), text_color="#3fb950").pack(anchor="w", pady=(4, 0))
            ctk.CTkLabel(p_inner, text=desc, font=ctk.CTkFont(size=12), text_color="#8b949e", wraplength=700, justify="left").pack(anchor="w", pady=(0, 6))

    def _kv_row(self, parent, key, val, t, copyable=False, mono=False, custom_color=None):
        row = ctk.CTkFrame(parent, fg_color="transparent")
        row.pack(fill="x", padx=12, pady=4)
        ctk.CTkLabel(row, text=key + " :", font=ctk.CTkFont(size=12, weight="bold"), text_color="#8b949e", width=180, anchor="w").pack(side="left")
        font_family = "Consolas" if mono else "Segoe UI"
        text_col = custom_color or "#f0f6fc"
        ctk.CTkLabel(row, text=str(val), font=ctk.CTkFont(family=font_family, size=12), text_color=text_col, wraplength=480, justify="left").pack(side="left", fill="x", expand=True)
        if copyable and str(val) not in ("?", "", "None"):
            c_btn = ctk.CTkButton(row, text=t.t("misc.copy"), width=55, height=22, font=ctk.CTkFont(size=11), fg_color="#21262d", hover_color="#30363d")
            c_btn.configure(command=lambda v=str(val), b=c_btn: self._copy_to_clipboard(v, b, t))
            c_btn.pack(side="right")
