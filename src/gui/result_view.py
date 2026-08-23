import customtkinter as ctk

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
        fg_color="#161b22",
        corner_radius=8,
        border_width=1,
        border_color=theme["border"],
    )
    card.pack(fill="x", padx=4, pady=3)

    inner = ctk.CTkFrame(card, fg_color="transparent")
    inner.pack(fill="x", padx=12, pady=8)

    badge = ctk.CTkFrame(inner, fg_color=theme["bg"], corner_radius=4, border_width=1, border_color=theme["border"])
    badge.pack(side="left", padx=(0, 10))
    ctk.CTkLabel(
        badge,
        text=f"{SEVERITY_ICONS.get(sev, '•')} {sev_label}",
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


class ResultView(ctk.CTkFrame):
    def __init__(self, master, result, translator, **kwargs):
        super().__init__(master, fg_color="#0d1117", **kwargs)
        self.result = result
        self.t = translator
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

        status_text = t.t(f"execution.status.{adv_status}")
        ctk.CTkLabel(
            e_inner,
            text=f"{atheme['icon']}  {status_text}",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color=atheme["title_color"],
            anchor="w",
        ).pack(anchor="w")

        msg_key = advice.get("message_key", "execution.safe_message")
        ctk.CTkLabel(
            e_inner,
            text=t.t(msg_key),
            font=ctk.CTkFont(size=12),
            text_color="#e6edf3",
            wraplength=940,
            justify="left",
            anchor="w",
        ).pack(anchor="w", pady=(2, 0))

        # --- 4 Quick Metric Summary Cards ---
        metrics_bar = ctk.CTkFrame(self, fg_color="transparent")
        metrics_bar.pack(fill="x", padx=12, pady=(0, 8))
        metrics_bar.columnconfigure((0, 1, 2, 3), weight=1)

        real_type = result.get("identity", {}).get("human_type") or result.get("identity", {}).get("family", "inconnu")
        ent_val = result.get("entropy", {}).get("global", 0)
        
        all_findings = []
        for f in result.get("identity", {}).get("findings", []):
            if f.get("code") != "find.type_ok":
                all_findings.append(f)
        if result.get("entropy", {}).get("finding"):
            all_findings.append(result["entropy"]["finding"])
        for f in result.get("pe", {}).get("findings", []):
            if f.get("code") != "pe.not_pe":
                all_findings.append(f)
        for m in result.get("yara", {}).get("matches", []):
            all_findings.append({"code": "yara.match", "severity": m["severity"]})

        metric_items = [
            ("📁 Type de fichier", str(real_type)[:24], "#58a6ff"),
            ("🏷️ Famille de menace", f"{threat_icon} {threat_name}", "#f85149" if threat_key != "clean" else "#3fb950"),
            ("📊 Entropie globale", f"{ent_val:.2f} / 8.0" if ent_val else "N/A", "#bc8cff"),
            ("⚠️ Indicateurs détectés", f"{len(all_findings)} élément(s)", "#f0883e" if all_findings else "#3fb950"),
        ]

        for col, (m_label, m_val, m_col) in enumerate(metric_items):
            m_card = ctk.CTkFrame(metrics_bar, fg_color="#161b22", corner_radius=8, border_width=1, border_color="#30363d")
            m_card.grid(row=0, column=col, padx=3, sticky="nsew")
            ctk.CTkLabel(m_card, text=m_label, font=ctk.CTkFont(size=11), text_color="#8b949e", anchor="w").pack(padx=10, pady=(6, 0), anchor="w")
            ctk.CTkLabel(m_card, text=m_val, font=ctk.CTkFont(size=13, weight="bold"), text_color=m_col, anchor="w").pack(padx=10, pady=(2, 6), anchor="w")

        # --- Main Tabview ---
        tabs = ctk.CTkTabview(
            self,
            anchor="nw",
            fg_color="#161b22",
            segmented_button_fg_color="#0d1117",
            segmented_button_selected_color="#1f6feb",
            segmented_button_unselected_color="#21262d",
            segmented_button_selected_hover_color="#1158c7",
        )
        tabs.pack(fill="both", expand=True, padx=12, pady=(0, 10))

        tab_keys = ["summary", "safety", "identity", "pe", "entropy", "strings", "yara", "vt", "privacy"]
        for key in tab_keys:
            tabs.add(t.t(f"tabs.{key}"))

        self._fill_summary(tabs.tab(t.t("tabs.summary")), t, result, all_findings, advice, threat_key)
        self._fill_safety(tabs.tab(t.t("tabs.safety")), t, result, advice, threat_key)
        self._fill_identity(tabs.tab(t.t("tabs.identity")), t, result)
        self._fill_pe(tabs.tab(t.t("tabs.pe")), t, result)
        self._fill_entropy(tabs.tab(t.t("tabs.entropy")), t, result)
        self._fill_strings(tabs.tab(t.t("tabs.strings")), t, result)
        self._fill_yara(tabs.tab(t.t("tabs.yara")), t, result)
        self._fill_vt(tabs.tab(t.t("tabs.vt")), t, result)
        self._fill_privacy(tabs.tab(t.t("tabs.privacy")), t)

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

        # Recommended actions
        actions = advice.get("actions", [])
        if actions:
            ctk.CTkLabel(t_card, text="🛡️ " + t.t("execution.actions_title"), font=ctk.CTkFont(size=12, weight="bold"), text_color="#58a6ff").pack(padx=12, pady=(8, 2), anchor="w")
            for a_key in actions:
                ctk.CTkLabel(t_card, text=f"  ✔ {t.t(a_key)}", font=ctk.CTkFont(size=12), text_color="#e6edf3", wraplength=700, justify="left").pack(padx=16, pady=1, anchor="w")
            ctk.CTkFrame(t_card, fg_color="transparent", height=6).pack()

        # Risk breakdown section
        section_header(frame, "Décomposition du score de risque")
        breakdown_box = ctk.CTkFrame(frame, fg_color="#0d1117", corner_radius=6, border_width=1, border_color="#30363d")
        breakdown_box.pack(fill="x", padx=4, pady=(0, 8))

        breakdown = result.get("risk", {}).get("breakdown", [])
        if breakdown:
            for item in breakdown:
                pts = item.get("points", 0)
                row = ctk.CTkFrame(breakdown_box, fg_color="transparent")
                row.pack(fill="x", padx=12, pady=4)
                ctk.CTkLabel(row, text=f"• {t.t(item['key'])}", font=ctk.CTkFont(size=13), text_color="#e6edf3").pack(side="left")
                ctk.CTkLabel(row, text=f"+{pts} pts", font=ctk.CTkFont(size=13, weight="bold"), text_color="#f0883e").pack(side="right")
        else:
            ctk.CTkLabel(breakdown_box, text=t.t("find.none"), text_color="#3fb950", font=ctk.CTkFont(size=13)).pack(padx=12, pady=8, anchor="w")

        # Findings section
        section_header(frame, "Anomalies et indicateurs de menace détectés")
        seen = set()
        unique = []
        for f in all_findings:
            k = (f.get("code"), tuple(sorted((k, str(v)) for k, v in (f.get("params") or {}).items())))
            if k not in seen:
                seen.add(k)
                unique.append(f)

        if unique:
            order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
            unique.sort(key=lambda x: order.get(x.get("severity", "info"), 9))
            for f in unique:
                finding_card(frame, t, f)
        else:
            good_box = ctk.CTkFrame(frame, fg_color="#0d1117", corner_radius=6, border_width=1, border_color="#238636")
            good_box.pack(fill="x", padx=4, pady=4)
            ctk.CTkLabel(good_box, text="✔ " + t.t("find.none"), font=ctk.CTkFont(size=13), text_color="#3fb950").pack(padx=12, pady=10, anchor="w")

    # --- 2. Safety & Execution Tab ---
    def _fill_safety(self, tab, t, result, advice, threat_key):
        frame = self._scrollable(tab)
        frame.pack(fill="both", expand=True, padx=4, pady=4)

        adv_status = advice.get("advice_status", "safe")
        atheme = ADVICE_THEMES.get(adv_status, ADVICE_THEMES["safe"])
        status_text = t.t(f"execution.status.{adv_status}")

        section_header(frame, "Recommandation de Sécurité & Précautions d'Exécution")

        decision_card = ctk.CTkFrame(frame, fg_color=atheme["bg"], corner_radius=8, border_width=1, border_color=atheme["border"])
        decision_card.pack(fill="x", padx=4, pady=(0, 12))
        d_inner = ctk.CTkFrame(decision_card, fg_color="transparent")
        d_inner.pack(fill="x", padx=16, pady=12)

        ctk.CTkLabel(d_inner, text=f"{atheme['icon']}  {status_text}", font=ctk.CTkFont(size=16, weight="bold"), text_color=atheme["title_color"]).pack(anchor="w")
        ctk.CTkLabel(d_inner, text=t.t(advice.get("title_key", "execution.safe_title")), font=ctk.CTkFont(size=13, weight="bold"), text_color="#f0f6fc").pack(anchor="w", pady=(6, 2))
        ctk.CTkLabel(d_inner, text=t.t(advice.get("message_key", "execution.safe_message")), font=ctk.CTkFont(size=12), text_color="#e6edf3", wraplength=720, justify="left").pack(anchor="w")

        # Threat classification
        threat_name = t.t(f"threat.type.{threat_key}")
        threat_desc = t.t(f"threat.desc.{threat_key}")
        threat_icon = THREAT_ICONS.get(threat_key, "🛡️")

        section_header(frame, "Typologie détaillée du fichier analysé")
        t_box = ctk.CTkFrame(frame, fg_color="#0d1117", corner_radius=6, border_width=1, border_color="#30363d")
        t_box.pack(fill="x", padx=4, pady=(0, 12))
        t_inner = ctk.CTkFrame(t_box, fg_color="transparent")
        t_inner.pack(fill="x", padx=14, pady=10)
        ctk.CTkLabel(t_inner, text=f"{threat_icon} {threat_name}", font=ctk.CTkFont(size=15, weight="bold"), text_color="#58a6ff").pack(anchor="w")
        ctk.CTkLabel(t_inner, text=threat_desc, font=ctk.CTkFont(size=12), text_color="#e6edf3", wraplength=720, justify="left").pack(anchor="w", pady=(4, 0))

        # Potential Computer Risks
        risks = advice.get("risks", [])
        if risks:
            section_header(frame, "Quels sont les risques concrets pour votre PC ?")
            r_box = ctk.CTkFrame(frame, fg_color="#0d1117", corner_radius=6, border_width=1, border_color="#30363d")
            r_box.pack(fill="x", padx=4, pady=(0, 12))
            r_inner = ctk.CTkFrame(r_box, fg_color="transparent")
            r_inner.pack(fill="x", padx=14, pady=10)
            for r_key in risks:
                r_col = "#f85149" if adv_status == "danger" else ("#e3b341" if adv_status == "caution" else "#3fb950")
                ctk.CTkLabel(r_inner, text=f"• {t.t(r_key)}", font=ctk.CTkFont(size=13), text_color=r_col, wraplength=720, justify="left").pack(anchor="w", pady=3)

        # Protective Actions
        actions = advice.get("actions", [])
        if actions:
            section_header(frame, "Conduite à tenir & Actions recommandées")
            a_box = ctk.CTkFrame(frame, fg_color="#0d1117", corner_radius=6, border_width=1, border_color="#30363d")
            a_box.pack(fill="x", padx=4, pady=(0, 12))
            a_inner = ctk.CTkFrame(a_box, fg_color="transparent")
            a_inner.pack(fill="x", padx=14, pady=10)
            for a_key in actions:
                ctk.CTkLabel(a_inner, text=f"✔ {t.t(a_key)}", font=ctk.CTkFont(size=13), text_color="#e6edf3", wraplength=720, justify="left").pack(anchor="w", pady=3)

    # --- 3. Identity & Hashes Tab ---
    def _fill_identity(self, tab, t, result):
        frame = self._scrollable(tab)
        frame.pack(fill="both", expand=True, padx=4, pady=4)

        file_info = result.get("file", {})
        identity = result.get("identity", {})
        hashes_data = result.get("hashes", {})
        real_type = identity.get("human_type") or identity.get("mime") or t.t("misc.unknown")

        section_header(frame, "Informations générales sur le fichier")
        grid1 = ctk.CTkFrame(frame, fg_color="#0d1117", corner_radius=6, border_width=1, border_color="#30363d")
        grid1.pack(fill="x", padx=4, pady=(0, 10))
        grid1.columnconfigure(1, weight=1)

        general_rows = [
            (t.t("field.name"), file_info.get("name", ""), None),
            (t.t("field.path"), file_info.get("path", ""), file_info.get("path")),
            (t.t("field.size"), f"{file_info.get('size_human', '')} ({file_info.get('size', 0)} octets)", None),
            (t.t("field.type_declared"), identity.get("extension") or "?", None),
            (t.t("field.type_real"), str(real_type), None),
            (t.t("field.attributes"), ", ".join(file_info.get("attributes", ["Normal"])), None),
            (t.t("field.created"), file_info.get("created", ""), None),
            (t.t("field.modified"), file_info.get("modified", ""), None),
            (t.t("field.accessed"), file_info.get("accessed", ""), None),
        ]

        for idx, (label, val, clip) in enumerate(general_rows):
            bg = "#161b22" if idx % 2 == 0 else "#0d1117"
            row = ctk.CTkFrame(grid1, fg_color=bg, corner_radius=0)
            row.pack(fill="x", padx=1, pady=1)
            row.columnconfigure(1, weight=1)
            ctk.CTkLabel(row, text=label, font=ctk.CTkFont(size=12, weight="bold"), text_color="#8b949e", width=160, anchor="w").grid(row=0, column=0, padx=10, pady=4, sticky="w")
            ctk.CTkLabel(row, text=val, font=ctk.CTkFont(size=12), text_color="#e6edf3", anchor="w", justify="left").grid(row=0, column=1, padx=6, pady=4, sticky="w")
            if clip:
                c_btn = ctk.CTkButton(row, text=t.t("misc.copy"), width=56, height=22, font=ctk.CTkFont(size=11), fg_color="#21262d", hover_color="#30363d")
                c_btn.configure(command=lambda v=clip, b=c_btn: self._copy_to_clipboard(v, b, t))
                c_btn.grid(row=0, column=2, padx=10, pady=4)

        section_header(frame, "Empreintes cryptographiques & Hachages")
        grid2 = ctk.CTkFrame(frame, fg_color="#0d1117", corner_radius=6, border_width=1, border_color="#30363d")
        grid2.pack(fill="x", padx=4, pady=(0, 10))

        hash_rows = [
            (t.t("field.sha256"), hashes_data.get("sha256", "")),
            (t.t("field.sha512"), hashes_data.get("sha512", "")),
            (t.t("field.sha1"), hashes_data.get("sha1", "")),
            (t.t("field.md5"), hashes_data.get("md5", "")),
            (t.t("field.crc32"), hashes_data.get("crc32", "")),
        ]
        if hashes_data.get("imphash"):
            hash_rows.append((t.t("field.imphash"), hashes_data["imphash"]))

        for idx, (label, val) in enumerate(hash_rows):
            bg = "#161b22" if idx % 2 == 0 else "#0d1117"
            row = ctk.CTkFrame(grid2, fg_color=bg, corner_radius=0)
            row.pack(fill="x", padx=1, pady=1)
            row.columnconfigure(1, weight=1)
            ctk.CTkLabel(row, text=label, font=ctk.CTkFont(size=12, weight="bold"), text_color="#8b949e", width=160, anchor="w").grid(row=0, column=0, padx=10, pady=5, sticky="w")
            ctk.CTkLabel(row, text=val, font=ctk.CTkFont(family="Consolas", size=12), text_color="#58a6ff", anchor="w").grid(row=0, column=1, padx=6, pady=5, sticky="w")
            if val:
                c_btn = ctk.CTkButton(row, text=t.t("misc.copy"), width=56, height=22, font=ctk.CTkFont(size=11), fg_color="#21262d", hover_color="#30363d")
                c_btn.configure(command=lambda v=val, b=c_btn: self._copy_to_clipboard(v, b, t))
                c_btn.grid(row=0, column=2, padx=10, pady=5)

    # --- 4. PE Structure Tab ---
    def _fill_pe(self, tab, t, result):
        frame = self._scrollable(tab)
        frame.pack(fill="both", expand=True, padx=4, pady=4)

        pe = result.get("pe", {})
        if not pe.get("applicable"):
            ctk.CTkLabel(frame, text=t.t("pe.not_pe"), font=ctk.CTkFont(size=13), text_color="#8b949e").pack(padx=10, pady=20)
            return

        if not pe.get("parsed"):
            finding_card(frame, t, {"code": "pe.parse_failed", "severity": "medium", "params": {}})
            return

        info = pe.get("info", {})

        section_header(frame, "En-têtes et architecture PE")
        pe_grid = ctk.CTkFrame(frame, fg_color="#0d1117", corner_radius=6, border_width=1, border_color="#30363d")
        pe_grid.pack(fill="x", padx=4, pady=(0, 10))

        pe_fields = [
            (t.t("pe_info.machine"), info.get("machine", "N/A")),
            (t.t("pe_info.subsystem"), info.get("subsystem", "N/A")),
            (t.t("pe_info.signed"), t.t("misc.yes") if info.get("is_signed") else t.t("misc.no")),
            (t.t("pe_info.dotnet"), t.t("misc.yes") if info.get("is_dotnet") else t.t("misc.no")),
            (t.t("pe_info.entry_point"), info.get("entry_point", "N/A")),
            (t.t("pe_info.image_base"), info.get("image_base", "N/A")),
            (t.t("pe_info.timestamp"), info.get("compiled") or "Inconnu"),
        ]
        if info.get("pdb_path"):
            pe_fields.append((t.t("pe_info.pdb"), info["pdb_path"]))

        for idx, (label, val) in enumerate(pe_fields):
            bg = "#161b22" if idx % 2 == 0 else "#0d1117"
            row = ctk.CTkFrame(pe_grid, fg_color=bg, corner_radius=0)
            row.pack(fill="x", padx=1, pady=1)
            row.columnconfigure(1, weight=1)
            ctk.CTkLabel(row, text=label, font=ctk.CTkFont(size=12, weight="bold"), text_color="#8b949e", width=180, anchor="w").grid(row=0, column=0, padx=10, pady=4, sticky="w")
            val_col = "#3fb950" if val in (t.t("misc.yes"),) else ("#f85149" if val in (t.t("misc.no"),) and label == t.t("pe_info.signed") else "#e6edf3")
            ctk.CTkLabel(row, text=val, font=ctk.CTkFont(size=12), text_color=val_col, anchor="w").grid(row=0, column=1, padx=6, pady=4, sticky="w")

        v_info = info.get("version_info", {})
        if v_info:
            section_header(frame, t.t("pe_info.version"))
            v_grid = ctk.CTkFrame(frame, fg_color="#0d1117", corner_radius=6, border_width=1, border_color="#30363d")
            v_grid.pack(fill="x", padx=4, pady=(0, 10))
            for idx, (k, v) in enumerate(v_info.items()):
                bg = "#161b22" if idx % 2 == 0 else "#0d1117"
                row = ctk.CTkFrame(v_grid, fg_color=bg, corner_radius=0)
                row.pack(fill="x", padx=1, pady=1)
                row.columnconfigure(1, weight=1)
                ctk.CTkLabel(row, text=k, font=ctk.CTkFont(size=12, weight="bold"), text_color="#8b949e", width=180, anchor="w").grid(row=0, column=0, padx=10, pady=4, sticky="w")
                ctk.CTkLabel(row, text=str(v), font=ctk.CTkFont(size=12), text_color="#e6edf3", anchor="w").grid(row=0, column=1, padx=6, pady=4, sticky="w")

        sections = info.get("sections", [])
        if sections:
            section_header(frame, f"{t.t('pe_info.sections')} ({len(sections)})")
            s_grid = ctk.CTkFrame(frame, fg_color="#0d1117", corner_radius=6, border_width=1, border_color="#30363d")
            s_grid.pack(fill="x", padx=4, pady=(0, 10))
            
            h_row = ctk.CTkFrame(s_grid, fg_color="#21262d", corner_radius=0)
            h_row.pack(fill="x", padx=1, pady=1)
            h_row.columnconfigure((0, 1, 2, 3, 4), weight=2)
            ctk.CTkLabel(h_row, text="Nom", font=ctk.CTkFont(size=11, weight="bold"), text_color="#8b949e").grid(row=0, column=0, padx=8, pady=4, sticky="w")
            ctk.CTkLabel(h_row, text="Taille disque", font=ctk.CTkFont(size=11, weight="bold"), text_color="#8b949e").grid(row=0, column=1, padx=8, pady=4, sticky="w")
            ctk.CTkLabel(h_row, text="Taille mémoire", font=ctk.CTkFont(size=11, weight="bold"), text_color="#8b949e").grid(row=0, column=2, padx=8, pady=4, sticky="w")
            ctk.CTkLabel(h_row, text="Entropie", font=ctk.CTkFont(size=11, weight="bold"), text_color="#8b949e").grid(row=0, column=3, padx=8, pady=4, sticky="w")
            ctk.CTkLabel(h_row, text="Flags", font=ctk.CTkFont(size=11, weight="bold"), text_color="#8b949e").grid(row=0, column=4, padx=8, pady=4, sticky="w")

            for idx, s in enumerate(sections):
                bg = "#161b22" if idx % 2 == 0 else "#0d1117"
                s_row = ctk.CTkFrame(s_grid, fg_color=bg, corner_radius=0)
                s_row.pack(fill="x", padx=1, pady=1)
                s_row.columnconfigure((0, 1, 2, 3, 4), weight=2)
                ent_color = "#f85149" if s["entropy"] > 7.0 else ("#d29922" if s["entropy"] > 6.2 else "#e6edf3")
                flag_color = "#f85149" if "W" in s["flags"] and "X" in s["flags"] else "#e6edf3"
                ctk.CTkLabel(s_row, text=s["name"], font=ctk.CTkFont(size=12, weight="bold"), text_color="#58a6ff").grid(row=0, column=0, padx=8, pady=3, sticky="w")
                ctk.CTkLabel(s_row, text=f"{s['size']:,} o", font=ctk.CTkFont(size=12), text_color="#e6edf3").grid(row=0, column=1, padx=8, pady=3, sticky="w")
                ctk.CTkLabel(s_row, text=f"{s.get('virtual_size', 0):,} o", font=ctk.CTkFont(size=12), text_color="#8b949e").grid(row=0, column=2, padx=8, pady=3, sticky="w")
                ctk.CTkLabel(s_row, text=f"{s['entropy']:.2f} / 8", font=ctk.CTkFont(size=12), text_color=ent_color).grid(row=0, column=3, padx=8, pady=3, sticky="w")
                ctk.CTkLabel(s_row, text=s["flags"] or "-", font=ctk.CTkFont(size=12, weight="bold"), text_color=flag_color).grid(row=0, column=4, padx=8, pady=3, sticky="w")

        mitre_apis = info.get("mitre_apis", {})
        if mitre_apis:
            section_header(frame, t.t("pe_info.mitre_title"))
            m_box = ctk.CTkFrame(frame, fg_color="#0d1117", corner_radius=6, border_width=1, border_color="#30363d")
            m_box.pack(fill="x", padx=4, pady=(0, 10))
            for cat, apis in mitre_apis.items():
                c_frame = ctk.CTkFrame(m_box, fg_color="#161b22", corner_radius=4, border_width=1, border_color="#30363d")
                c_frame.pack(fill="x", padx=8, pady=4)
                ctk.CTkLabel(c_frame, text=f"🏷️ {cat.upper()}", font=ctk.CTkFont(size=11, weight="bold"), text_color="#fa8c16").pack(anchor="w", padx=8, pady=(4, 2))
                ctk.CTkLabel(c_frame, text=", ".join(apis), font=ctk.CTkFont(family="Consolas", size=12), text_color="#e6edf3", wraplength=680, justify="left").pack(anchor="w", padx=8, pady=(0, 4))

        exports = info.get("exports", [])
        if exports:
            section_header(frame, f"{t.t('pe_info.exports')} ({len(exports)})")
            exp_box = ctk.CTkFrame(frame, fg_color="#0d1117", corner_radius=6, border_width=1, border_color="#30363d")
            exp_box.pack(fill="x", padx=4, pady=(0, 10))
            exp_text = ", ".join([e["name"] for e in exports[:40]])
            if len(exports) > 40:
                exp_text += f" ... (+{len(exports) - 40} autres)"
            ctk.CTkLabel(exp_box, text=exp_text, font=ctk.CTkFont(family="Consolas", size=12), text_color="#58a6ff", wraplength=700, justify="left").pack(padx=10, pady=8, anchor="w")

    # --- 5. Entropy & Blocks Tab ---
    def _fill_entropy(self, tab, t, result):
        frame = self._scrollable(tab)
        frame.pack(fill="both", expand=True, padx=4, pady=4)

        ent_data = result.get("entropy", {})
        glob_ent = ent_data.get("global")
        level = ent_data.get("level", "normal")
        blocks = ent_data.get("blocks", {})

        section_header(frame, t.t("entropy_tab.title"))
        e_card = ctk.CTkFrame(frame, fg_color="#0d1117", corner_radius=6, border_width=1, border_color="#30363d")
        e_card.pack(fill="x", padx=4, pady=(0, 10))

        if glob_ent is not None:
            ctk.CTkLabel(e_card, text=f"Entropie globale : {glob_ent:.3f} / 8.00 ({level.upper()})", font=ctk.CTkFont(size=14, weight="bold"), text_color="#bc8cff").pack(anchor="w", padx=12, pady=(10, 4))
            
            if blocks.get("total_blocks"):
                ctk.CTkLabel(e_card, text=f"• Blocs analysés (16 Ko) : {blocks['total_blocks']}", font=ctk.CTkFont(size=12), text_color="#e6edf3").pack(anchor="w", padx=12, pady=2)
                ctk.CTkLabel(e_card, text=f"• Entropie minimale : {blocks['min']:.2f}  |  Maximale : {blocks['max']:.2f}  |  Moyenne : {blocks['avg']:.2f}", font=ctk.CTkFont(size=12), text_color="#e6edf3").pack(anchor="w", padx=12, pady=2)
                ctk.CTkLabel(e_card, text=f"• Blocs hautement chiffrés / packés (> 7.2) : {blocks['high_count']} sur {blocks['total_blocks']}", font=ctk.CTkFont(size=12), text_color="#f85149" if blocks['high_count'] else "#3fb950").pack(anchor="w", padx=12, pady=(2, 10))

                samples = blocks.get("samples", [])
                if samples:
                    section_header(frame, "Distribution visuelle de l'entropie par bloc")
                    map_box = ctk.CTkFrame(frame, fg_color="#0d1117", corner_radius=6, border_width=1, border_color="#30363d")
                    map_box.pack(fill="x", padx=4, pady=(0, 10))
                    grid_bar = ctk.CTkFrame(map_box, fg_color="transparent")
                    grid_bar.pack(fill="x", padx=12, pady=10)
                    for idx, val in enumerate(samples):
                        if val > 7.2:
                            color = "#da3633"
                        elif val > 6.0:
                            color = "#d29922"
                        elif val > 4.0:
                            color = "#1f6feb"
                        else:
                            color = "#238636"
                        b_elem = ctk.CTkFrame(grid_bar, fg_color=color, width=18, height=36, corner_radius=3)
                        b_elem.pack(side="left", padx=1, pady=2)

    # --- 6. Strings & IOCs Tab ---
    def _fill_strings(self, tab, t, result):
        frame = self._scrollable(tab)
        frame.pack(fill="both", expand=True, padx=4, pady=4)

        strings = result.get("strings", {})
        total = strings.get("total_strings", 0)

        section_header(frame, t.t("strings_tab.title"), subtitle=f"{total} chaînes extraites")

        categories = [
            ("ransom", "🚨 Indicateurs de Ransomware / Tor", strings.get("ransom", []), "#f85149"),
            ("commands", "⚙️ Commandes système & Processus", strings.get("commands", []), "#fa8c16"),
            ("urls", "🌐 URLs & Domaines Web", strings.get("urls", []), "#58a6ff"),
            ("ips", "📡 Adresses IP extraites", strings.get("ips", []), "#40a9ff"),
            ("registry", "🔑 Clés de Registre / Persistance", strings.get("registry", []), "#d29922"),
        ]

        has_any = False
        for cat_id, cat_title, items, col in categories:
            if items:
                has_any = True
                section_header(frame, f"{cat_title} ({len(items)})")
                box = ctk.CTkFrame(frame, fg_color="#0d1117", corner_radius=6, border_width=1, border_color="#30363d")
                box.pack(fill="x", padx=4, pady=(0, 8))
                for it in items:
                    row = ctk.CTkFrame(box, fg_color="transparent")
                    row.pack(fill="x", padx=10, pady=2)
                    ctk.CTkLabel(row, text=f"• {it}", font=ctk.CTkFont(family="Consolas", size=12), text_color=col, anchor="w", justify="left", wraplength=640).pack(side="left", fill="x", expand=True)
                    c_btn = ctk.CTkButton(row, text=t.t("misc.copy"), width=50, height=20, font=ctk.CTkFont(size=10), fg_color="#21262d", hover_color="#30363d")
                    c_btn.configure(command=lambda v=it, b=c_btn: self._copy_to_clipboard(v, b, t))
                    c_btn.pack(side="right", padx=(6, 0))

        if not has_any:
            no_box = ctk.CTkFrame(frame, fg_color="#0d1117", corner_radius=6, border_width=1, border_color="#238636")
            no_box.pack(fill="x", padx=4, pady=10)
            ctk.CTkLabel(no_box, text="✔ " + t.t("strings_tab.none"), font=ctk.CTkFont(size=13), text_color="#3fb950").pack(padx=12, pady=12, anchor="w")

    # --- 7. YARA Tab ---
    def _fill_yara(self, tab, t, result):
        frame = self._scrollable(tab)
        frame.pack(fill="both", expand=True, padx=4, pady=4)

        yara_res = result.get("yara", {})
        if not yara_res.get("available"):
            ctk.CTkLabel(frame, text=t.t("yara.disabled"), font=ctk.CTkFont(size=13), text_color="#8b949e").pack(padx=10, pady=20)
            return

        count_text = t.t("yara.rules_count", count=yara_res.get("rules_count", 0), files=yara_res.get("rules_files", 0))
        section_header(frame, "Signatures YARA chargées", subtitle=count_text)

        matches = yara_res.get("matches", [])
        if matches:
            for match in matches:
                finding_card(frame, t, {
                    "code": "yara.match",
                    "severity": match["severity"],
                    "params": {"rule": match["rule"], "desc": match["description"]},
                })
        else:
            good_box = ctk.CTkFrame(frame, fg_color="#0d1117", corner_radius=6, border_width=1, border_color="#238636")
            good_box.pack(fill="x", padx=4, pady=10)
            ctk.CTkLabel(good_box, text="✔ " + t.t("yara.none"), font=ctk.CTkFont(size=13), text_color="#3fb950").pack(padx=12, pady=12, anchor="w")

    # --- 8. VirusTotal Tab ---
    def _fill_vt(self, tab, t, result):
        frame = self._scrollable(tab)
        frame.pack(fill="both", expand=True, padx=4, pady=4)

        vt = result.get("virustotal", {})
        status = vt.get("status")

        section_header(frame, "Service de réputation VirusTotal (Hash-only)")
        note_box = ctk.CTkFrame(frame, fg_color="#0d1117", corner_radius=6, border_width=1, border_color="#1f6feb")
        note_box.pack(fill="x", padx=4, pady=(0, 10))
        ctk.CTkLabel(note_box, text="🔒 " + t.t("vt.enabled_note"), font=ctk.CTkFont(size=12), text_color="#58a6ff", wraplength=720, justify="left").pack(padx=12, pady=8, anchor="w")

        if status == "disabled":
            ctk.CTkLabel(frame, text=t.t("vt.disabled"), font=ctk.CTkFont(size=13), text_color="#8b949e").pack(padx=10, pady=10)
            return
        if status == "not_found":
            ctk.CTkLabel(frame, text=t.t("vt.not_found"), font=ctk.CTkFont(size=13), text_color="#d29922").pack(padx=10, pady=10)
            return
        if status.startswith("error_"):
            ctk.CTkLabel(frame, text=t.t(f"vt.{status}"), font=ctk.CTkFont(size=13), text_color="#f85149").pack(padx=10, pady=10)
            return

        if status == "found":
            malicious = vt.get("malicious", 0)
            total = vt.get("total_engines", 0)
            ratio = round(100 * malicious / total) if total else 0
            
            res_box = ctk.CTkFrame(frame, fg_color="#0d1117", corner_radius=6, border_width=1, border_color="#da3633" if malicious else "#238636")
            res_box.pack(fill="x", padx=4, pady=(0, 10))
            
            summary = t.t("vt.found", malicious=malicious, total=total) if malicious else t.t("vt.found_none", total=total)
            ctk.CTkLabel(res_box, text=summary, font=ctk.CTkFont(size=15, weight="bold"), text_color="#f85149" if malicious else "#3fb950").pack(padx=12, pady=(10, 2), anchor="w")
            ctk.CTkLabel(res_box, text=t.t("vt.ratio", ratio=ratio), font=ctk.CTkFont(size=12), text_color="#8b949e").pack(padx=12, pady=(0, 10), anchor="w")

            flagged = vt.get("flagged_by", [])
            if flagged:
                section_header(frame, t.t("vt.flagged_by"))
                f_box = ctk.CTkFrame(frame, fg_color="#0d1117", corner_radius=6, border_width=1, border_color="#30363d")
                f_box.pack(fill="x", padx=4, pady=(0, 10))
                for eng in flagged:
                    r = ctk.CTkFrame(f_box, fg_color="transparent")
                    r.pack(fill="x", padx=10, pady=2)
                    ctk.CTkLabel(r, text=f"• {eng['engine']}", font=ctk.CTkFont(size=12, weight="bold"), text_color="#e6edf3").pack(side="left")
                    ctk.CTkLabel(r, text=eng['result'], font=ctk.CTkFont(family="Consolas", size=12), text_color="#f85149").pack(side="right")

            permalink = vt.get("permalink")
            if permalink:
                ctk.CTkButton(frame, text="🌐 " + t.t("vt.open_link"), fg_color="#1f6feb", hover_color="#1158c7", command=lambda: self._open(permalink)).pack(anchor="w", padx=6, pady=10)

    def _open(self, url):
        import webbrowser
        webbrowser.open(url)

    # --- 9. Privacy Tab ---
    def _fill_privacy(self, tab, t):
        frame = self._scrollable(tab)
        frame.pack(fill="both", expand=True, padx=4, pady=4)

        section_header(frame, "Engagement de Confidentialité & Analyse 100% Locale")
        for key, icon in [("line1", "🔒"), ("line2", "🛡️"), ("telemetry", "✨")]:
            p_card = ctk.CTkFrame(frame, fg_color="#0d1117", corner_radius=6, border_width=1, border_color="#30363d")
            p_card.pack(fill="x", padx=4, pady=4)
            ctk.CTkLabel(p_card, text=f"{icon} {t.t(f'privacy.{key}')}", font=ctk.CTkFont(size=13), text_color="#e6edf3", wraplength=700, justify="left").pack(padx=14, pady=10, anchor="w")
