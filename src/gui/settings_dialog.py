import webbrowser
import customtkinter as ctk

from i18n.translator import available_languages
from .theme_manager import THEMES, available_themes, get_theme

RAM_PROFILES = {
    "balanced": {"max_mb": 200, "block_kb": 16, "yara": True, "strings": True},
    "low_ram": {"max_mb": 50, "block_kb": 32, "yara": True, "strings": False},
    "max_speed": {"max_mb": 500, "block_kb": 8, "yara": True, "strings": True},
}

AI_PROVIDERS = [
    ("openrouter", "OpenRouter (Universel — DeepSeek, Claude, Llama, GPT)"),
    ("google", "Google Gemini (Gemini 2.0 Flash / Pro)"),
    ("openai", "OpenAI (GPT-4o / GPT-4o-mini)"),
    ("anthropic", "Anthropic (Claude 3.5 Sonnet / Haiku)"),
]

AI_MODEL_SUGGESTIONS = {
    "openrouter": ["google/gemini-2.0-flash-001", "anthropic/claude-3.5-haiku", "openai/gpt-4o-mini", "deepseek/deepseek-r1", "meta-llama/llama-3.3-70b-instruct"],
    "google": ["gemini-2.0-flash", "gemini-1.5-flash", "gemini-1.5-pro"],
    "openai": ["gpt-4o-mini", "gpt-4o"],
    "anthropic": ["claude-3-5-haiku-20241022", "claude-3-5-sonnet-20241022"],
}

AI_KEY_LINKS = {
    "openrouter": "https://openrouter.ai/keys",
    "google": "https://aistudio.google.com/app/apikey",
    "openai": "https://platform.openai.com/api-keys",
    "anthropic": "https://console.anthropic.com/settings/keys",
}


class SettingsDialog(ctk.CTkToplevel):
    def __init__(self, master, config, translator, on_saved=None, **kwargs):
        super().__init__(master, **kwargs)
        self.config_data = config
        self.t = translator
        self.on_saved = on_saved
        self.restart_required = False

        active_theme_key = config.get("theme", "cyber_dark")
        self.theme = get_theme(active_theme_key)

        self.title("⚙ " + self.t.t("settings.title") + " & Personnalisation")
        self.geometry("680x560")
        self.minsize(620, 500)
        self.transient(master)
        self.configure(fg_color=self.theme["bg"])
        self.grab_set()

        self._build_ui()

    def _build_ui(self):
        t = self.t
        theme = self.theme
        cfg = self.config_data

        # Top Header
        top_header = ctk.CTkFrame(self, fg_color=theme["header"], corner_radius=0, border_width=1, border_color=theme["border"])
        top_header.pack(fill="x")

        h_inner = ctk.CTkFrame(top_header, fg_color="transparent")
        h_inner.pack(fill="x", padx=20, pady=12)

        ctk.CTkLabel(
            h_inner,
            text="⚙ " + t.t("settings.title") + " — Préférences",
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color=theme["text"],
        ).pack(side="left")

        # Main Tabview
        tabs = ctk.CTkTabview(
            self,
            fg_color=theme["card"],
            segmented_button_fg_color=theme["subcard"],
            segmented_button_selected_color=theme["accent"],
            segmented_button_selected_hover_color=theme["accent_hover"],
            segmented_button_unselected_color=theme["card"],
        )
        tabs.pack(fill="both", expand=True, padx=16, pady=(10, 6))

        tab_general = tabs.add(t.t("settings.tab_general"))
        tab_perf = tabs.add(t.t("settings.tab_perf"))
        tab_ai = tabs.add("🤖 " + t.t("settings.tab_ai"))
        tab_vt = tabs.add(t.t("settings.tab_vt"))
        tab_contact = tabs.add(t.t("settings.tab_contact"))

        # --- 1. Tab General ---
        self._build_general_tab(tab_general, t, theme, cfg)

        # --- 2. Tab Performance & RAM ---
        self._build_perf_tab(tab_perf, t, theme, cfg)

        # --- 3. Tab AI Analyst ---
        self._build_ai_tab(tab_ai, t, theme, cfg)

        # --- 4. Tab VirusTotal ---
        self._build_vt_tab(tab_vt, t, theme, cfg)

        # --- 5. Tab Contact & Feedback ---
        self._build_contact_tab(tab_contact, t, theme, cfg)

        # Bottom Buttons
        bottom = ctk.CTkFrame(self, fg_color="transparent")
        bottom.pack(side="bottom", fill="x", padx=20, pady=12)

        self.restart_note = ctk.CTkLabel(bottom, text="", font=ctk.CTkFont(size=11), text_color="#e3b341")
        self.restart_note.pack(side="left")

        ctk.CTkButton(
            bottom,
            text=t.t("settings.cancel"),
            width=100,
            fg_color="#21262d",
            hover_color="#30363d",
            text_color=theme["text"],
            command=self.destroy,
        ).pack(side="right", padx=(8, 0))

        ctk.CTkButton(
            bottom,
            text="💾 " + t.t("settings.save"),
            width=120,
            fg_color=theme["accent"],
            hover_color=theme["accent_hover"],
            command=self._save,
        ).pack(side="right")

    def _build_general_tab(self, parent, t, theme, cfg):
        frame = ctk.CTkScrollableFrame(parent, fg_color=theme["card"])
        frame.pack(fill="both", expand=True, padx=4, pady=4)

        # Language
        ctk.CTkLabel(frame, text=t.t("settings.language"), font=ctk.CTkFont(size=13, weight="bold"), text_color=theme["text"]).pack(anchor="w", padx=10, pady=(10, 4))
        self.lang_menu = ctk.CTkOptionMenu(
            frame,
            values=available_languages() or ["fr", "en"],
            fg_color=theme["subcard"],
            button_color=theme["accent"],
            button_hover_color=theme["accent_hover"],
            command=self._on_change_trigger_restart,
        )
        self.lang_menu.set(cfg.get("language", "fr"))
        self.lang_menu.pack(fill="x", padx=10, pady=(0, 14))

        # Visual Theme
        ctk.CTkLabel(frame, text=t.t("settings.theme_label"), font=ctk.CTkFont(size=13, weight="bold"), text_color=theme["text"]).pack(anchor="w", padx=10, pady=(6, 4))
        theme_names = [THEMES[k]["name"] for k in available_themes()]
        self.theme_map = {THEMES[k]["name"]: k for k in available_themes()}
        self.theme_rev_map = {k: THEMES[k]["name"] for k in available_themes()}

        current_theme_name = self.theme_rev_map.get(cfg.get("theme", "cyber_dark"), theme_names[0])
        self.theme_menu = ctk.CTkOptionMenu(
            frame,
            values=theme_names,
            fg_color=theme["subcard"],
            button_color=theme["accent"],
            button_hover_color=theme["accent_hover"],
            command=self._on_change_trigger_restart,
        )
        self.theme_menu.set(current_theme_name)
        self.theme_menu.pack(fill="x", padx=10, pady=(0, 14))

        # Sound Alert
        self.sound_switch_var = ctk.BooleanVar(value=bool(cfg.get("sound_alert", False)))
        ctk.CTkSwitch(
            frame,
            text=t.t("settings.sound_alert"),
            font=ctk.CTkFont(size=13),
            progress_color=theme["accent"],
            variable=self.sound_switch_var,
        ).pack(anchor="w", padx=10, pady=10)

    def _build_perf_tab(self, parent, t, theme, cfg):
        frame = ctk.CTkScrollableFrame(parent, fg_color=theme["card"])
        frame.pack(fill="both", expand=True, padx=4, pady=4)

        perf = cfg.get("performance", {})

        # RAM profile
        ctk.CTkLabel(frame, text=t.t("settings.perf_profile"), font=ctk.CTkFont(size=13, weight="bold"), text_color=theme["text"]).pack(anchor="w", padx=10, pady=(10, 4))
        profile_options = [
            t.t("settings.profile_balanced"),
            t.t("settings.profile_low_ram"),
            t.t("settings.profile_max_speed"),
        ]
        self.profile_keys = ["balanced", "low_ram", "max_speed"]
        self.profile_menu = ctk.CTkOptionMenu(
            frame,
            values=profile_options,
            fg_color=theme["subcard"],
            button_color=theme["accent"],
            button_hover_color=theme["accent_hover"],
            command=self._on_profile_change,
        )
        cur_prof = perf.get("profile", "balanced")
        idx = self.profile_keys.index(cur_prof) if cur_prof in self.profile_keys else 0
        self.profile_menu.set(profile_options[idx])
        self.profile_menu.pack(fill="x", padx=10, pady=(0, 14))

        # Max file size MB
        ctk.CTkLabel(frame, text=t.t("settings.max_file_size"), font=ctk.CTkFont(size=13, weight="bold"), text_color=theme["text"]).pack(anchor="w", padx=10, pady=(4, 4))
        size_options = ["50 Mo", "100 Mo", "200 Mo", "500 Mo", "1000 Mo"]
        self.size_values = [50, 100, 200, 500, 1000]
        self.size_menu = ctk.CTkOptionMenu(
            frame,
            values=size_options,
            fg_color=theme["subcard"],
            button_color=theme["accent"],
            button_hover_color=theme["accent_hover"],
        )
        cur_size = perf.get("max_file_size_mb", 200)
        s_idx = self.size_values.index(cur_size) if cur_size in self.size_values else 2
        self.size_menu.set(size_options[s_idx])
        self.size_menu.pack(fill="x", padx=10, pady=(0, 14))

        # Entropy Block Size
        ctk.CTkLabel(frame, text=t.t("settings.entropy_block_size"), font=ctk.CTkFont(size=13, weight="bold"), text_color=theme["text"]).pack(anchor="w", padx=10, pady=(4, 4))
        block_options = ["8 Ko (Ultra précis)", "16 Ko (Recommandé)", "32 Ko (Rapide)", "64 Ko (Très grand)"]
        self.block_values = [8, 16, 32, 64]
        self.block_menu = ctk.CTkOptionMenu(
            frame,
            values=block_options,
            fg_color=theme["subcard"],
            button_color=theme["accent"],
            button_hover_color=theme["accent_hover"],
        )
        cur_b = perf.get("entropy_block_size_kb", 16)
        b_idx = self.block_values.index(cur_b) if cur_b in self.block_values else 1
        self.block_menu.set(block_options[b_idx])
        self.block_menu.pack(fill="x", padx=10, pady=(0, 14))

        # Toggles
        self.yara_var = ctk.BooleanVar(value=bool(perf.get("enable_yara", True)))
        ctk.CTkSwitch(frame, text=t.t("settings.enable_yara"), font=ctk.CTkFont(size=13), progress_color=theme["accent"], variable=self.yara_var).pack(anchor="w", padx=10, pady=6)

        self.strings_var = ctk.BooleanVar(value=bool(perf.get("enable_strings_scan", True)))
        ctk.CTkSwitch(frame, text=t.t("settings.enable_strings"), font=ctk.CTkFont(size=13), progress_color=theme["accent"], variable=self.strings_var).pack(anchor="w", padx=10, pady=6)

    def _on_profile_change(self, choice):
        t = self.t
        profile_options = [
            t.t("settings.profile_balanced"),
            t.t("settings.profile_low_ram"),
            t.t("settings.profile_max_speed"),
        ]
        idx = profile_options.index(choice) if choice in profile_options else 0
        key = self.profile_keys[idx]
        pdata = RAM_PROFILES.get(key, RAM_PROFILES["balanced"])
        
        s_idx = self.size_values.index(pdata["max_mb"]) if pdata["max_mb"] in self.size_values else 2
        self.size_menu.set(["50 Mo", "100 Mo", "200 Mo", "500 Mo", "1000 Mo"][s_idx])
        
        b_idx = self.block_values.index(pdata["block_kb"]) if pdata["block_kb"] in self.block_values else 1
        self.block_menu.set(["8 Ko (Ultra précis)", "16 Ko (Recommandé)", "32 Ko (Rapide)", "64 Ko (Très grand)"][b_idx])
        
        self.yara_var.set(pdata["yara"])
        self.strings_var.set(pdata["strings"])

    def _build_ai_tab(self, parent, t, theme, cfg):
        frame = ctk.CTkScrollableFrame(parent, fg_color=theme["card"])
        frame.pack(fill="both", expand=True, padx=4, pady=4)

        ai_cfg = cfg.get("ai_analyst", {})
        self.ai_enable_var = ctk.BooleanVar(value=bool(ai_cfg.get("enabled", False)))

        # Header card
        header_card = ctk.CTkFrame(frame, fg_color=theme["subcard"], corner_radius=6, border_width=1, border_color=theme["border"])
        header_card.pack(fill="x", padx=10, pady=(10, 10))

        h_inner = ctk.CTkFrame(header_card, fg_color="transparent")
        h_inner.pack(fill="x", padx=12, pady=10)

        ctk.CTkSwitch(
            h_inner,
            text=t.t("settings.ai_enable"),
            font=ctk.CTkFont(size=14, weight="bold"),
            progress_color=theme["accent"],
            variable=self.ai_enable_var,
        ).pack(anchor="w")

        ctk.CTkLabel(
            h_inner,
            text=t.t("settings.ai_desc"),
            font=ctk.CTkFont(size=11),
            text_color="#58a6ff",
            wraplength=520,
            justify="left",
        ).pack(anchor="w", pady=(4, 0))

        # Provider Selector
        ctk.CTkLabel(frame, text=t.t("settings.ai_provider") + " :", font=ctk.CTkFont(size=13, weight="bold"), text_color=theme["text"]).pack(anchor="w", padx=10, pady=(8, 4))
        
        self.provider_labels = [label for _, label in AI_PROVIDERS]
        self.provider_keys = [key for key, _ in AI_PROVIDERS]
        self.provider_menu = ctk.CTkOptionMenu(
            frame,
            values=self.provider_labels,
            fg_color=theme["subcard"],
            button_color=theme["accent"],
            button_hover_color=theme["accent_hover"],
            command=self._on_ai_provider_change,
        )
        cur_p = ai_cfg.get("provider", "openrouter")
        p_idx = self.provider_keys.index(cur_p) if cur_p in self.provider_keys else 0
        self.provider_menu.set(self.provider_labels[p_idx])
        self.provider_menu.pack(fill="x", padx=10, pady=(0, 10))

        # Model input / dropdown
        ctk.CTkLabel(frame, text=t.t("settings.ai_model") + " :", font=ctk.CTkFont(size=13, weight="bold"), text_color=theme["text"]).pack(anchor="w", padx=10, pady=(4, 4))
        self.ai_model_menu = ctk.CTkComboBox(
            frame,
            values=AI_MODEL_SUGGESTIONS.get(cur_p, ["google/gemini-2.0-flash-001"]),
            fg_color=theme["subcard"],
            border_color=theme["border"],
        )
        cur_model = ai_cfg.get("model", "") or AI_MODEL_SUGGESTIONS.get(cur_p, ["google/gemini-2.0-flash-001"])[0]
        self.ai_model_menu.set(cur_model)
        self.ai_model_menu.pack(fill="x", padx=10, pady=(0, 10))

        # API Key
        ctk.CTkLabel(frame, text=t.t("settings.ai_api_key") + " :", font=ctk.CTkFont(size=13, weight="bold"), text_color=theme["text"]).pack(anchor="w", padx=10, pady=(4, 4))
        self.ai_key_entry = ctk.CTkEntry(frame, show="•", fg_color=theme["subcard"], border_color=theme["border"])
        self.ai_key_entry.insert(0, ai_cfg.get("api_key", ""))
        self.ai_key_entry.pack(fill="x", padx=10, pady=(0, 8))

        # Get API key button
        self.ai_link_btn = ctk.CTkButton(
            frame,
            text="🔑 " + t.t("settings.ai_get_key"),
            font=ctk.CTkFont(size=12),
            fg_color="#21262d",
            hover_color="#30363d",
            text_color=theme["text"],
            command=self._open_ai_key_link,
        )
        self.ai_link_btn.pack(anchor="w", padx=10, pady=(4, 10))

        # Auto analyze toggle
        self.ai_auto_var = ctk.BooleanVar(value=bool(ai_cfg.get("auto_analyze", False)))
        ctk.CTkSwitch(
            frame,
            text=t.t("settings.ai_auto_analyze"),
            font=ctk.CTkFont(size=13),
            progress_color=theme["accent"],
            variable=self.ai_auto_var,
        ).pack(anchor="w", padx=10, pady=(6, 12))

        # Privacy notice
        p_card = ctk.CTkFrame(frame, fg_color=theme["subcard"], corner_radius=6, border_width=1, border_color="#1f6feb")
        p_card.pack(fill="x", padx=10, pady=(4, 10))
        ctk.CTkLabel(
            p_card,
            text="🔒 " + t.t("settings.ai_privacy_note"),
            font=ctk.CTkFont(size=11),
            text_color="#58a6ff",
            wraplength=520,
            justify="left",
        ).pack(padx=12, pady=10, anchor="w")

    def _on_ai_provider_change(self, choice):
        idx = self.provider_labels.index(choice) if choice in self.provider_labels else 0
        key = self.provider_keys[idx]
        suggestions = AI_MODEL_SUGGESTIONS.get(key, [])
        self.ai_model_menu.configure(values=suggestions)
        if suggestions:
            self.ai_model_menu.set(suggestions[0])

    def _open_ai_key_link(self):
        choice = self.provider_menu.get()
        idx = self.provider_labels.index(choice) if choice in self.provider_labels else 0
        key = self.provider_keys[idx]
        link = AI_KEY_LINKS.get(key, "https://openrouter.ai/keys")
        webbrowser.open(link)

    def _build_vt_tab(self, parent, t, theme, cfg):
        frame = ctk.CTkScrollableFrame(parent, fg_color=theme["card"])
        frame.pack(fill="both", expand=True, padx=4, pady=4)

        # Status & Toggle
        vt_cfg = cfg.get("virustotal", {})
        self.vt_switch_var = ctk.BooleanVar(value=bool(vt_cfg.get("enabled")))

        vt_header = ctk.CTkFrame(frame, fg_color=theme["subcard"], corner_radius=6, border_width=1, border_color=theme["border"])
        vt_header.pack(fill="x", padx=10, pady=(10, 10))

        v_inner = ctk.CTkFrame(vt_header, fg_color="transparent")
        v_inner.pack(fill="x", padx=12, pady=10)

        ctk.CTkSwitch(
            v_inner,
            text=t.t("settings.vt_enable_labeled"),
            font=ctk.CTkFont(size=14, weight="bold"),
            progress_color=theme["accent"],
            variable=self.vt_switch_var,
        ).pack(anchor="w")

        ctk.CTkLabel(
            v_inner,
            text=t.t("settings.vt_badge_info"),
            font=ctk.CTkFont(size=11),
            text_color="#58a6ff",
            wraplength=520,
            justify="left",
        ).pack(anchor="w", pady=(4, 0))

        # API Key
        ctk.CTkLabel(frame, text=t.t("settings.vt_key") + " :", font=ctk.CTkFont(size=13, weight="bold"), text_color=theme["text"]).pack(anchor="w", padx=10, pady=(8, 4))
        self.key_entry = ctk.CTkEntry(frame, show="•", fg_color=theme["subcard"], border_color=theme["border"])
        key = vt_cfg.get("api_key", "")
        self.key_entry.insert(0, key)
        self.key_entry.pack(fill="x", padx=10, pady=(0, 8))

        # Join link button
        ctk.CTkButton(
            frame,
            text="🌐 " + t.t("settings.vt_get_free_key"),
            font=ctk.CTkFont(size=12),
            fg_color="#21262d",
            hover_color="#30363d",
            text_color=theme["text"],
            command=lambda: webbrowser.open("https://www.virustotal.com/gui/join-us"),
        ).pack(anchor="w", padx=10, pady=(4, 10))

        # Privacy assurance note
        p_card = ctk.CTkFrame(frame, fg_color=theme["subcard"], corner_radius=6, border_width=1, border_color="#1f6feb")
        p_card.pack(fill="x", padx=10, pady=10)
        ctk.CTkLabel(
            p_card,
            text="🔒 " + t.t("settings.hint"),
            font=ctk.CTkFont(size=11),
            text_color="#58a6ff",
            wraplength=520,
            justify="left",
        ).pack(padx=12, pady=10, anchor="w")

    def _build_contact_tab(self, parent, t, theme, cfg):
        frame = ctk.CTkScrollableFrame(parent, fg_color=theme["card"])
        frame.pack(fill="both", expand=True, padx=4, pady=4)

        # Developer card
        c_card = ctk.CTkFrame(frame, fg_color=theme["subcard"], corner_radius=8, border_width=1, border_color=theme["border"])
        c_card.pack(fill="x", padx=10, pady=(10, 10))

        c_inner = ctk.CTkFrame(c_card, fg_color="transparent")
        c_inner.pack(fill="x", padx=14, pady=12)

        ctk.CTkLabel(c_inner, text="📬 " + t.t("settings.contact_title"), font=ctk.CTkFont(size=15, weight="bold"), text_color=theme["text"]).pack(anchor="w")
        ctk.CTkLabel(
            c_inner,
            text=t.t("settings.contact_desc"),
            font=ctk.CTkFont(size=12),
            text_color=theme["subtext"],
            wraplength=520,
            justify="left",
        ).pack(anchor="w", pady=(4, 10))

        # Email Box
        email_str = cfg.get("contact", {}).get("developer_email", "maelmeriguet4@proton.me")
        e_box = ctk.CTkFrame(c_inner, fg_color="#0d1117", corner_radius=6, border_width=1, border_color=theme["border"])
        e_box.pack(fill="x", pady=(0, 10))

        e_row = ctk.CTkFrame(e_box, fg_color="transparent")
        e_row.pack(fill="x", padx=10, pady=8)

        ctk.CTkLabel(e_row, text=f"✉️ {email_str}", font=ctk.CTkFont(family="Consolas", size=13, weight="bold"), text_color="#58a6ff").pack(side="left")

        c_btn = ctk.CTkButton(
            e_row,
            text=t.t("misc.copy"),
            width=70,
            height=26,
            font=ctk.CTkFont(size=11),
            fg_color="#21262d",
            hover_color="#30363d",
        )
        c_btn.configure(command=lambda v=email_str, b=c_btn: self._copy_email(v, b, t))
        c_btn.pack(side="right")

        # Send mail button
        ctk.CTkButton(
            c_inner,
            text="📧 " + t.t("settings.contact_send_mail"),
            height=34,
            font=ctk.CTkFont(size=12, weight="bold"),
            fg_color=theme["accent"],
            hover_color=theme["accent_hover"],
            command=lambda: webbrowser.open(f"mailto:{email_str}?subject=[MalyxScanner]%20Feedback%20/%20Rapport%20de%20Bug"),
        ).pack(fill="x", pady=(2, 6))

        # License & Project info
        info_text = f"🛡️ MalyxScanner v2.0 — {t.t('settings.vibe_desc')}\nCréé avec passion pour protéger les ordinateurs et sensibiliser aux cybermenaces."
        ctk.CTkLabel(
            info_card,
            text=info_text,
            font=ctk.CTkFont(size=11),
            text_color=theme["subtext"],
            wraplength=520,
            justify="left",
        ).pack(padx=12, pady=10, anchor="w")

    def _copy_email(self, val, btn, t):
        try:
            self.clipboard_clear()
            self.clipboard_append(val)
            self.update()
            orig = btn.cget("text")
            btn.configure(text=t.t("misc.copied"), fg_color="#238636")
            self.after(1400, lambda: btn.configure(text=orig, fg_color="#21262d"))
        except Exception:
            pass

    def _on_change_trigger_restart(self, choice=None):
        self.restart_required = True
        self.restart_note.configure(text=self.t.t("app.language_changed"))

    def _save(self):
        t = self.t
        # Language
        self.config_data["language"] = self.lang_menu.get()

        # Theme
        theme_selected_name = self.theme_menu.get()
        self.config_data["theme"] = self.theme_map.get(theme_selected_name, "cyber_dark")

        # Sound
        self.config_data["sound_alert"] = bool(self.sound_switch_var.get())

        # Performance
        perf = self.config_data.setdefault("performance", {})
        
        prof_options = [
            t.t("settings.profile_balanced"),
            t.t("settings.profile_low_ram"),
            t.t("settings.profile_max_speed"),
        ]
        p_idx = prof_options.index(self.profile_menu.get()) if self.profile_menu.get() in prof_options else 0
        perf["profile"] = self.profile_keys[p_idx]

        s_idx = ["50 Mo", "100 Mo", "200 Mo", "500 Mo", "1000 Mo"].index(self.size_menu.get()) if self.size_menu.get() in ["50 Mo", "100 Mo", "200 Mo", "500 Mo", "1000 Mo"] else 2
        perf["max_file_size_mb"] = self.size_values[s_idx]

        b_idx = ["8 Ko (Ultra précis)", "16 Ko (Recommandé)", "32 Ko (Rapide)", "64 Ko (Très grand)"].index(self.block_menu.get()) if self.block_menu.get() in ["8 Ko (Ultra précis)", "16 Ko (Recommandé)", "32 Ko (Rapide)", "64 Ko (Très grand)"] else 1
        perf["entropy_block_size_kb"] = self.block_values[b_idx]

        perf["enable_yara"] = bool(self.yara_var.get())
        perf["enable_strings_scan"] = bool(self.strings_var.get())

        # AI Analyst
        ai_cfg = self.config_data.setdefault("ai_analyst", {})
        ai_cfg["enabled"] = bool(self.ai_enable_var.get())
        idx_p = self.provider_labels.index(self.provider_menu.get()) if self.provider_menu.get() in self.provider_labels else 0
        ai_cfg["provider"] = self.provider_keys[idx_p]
        ai_cfg["model"] = self.ai_model_menu.get().strip()
        ai_cfg["api_key"] = self.ai_key_entry.get().strip()
        ai_cfg["auto_analyze"] = bool(self.ai_auto_var.get())

        # VirusTotal
        vt = self.config_data.setdefault("virustotal", {})
        vt["enabled"] = bool(self.vt_switch_var.get())
        vt["api_key"] = self.key_entry.get().strip()

        if self.on_saved:
            self.on_saved(self.config_data)
        self.destroy()
