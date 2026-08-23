import queue
import threading
from tkinter import filedialog, messagebox

import customtkinter as ctk

from core.analyzer import analyze_file
from .result_view import ResultView
from .settings_dialog import SettingsDialog
from .theme_manager import get_theme


class MalyxApp:
    def __init__(self, root, translator, config, config_saver):
        self.root = root
        self.t = translator
        self.config = config
        self.save_config = config_saver
        self.result = None
        self.queue = queue.Queue()
        self.analyzing = False

        self.theme = get_theme(config.get("theme", "cyber_dark"))
        ctk.set_appearance_mode(self.theme.get("appearance_mode", "Dark"))

        root.title(self.t.t("app.title") + " — Détection locale & privée")
        root.geometry("1060x780")
        root.minsize(920, 680)
        root.configure(fg_color=self.theme["bg"])

        self._build_header()
        self._build_dropzone()
        self._build_status()
        self.content = ctk.CTkFrame(root, fg_color=self.theme["bg"])
        self.content.pack(fill="both", expand=True, padx=4, pady=4)
        self._show_waiting()
        self._build_footer()
        self._try_bind_dnd()

        root.after(100, self._poll_queue)

    def _build_header(self):
        theme = self.theme
        header = ctk.CTkFrame(self.root, fg_color=theme["header"], corner_radius=0, border_width=1, border_color=theme["border"])
        header.pack(fill="x")

        title_box = ctk.CTkFrame(header, fg_color="transparent")
        title_box.pack(side="left", padx=20, pady=12)

        ctk.CTkLabel(
            title_box,
            text="🛡️ " + self.t.t("app.title"),
            font=ctk.CTkFont(size=22, weight="bold"),
            text_color=theme["text"],
        ).pack(anchor="w")

        ctk.CTkLabel(title_box, text=self.t.t("app.subtitle"), font=ctk.CTkFont(size=12), text_color=theme["subtext"]).pack(anchor="w")

        settings_btn = ctk.CTkButton(
            header,
            text="⚙ " + self.t.t("app.settings"),
            width=120,
            height=32,
            font=ctk.CTkFont(size=12),
            fg_color="#21262d",
            hover_color="#30363d",
            text_color=theme["text"],
            command=self.open_settings,
        )
        settings_btn.pack(side="right", padx=20)

    def _build_dropzone(self):
        theme = self.theme
        self.dropzone = ctk.CTkFrame(
            self.root,
            height=110,
            corner_radius=10,
            border_width=1,
            border_color=theme["accent"],
            fg_color=theme["card"],
        )
        self.dropzone.pack(fill="x", padx=16, pady=(12, 6))

        inner = ctk.CTkFrame(self.dropzone, fg_color="transparent")
        inner.place(relx=0.5, rely=0.5, anchor="center")

        ctk.CTkLabel(
            inner,
            text=self.t.t("app.drop_title"),
            font=ctk.CTkFont(size=15, weight="bold"),
            text_color=theme["text"],
        ).pack(side="left", padx=12)

        ctk.CTkLabel(inner, text=self.t.t("app.drop_or"), font=ctk.CTkFont(size=13), text_color=theme["subtext"]).pack(side="left", padx=8)

        ctk.CTkButton(
            inner,
            text="📁 " + self.t.t("app.browse"),
            width=140,
            height=32,
            font=ctk.CTkFont(size=13, weight="bold"),
            fg_color=theme["accent"],
            hover_color=theme["accent_hover"],
            command=self.pick_file,
        ).pack(side="left", padx=12)

    def _build_status(self):
        theme = self.theme
        status_bar = ctk.CTkFrame(self.root, fg_color="transparent")
        status_bar.pack(fill="x", padx=18, pady=(2, 2))

        self.status_label = ctk.CTkLabel(status_bar, text="", font=ctk.CTkFont(size=12), anchor="w", text_color=theme["subtext"])
        self.status_label.pack(side="left")

        self.progress = ctk.CTkProgressBar(status_bar, width=180, mode="indeterminate", progress_color=theme["accent"], fg_color=theme["subcard"])

    def _build_footer(self):
        theme = self.theme
        footer = ctk.CTkFrame(self.root, fg_color=theme["header"], corner_radius=0, border_width=1, border_color=theme["border"])
        footer.pack(side="bottom", fill="x")

        f_inner = ctk.CTkFrame(footer, fg_color="transparent")
        f_inner.pack(fill="x", padx=16, pady=8)

        self.export_txt_btn = ctk.CTkButton(
            f_inner,
            text=self.t.t("misc.export_txt"),
            font=ctk.CTkFont(size=12),
            state="disabled",
            fg_color="#21262d",
            hover_color="#30363d",
            command=lambda: self.export_report("txt"),
        )
        self.export_txt_btn.pack(side="right", padx=(8, 0))

        self.export_json_btn = ctk.CTkButton(
            f_inner,
            text=self.t.t("misc.export_json"),
            font=ctk.CTkFont(size=12),
            state="disabled",
            fg_color="#21262d",
            hover_color="#30363d",
            command=lambda: self.export_report("json"),
        )
        self.export_json_btn.pack(side="right")

        self.reanalyze_btn = ctk.CTkButton(
            f_inner,
            text="🔄 " + self.t.t("app.reanalyze"),
            font=ctk.CTkFont(size=12, weight="bold"),
            state="disabled",
            fg_color=theme["accent"],
            hover_color=theme["accent_hover"],
            command=self.pick_file,
        )
        self.reanalyze_btn.pack(side="left")

        self.vibe_label = ctk.CTkLabel(
            f_inner,
            text=self.t.t("app.vibe_credit"),
            font=ctk.CTkFont(size=11),
            text_color=theme["subtext"],
        )
        self.vibe_label.pack(side="left", padx=16)

    def _try_bind_dnd(self):
        try:
            import tkinterdnd2

            dnd_files = getattr(tkinterdnd2, "DND_FILES", "DND_Files")
            if not hasattr(self.dropzone, "drop_target_register"):
                return
            self.dropzone.drop_target_register(dnd_files)
            self.dropzone.bind("<<Drop>>", self._on_drop)
        except Exception:
            pass

    def _on_drop(self, event):
        if self.analyzing:
            return
        try:
            paths = self.root.tk.splitlist(event.data)
        except Exception:
            return
        if paths:
            raw_path = paths[0].strip().strip("{}")
            if raw_path:
                self.start_analysis(raw_path)

    def pick_file(self):
        if self.analyzing:
            return
        chosen = filedialog.askopenfilename(title=self.t.t("app.browse"))
        if chosen:
            self.start_analysis(chosen)

    def start_analysis(self, path):
        self.analyzing = True
        self.result = None
        self.reanalyze_btn.configure(state="disabled")
        self.export_txt_btn.configure(state="disabled")
        self.export_json_btn.configure(state="disabled")

        for child in self.content.winfo_children():
            child.destroy()

        filename = path.replace("\\", "/").rsplit("/", 1)[-1]
        self.status_label.configure(text=self.t.t("app.analyzing", filename=filename), text_color="#e3b341")
        self.progress.pack(side="right")
        self.progress.start()

        thread = threading.Thread(target=self._worker, args=(path,), daemon=True)
        thread.start()

    def _worker(self, path):
        vt_cfg = self.config.get("virustotal", {})
        vt_enabled = bool(vt_cfg.get("enabled")) and bool(vt_cfg.get("api_key"))
        perf_cfg = self.config.get("performance", {})
        try:
            result = analyze_file(
                path,
                vt_enabled=vt_enabled,
                vt_api_key=vt_cfg.get("api_key", ""),
                perf_config=perf_cfg,
            )
        except Exception as exc:
            result = {"__fatal__": str(exc)}
        self.queue.put(result)

    def _poll_queue(self):
        try:
            result = self.queue.get_nowait()
        except queue.Empty:
            self.root.after(100, self._poll_queue)
            return

        try:
            self.progress.stop()
            self.progress.pack_forget()

            if "__fatal__" in result:
                self.status_label.configure(text=self.t.t("app.error_status"), text_color="#f85149")
                messagebox.showerror(self.t.t("app.analysis_error_box"), result["__fatal__"])
            else:
                self.result = result
                self._show_result(result)
                if self.config.get("sound_alert"):
                    try:
                        import winsound
                        winsound.MessageBeep(winsound.MB_ICONASTERISK)
                    except Exception:
                        pass
        except Exception as exc:
            self.status_label.configure(text=self.t.t("app.error_status"), text_color="#f85149")
            messagebox.showerror(self.t.t("app.analysis_error_box"), str(exc))
        finally:
            self.analyzing = False
            self.reanalyze_btn.configure(state="normal")
            self.export_txt_btn.configure(state="normal")
            self.export_json_btn.configure(state="normal")
            self.root.after(100, self._poll_queue)

    def _show_waiting(self):
        theme = self.theme
        for child in self.content.winfo_children():
            child.destroy()
        box = ctk.CTkFrame(self.content, fg_color=theme["card"], corner_radius=12, border_width=1, border_color=theme["border"])
        box.place(relx=0.5, rely=0.45, anchor="center")
        ctk.CTkLabel(box, text="🛡️", font=ctk.CTkFont(size=56)).pack(padx=40, pady=(24, 6))
        ctk.CTkLabel(box, text=self.t.t("app.waiting"), font=ctk.CTkFont(size=16, weight="bold"), text_color=theme["text"]).pack(padx=40, pady=(0, 4))
        ctk.CTkLabel(box, text="Déposez un fichier ou cliquez sur Parcourir pour lancer une analyse statique 100% locale", font=ctk.CTkFont(size=12), text_color=theme["subtext"]).pack(padx=40, pady=(0, 24))

    def _show_result(self, result):
        for child in self.content.winfo_children():
            child.destroy()
        view = ResultView(master=self.content, result=result, translator=self.t)
        view.pack(fill="both", expand=True)

        verdict = result["risk"]["verdict"]
        colors = {"clean": "#3fb950", "suspicious": "#e3b341", "malicious": "#f85149"}
        self.status_label.configure(
            text=f"{self.t.t('app.done')} — {result['file']['name']} (Score : {result['risk']['score']}/100)",
            text_color=colors.get(verdict, "#8b949e"),
        )

    def export_report(self, fmt):
        if not self.result:
            return
        default_name = f"malyx_report_{self.result['hashes'].get('sha256', 'unknown')[:12]}.{fmt}"
        filetypes = [(fmt.upper(), f"*.{fmt}")]
        target = filedialog.asksaveasfilename(
            defaultextension=fmt,
            initialfile=default_name,
            filetypes=filetypes,
        )
        if not target:
            return
        try:
            from core.report import render_txt, save_json, save_txt

            if fmt == "json":
                save_json(self.result, target)
            else:
                save_txt(render_txt(self.result, self.t), target)
            self.status_label.configure(text=self.t.t("misc.saved_to", path=target).split("\\n")[0], text_color="#3fb950")
            messagebox.showinfo(self.t.t("app.done"), self.t.t("misc.saved_to", path=target))
        except OSError as exc:
            messagebox.showerror(self.t.t("app.analysis_error_box"), self.t.t("misc.export_failed", error=str(exc)))

    def open_settings(self):
        dialog = SettingsDialog(
            master=self.root,
            config=self.config,
            translator=self.t,
            on_saved=self._settings_saved,
        )

    def _settings_saved(self, updated):
        self.save_config(updated)
        self.config = updated
        self.theme = get_theme(updated.get("theme", "cyber_dark"))
        ctk.set_appearance_mode(self.theme.get("appearance_mode", "Dark"))
