import logging
import queue
import threading
from pathlib import Path
from tkinter import filedialog, messagebox

import customtkinter as ctk

from core.analyzer import analyze_file
from core.sentinel import SentinelWatcher
from core.history import record_scan, get_history
from .result_view import ResultView
from .settings_dialog import SettingsDialog
from .history_panel import HistoryPanel
from .theme_manager import get_theme
from .toast_notification import SentinelToast

# System Tray support (optional — graceful fallback)
try:
    import pystray
    from PIL import Image as PILImage
    _HAS_TRAY = True
except ImportError:
    _HAS_TRAY = False

logger = logging.getLogger("MalyxApp")


class MalyxApp:
    def __init__(self, root, translator, config, config_saver):
        self.root = root
        self.t = translator
        self.config = config
        self.save_config = config_saver
        self.result = None
        self.queue = queue.Queue()
        self.analyzing = False
        self.sentinel_watcher = None
        self._active_toast = None
        self._tray_icon = None
        self._tray_thread = None
        self._minimized_to_tray = False
        self.history_panel = None

        self.theme = get_theme(config.get("theme", "cyber_dark"))
        ctk.set_appearance_mode(self.theme.get("appearance_mode", "Dark"))

        root.title(self.t.t("app.title") + " — Détection locale & privée")
        root.geometry("1280x860")
        root.minsize(1024, 720)
        root.configure(fg_color=self.theme["bg"])
        try:
            root.after(10, lambda: root.state("zoomed"))
        except Exception:
            pass

        root.protocol("WM_DELETE_WINDOW", self._on_close)

        self._build_header()
        self._build_dropzone()
        self._build_status()
        self.content = ctk.CTkFrame(root, fg_color=self.theme["bg"])
        self.content.pack(fill="both", expand=True, padx=4, pady=4)
        self._show_waiting()
        self._build_footer()
        self._try_bind_dnd()

        root.after(100, self._poll_queue)
        self._init_sentinel()


    def _build_header(self):
        theme = self.theme
        header = ctk.CTkFrame(self.root, fg_color=theme["header"], corner_radius=0, border_width=1, border_color=theme["border"])
        header.pack(fill="x")

        title_box = ctk.CTkFrame(header, fg_color="transparent")
        title_box.pack(side="left", padx=20, pady=10)

        ctk.CTkLabel(
            title_box,
            text="🛡️ " + self.t.t("app.title"),
            font=ctk.CTkFont(size=22, weight="bold"),
            text_color=theme["text"],
        ).pack(anchor="w")

        ctk.CTkLabel(title_box, text=self.t.t("app.subtitle"), font=ctk.CTkFont(size=12), text_color=theme["subtext"]).pack(anchor="w")

        # Top Action Toolbar (Quick 1-Click Access Everywhere)
        toolbar = ctk.CTkFrame(header, fg_color="transparent")
        toolbar.pack(side="right", padx=16, pady=10)

        self.hdr_scan_btn = ctk.CTkButton(
            toolbar,
            text="📁 " + self.t.t("app.browse"),
            width=150,
            height=36,
            font=ctk.CTkFont(size=13, weight="bold"),
            fg_color=theme["accent"],
            hover_color=theme["accent_hover"],
            command=self.pick_file,
        )
        self.hdr_scan_btn.pack(side="left", padx=5)

        self.hdr_export_txt_btn = ctk.CTkButton(
            toolbar,
            text="📄 " + self.t.t("misc.export_txt"),
            width=110,
            height=36,
            font=ctk.CTkFont(size=12),
            fg_color="#21262d",
            hover_color="#30363d",
            state="disabled",
            command=lambda: self.export_report("txt"),
        )
        self.hdr_export_txt_btn.pack(side="left", padx=4)

        self.hdr_export_json_btn = ctk.CTkButton(
            toolbar,
            text="💾 " + self.t.t("misc.export_json"),
            width=110,
            height=36,
            font=ctk.CTkFont(size=12),
            fg_color="#21262d",
            hover_color="#30363d",
            state="disabled",
            command=lambda: self.export_report("json"),
        )
        self.hdr_export_json_btn.pack(side="left", padx=4)

        self.hdr_history_btn = ctk.CTkButton(
            toolbar,
            text="📋 Historique",
            width=120,
            height=36,
            font=ctk.CTkFont(size=12, weight="bold"),
            fg_color="#21262d",
            hover_color="#30363d",
            text_color=theme["text"],
            command=self._toggle_history,
        )
        self.hdr_history_btn.pack(side="left", padx=4)

        settings_btn = ctk.CTkButton(
            toolbar,
            text="⚙ " + self.t.t("app.settings"),
            width=120,
            height=36,
            font=ctk.CTkFont(size=12, weight="bold"),
            fg_color="#21262d",
            hover_color="#30363d",
            text_color=theme["text"],
            command=self.open_settings,
        )
        settings_btn.pack(side="left", padx=5)

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
        self.dropzone.pack(fill="x", padx=16, pady=(10, 4))

        inner = ctk.CTkFrame(self.dropzone, fg_color="transparent")
        inner.place(relx=0.5, rely=0.5, anchor="center")

        ctk.CTkLabel(
            inner,
            text="🎯 " + self.t.t("app.drop_title"),
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color=theme["text"],
        ).pack(side="left", padx=12)

        ctk.CTkLabel(inner, text=self.t.t("app.drop_or"), font=ctk.CTkFont(size=13), text_color=theme["subtext"]).pack(side="left", padx=8)

        ctk.CTkButton(
            inner,
            text="📁 " + self.t.t("app.browse"),
            width=160,
            height=36,
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

        self.progress = ctk.CTkProgressBar(status_bar, width=220, mode="indeterminate", progress_color=theme["accent"], fg_color=theme["subcard"])

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
                record_scan(result, source="scan")
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
            self.hdr_export_txt_btn.configure(state="normal")
            self.hdr_export_json_btn.configure(state="normal")
            self.hdr_scan_btn.configure(text="🔄 " + self.t.t("app.browse"))
            self.root.after(100, self._poll_queue)

    def _show_waiting(self):
        theme = self.theme
        for child in self.content.winfo_children():
            child.destroy()
        box = ctk.CTkFrame(self.content, fg_color=theme["card"], corner_radius=14, border_width=1, border_color=theme["border"])
        box.place(relx=0.5, rely=0.45, anchor="center")
        ctk.CTkLabel(box, text="🛡️", font=ctk.CTkFont(size=64)).pack(padx=50, pady=(28, 8))
        ctk.CTkLabel(box, text=self.t.t("app.waiting"), font=ctk.CTkFont(size=18, weight="bold"), text_color=theme["text"]).pack(padx=50, pady=(0, 6))
        ctk.CTkLabel(
            box,
            text="Glissez-déposez un fichier ou cliquez sur le bouton ci-dessous pour analyser.",
            font=ctk.CTkFont(size=13),
            text_color=theme["subtext"],
        ).pack(padx=50, pady=(0, 16))

        ctk.CTkButton(
            box,
            text="📁 " + self.t.t("app.browse"),
            width=200,
            height=40,
            font=ctk.CTkFont(size=14, weight="bold"),
            fg_color=theme["accent"],
            hover_color=theme["accent_hover"],
            command=self.pick_file,
        ).pack(padx=50, pady=(0, 28))

    def _show_result(self, result):
        for child in self.content.winfo_children():
            child.destroy()
        self.current_view = ResultView(master=self.content, result=result, translator=self.t, config=self.config)
        self.current_view.pack(fill="both", expand=True)

        self.hdr_export_txt_btn.configure(state="normal")
        self.hdr_export_json_btn.configure(state="normal")
        self.hdr_scan_btn.configure(text="🔄 Nouveau scan")

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

    def _init_sentinel(self):
        """Initializes and starts the SentinelWatcher daemon if enabled in configuration."""
        sentinel_cfg = self.config.get("sentinel", {})
        if not sentinel_cfg.get("enabled", True):
            return

        watch_dir = sentinel_cfg.get("watch_dir", "")
        ram_limit_mb = sentinel_cfg.get("ram_limit_mb", 128)
        stream_chunk_kb = sentinel_cfg.get("stream_chunk_kb", 64)
        perf_cfg = self.config.get("performance", {})

        try:
            self.sentinel_watcher = SentinelWatcher(
                watch_dir=watch_dir if watch_dir else None,
                on_threat_detected=self._on_sentinel_threat_detected,
                ram_limit_mb=ram_limit_mb,
                stream_chunk_kb=stream_chunk_kb,
                perf_config=perf_cfg,
                enabled=True,
            )
            self.sentinel_watcher.start()
            logger.info("Sentinel watcher started on directory: %s", self.sentinel_watcher.watch_dir)
        except Exception as exc:
            logger.error("Failed to initialize Sentinel watcher: %s", exc, exc_info=True)

    def _on_sentinel_threat_detected(self, file_path: Path, result: dict):
        """
        Thread-safe bridge callback called by SentinelWatcher from background thread.
        Dispatches UI creation safely onto the Tkinter main event loop.
        """
        try:
            self.root.after(0, lambda: self._show_sentinel_toast(file_path, result))
        except Exception as exc:
            logger.error("Failed to dispatch sentinel toast to main thread: %s", exc)

    def _show_sentinel_toast(self, file_path: Path, result: dict):
        """
        Displays the custom borderless Tkinter toast alert at the bottom-left of the screen.
        Guarantees single active toast and respects user alert preferences.
        """
        sentinel_cfg = self.config.get("sentinel", {})
        if not sentinel_cfg.get("toast_alert", True):
            logger.info("Sentinel threat detected for %s, but toast alerts are disabled.", file_path)
            return

        # Dismiss previous active toast to prevent stacking
        if self._active_toast is not None:
            try:
                self._active_toast.dismiss()
            except Exception:
                pass
            self._active_toast = None

        auto_dismiss_sec = sentinel_cfg.get("auto_dismiss_sec", 10)
        auto_dismiss_ms = max(3000, min(60000, int(auto_dismiss_sec * 1000)))

        # Record detection in history
        record_scan(result, source="sentinel")

        try:
            self._active_toast = SentinelToast(
                master=self.root,
                file_path=file_path,
                scan_result=result,
                on_open_scanner=self._on_toast_open_scanner,
                auto_dismiss_ms=auto_dismiss_ms,
            )
            self._active_toast.show()

            # Optional audio cue
            if self.config.get("sound_alert", False):
                try:
                    import winsound
                    winsound.MessageBeep(winsound.MB_ICONEXCLAMATION)
                except Exception:
                    pass
        except Exception as exc:
            logger.error("Failed to display SentinelToast: %s", exc, exc_info=True)

    def _on_toast_open_scanner(self, file_path: Path):
        """
        Action callback triggered when user clicks '🔍 N'hésitez pas à scanner sur MalyxScanner'.
        Restores MalyxScanner to the foreground and starts a detailed deep scan.
        """
        try:
            self.root.deiconify()
            self.root.state("normal")
            self.root.lift()
            self.root.focus_force()
            self.root.attributes("-topmost", True)
            self.root.after_idle(lambda: self.root.attributes("-topmost", False))
        except Exception as exc:
            logger.debug("Non-critical warning restoring window focus: %s", exc)

        # Trigger comprehensive multi-engine analysis in MalyxScanner
        try:
            self.start_analysis(str(file_path))
        except Exception as exc:
            logger.error("Failed to start analysis on threat file %s: %s", file_path, exc, exc_info=True)

    def _reconfigure_sentinel(self, updated_config: dict):
        """Dynamically reconfigures or starts/stops Sentinel watcher when settings are saved."""
        sentinel_cfg = updated_config.get("sentinel", {})
        enabled = sentinel_cfg.get("enabled", True)

        if not enabled:
            if self.sentinel_watcher is not None and self.sentinel_watcher.is_running():
                try:
                    self.sentinel_watcher.stop(timeout=2.0)
                except Exception as exc:
                    logger.warning("Error stopping sentinel watcher: %s", exc)
        else:
            if self.sentinel_watcher is None:
                self._init_sentinel()
            else:
                cfg_copy = dict(sentinel_cfg)
                cfg_copy["perf_config"] = updated_config.get("performance", {})
                try:
                    self.sentinel_watcher.update_config(cfg_copy)
                    if not self.sentinel_watcher.is_running():
                        self.sentinel_watcher.start()
                except Exception as exc:
                    logger.error("Error updating sentinel watcher configuration: %s", exc, exc_info=True)

    def _settings_saved(self, updated):
        self.save_config(updated)
        self.config = updated
        self.theme = get_theme(updated.get("theme", "cyber_dark"))
        ctk.set_appearance_mode(self.theme.get("appearance_mode", "Dark"))
        if hasattr(self, "current_view") and self.current_view and hasattr(self.current_view, "update_config"):
            self.current_view.update_config(updated)
        self._reconfigure_sentinel(updated)

    def _on_close(self):
        """
        If Sentinel is active and pystray is available, minimize to System Tray.
        Otherwise, quit the application entirely.
        """
        sentinel_cfg = self.config.get("sentinel", {})
        sentinel_active = sentinel_cfg.get("enabled", True) and self.sentinel_watcher is not None

        if sentinel_active and _HAS_TRAY:
            self._minimize_to_tray()
        else:
            self._quit_app()

    def _minimize_to_tray(self):
        """Hides the main window and creates a System Tray icon."""
        if self._minimized_to_tray:
            return
        self._minimized_to_tray = True

        try:
            self.root.withdraw()
        except Exception:
            pass

        if self._tray_icon is not None:
            return

        # Create tray icon image
        try:
            icon_candidates = [
                Path(__file__).resolve().parents[1] / "assets" / "icon.ico",
                Path(getattr(__import__("sys"), "_MEIPASS", "")) / "assets" / "icon.ico",
            ]
            icon_img = None
            for c in icon_candidates:
                if c.exists():
                    icon_img = PILImage.open(str(c))
                    break
            if icon_img is None:
                # Fallback: create a simple colored square
                icon_img = PILImage.new("RGB", (64, 64), "#1f6feb")
        except Exception:
            icon_img = PILImage.new("RGB", (64, 64), "#1f6feb")

        menu = pystray.Menu(
            pystray.MenuItem("🛡️ Ouvrir MalyxScanner", self._restore_from_tray, default=True),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("❌ Quitter MalyxScanner", self._quit_from_tray),
        )

        self._tray_icon = pystray.Icon(
            "MalyxScanner",
            icon_img,
            "MalyxScanner — Sentinelle active",
            menu,
        )

        self._tray_thread = threading.Thread(
            target=self._tray_icon.run,
            name="MalyxTrayIcon",
            daemon=True,
        )
        self._tray_thread.start()
        logger.info("MalyxScanner minimized to System Tray. Sentinel continues monitoring.")

    def _restore_from_tray(self, icon=None, item=None):
        """Restores the main window from the System Tray."""
        self._minimized_to_tray = False

        # Stop tray icon
        if self._tray_icon is not None:
            try:
                self._tray_icon.stop()
            except Exception:
                pass
            self._tray_icon = None

        # Restore window on Tkinter main thread
        try:
            self.root.after(0, self._do_restore)
        except Exception:
            pass

    def _do_restore(self):
        """Restores the window (must run on Tkinter main thread)."""
        try:
            self.root.deiconify()
            self.root.state("normal")
            self.root.lift()
            self.root.focus_force()
            self.root.attributes("-topmost", True)
            self.root.after_idle(lambda: self.root.attributes("-topmost", False))
        except Exception as exc:
            logger.debug("Non-critical warning restoring window: %s", exc)

    def _quit_from_tray(self, icon=None, item=None):
        """Quit completely from tray menu."""
        if self._tray_icon is not None:
            try:
                self._tray_icon.stop()
            except Exception:
                pass
            self._tray_icon = None
        try:
            self.root.after(0, self._quit_app)
        except Exception:
            pass

    def _quit_app(self):
        """Gracefully terminates Sentinel watcher, dismisses active toasts, and destroys main window."""
        if self._active_toast is not None:
            try:
                self._active_toast.dismiss()
            except Exception:
                pass
            self._active_toast = None

        if self._tray_icon is not None:
            try:
                self._tray_icon.stop()
            except Exception:
                pass
            self._tray_icon = None

        if self.sentinel_watcher is not None:
            try:
                self.sentinel_watcher.stop(timeout=2.0)
            except Exception as exc:
                logger.warning("Error stopping Sentinel watcher during shutdown: %s", exc)
            self.sentinel_watcher = None

        try:
            self.root.destroy()
        except Exception:
            pass

    def _toggle_history(self):
        """Toggles between the main scan view and the history panel."""
        if self.history_panel is not None and self.history_panel.winfo_exists():
            # Switch back to main view
            self.history_panel.destroy()
            self.history_panel = None
            self.hdr_history_btn.configure(fg_color="#21262d")
            if self.result:
                self._show_result(self.result)
            else:
                self._show_waiting()
            return

        # Show history panel
        for child in self.content.winfo_children():
            child.destroy()

        self.hdr_history_btn.configure(fg_color=self.theme["accent"])

        self.history_panel = HistoryPanel(
            master=self.content,
            theme=self.theme,
            translator=self.t,
            on_rescan=self._rescan_from_history,
        )
        self.history_panel.pack(fill="both", expand=True)

    def _rescan_from_history(self, file_path: str):
        """Re-scans a file from the history panel."""
        if self.analyzing:
            return
        p = Path(file_path)
        if not p.exists():
            messagebox.showwarning("Fichier introuvable", f"Le fichier suivant n'existe plus :\n{file_path}")
            return
        # Switch back to scan view
        if self.history_panel is not None:
            self.history_panel.destroy()
            self.history_panel = None
            self.hdr_history_btn.configure(fg_color="#21262d")
        self.start_analysis(file_path)

