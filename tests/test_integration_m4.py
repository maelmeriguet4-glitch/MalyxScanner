"""
MalyxScanner - Milestone 4: Integration & Orchestration Unit & Integration Tests
Tests SentinelWatcher lifecycle management in MalyxApp, thread-safe dispatch,
single-active toast policy, foreground window focus restoration, and dynamic reconfiguration.
"""

import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

SRC_DIR = Path(__file__).resolve().parents[1] / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from gui.app import MalyxApp


class TestMilestone4Integration(unittest.TestCase):
    def setUp(self):
        self.mock_root = MagicMock()
        self.mock_translator = MagicMock()
        self.mock_translator.t.side_effect = lambda key, **kwargs: key
        self.saved_configs = []
        self.mock_config_saver = lambda cfg: self.saved_configs.append(dict(cfg))

        self.default_config = {
            "language": "fr",
            "theme": "cyber_dark",
            "sound_alert": False,
            "performance": {"max_file_size_mb": 128},
            "sentinel": {
                "enabled": True,
                "watch_dir": "",
                "ram_limit_mb": 128,
                "stream_chunk_kb": 64,
                "toast_alert": True,
                "auto_dismiss_sec": 10,
            },
        }

    def _create_app(self, config=None):
        cfg = config or self.default_config
        with patch.object(MalyxApp, "_build_header"), \
             patch.object(MalyxApp, "_build_dropzone"), \
             patch.object(MalyxApp, "_build_status"), \
             patch.object(MalyxApp, "_show_waiting"), \
             patch.object(MalyxApp, "_build_footer"), \
             patch.object(MalyxApp, "_try_bind_dnd"), \
             patch("customtkinter.CTkFrame"):
            app = MalyxApp(
                root=self.mock_root,
                translator=self.mock_translator,
                config=cfg,
                config_saver=self.mock_config_saver,
            )
        return app

    @patch("gui.app.SentinelWatcher")
    def test_app_sentinel_initialization_enabled(self, MockWatcher):
        mock_watcher_instance = MagicMock()
        MockWatcher.return_value = mock_watcher_instance

        app = self._create_app(self.default_config)

        MockWatcher.assert_called_once()
        mock_watcher_instance.start.assert_called_once()
        self.assertEqual(app.sentinel_watcher, mock_watcher_instance)

    @patch("gui.app.SentinelWatcher")
    def test_app_sentinel_initialization_disabled(self, MockWatcher):
        cfg = dict(self.default_config)
        cfg["sentinel"] = dict(self.default_config["sentinel"])
        cfg["sentinel"]["enabled"] = False

        app = self._create_app(cfg)

        MockWatcher.assert_not_called()
        self.assertIsNone(app.sentinel_watcher)

    @patch("gui.app.SentinelWatcher")
    def test_thread_safe_threat_dispatch(self, MockWatcher):
        app = self._create_app(self.default_config)

        file_path = Path("C:/Downloads/malware.exe")
        result = {"risk": {"score": 80, "verdict": "malicious"}}

        app._on_sentinel_threat_detected(file_path, result)

        self.mock_root.after.assert_called()
        args, _ = self.mock_root.after.call_args
        self.assertEqual(args[0], 0)
        self.assertTrue(callable(args[1]))

    @patch("gui.app.SentinelToast")
    @patch("gui.app.SentinelWatcher")
    def test_toast_presentation_and_single_active(self, MockWatcher, MockToast):
        mock_toast_1 = MagicMock()
        mock_toast_2 = MagicMock()
        MockToast.side_effect = [mock_toast_1, mock_toast_2]

        app = self._create_app(self.default_config)

        path_1 = Path("C:/Downloads/threat1.exe")
        res_1 = {"risk": {"score": 50, "verdict": "malicious"}}
        app._show_sentinel_toast(path_1, res_1)

        self.assertEqual(app._active_toast, mock_toast_1)
        mock_toast_1.show.assert_called_once()

        path_2 = Path("C:/Downloads/threat2.exe")
        res_2 = {"risk": {"score": 90, "verdict": "malicious"}}
        app._show_sentinel_toast(path_2, res_2)

        mock_toast_1.dismiss.assert_called_once()
        self.assertEqual(app._active_toast, mock_toast_2)
        mock_toast_2.show.assert_called_once()

    @patch("gui.app.SentinelToast")
    @patch("gui.app.SentinelWatcher")
    def test_toast_alert_disabled_in_config(self, MockWatcher, MockToast):
        cfg = dict(self.default_config)
        cfg["sentinel"] = dict(self.default_config["sentinel"])
        cfg["sentinel"]["toast_alert"] = False

        app = self._create_app(cfg)

        path = Path("C:/Downloads/threat.exe")
        res = {"risk": {"score": 75, "verdict": "malicious"}}
        app._show_sentinel_toast(path, res)

        MockToast.assert_not_called()
        self.assertIsNone(app._active_toast)

    @patch("gui.app.SentinelWatcher")
    def test_open_scanner_restores_window_and_scans(self, MockWatcher):
        app = self._create_app(self.default_config)
        app.start_analysis = MagicMock()
        threat_file = Path("C:/Downloads/trojan.exe")

        app._on_toast_open_scanner(threat_file)

        self.mock_root.deiconify.assert_called_once()
        self.mock_root.state.assert_called_with("normal")
        self.mock_root.lift.assert_called_once()
        self.mock_root.focus_force.assert_called_once()
        self.mock_root.attributes.assert_called_with("-topmost", True)
        self.mock_root.after_idle.assert_called_once()
        app.start_analysis.assert_called_once_with(str(threat_file))

    @patch("gui.app.SentinelWatcher")
    def test_dynamic_reconfiguration_toggle(self, MockWatcher):
        mock_watcher_instance = MagicMock()
        MockWatcher.return_value = mock_watcher_instance
        mock_watcher_instance.is_running.return_value = True

        app = self._create_app(self.default_config)

        # 1. Disable Sentinel via settings
        updated_cfg_disabled = dict(self.default_config)
        updated_cfg_disabled["sentinel"] = dict(self.default_config["sentinel"])
        updated_cfg_disabled["sentinel"]["enabled"] = False

        app._settings_saved(updated_cfg_disabled)
        mock_watcher_instance.stop.assert_called_with(timeout=2.0)

        # 2. Re-enable with new RAM limits
        mock_watcher_instance.is_running.return_value = False
        updated_cfg_enabled = dict(self.default_config)
        updated_cfg_enabled["sentinel"] = dict(self.default_config["sentinel"])
        updated_cfg_enabled["sentinel"]["enabled"] = True
        updated_cfg_enabled["sentinel"]["ram_limit_mb"] = 256

        app._settings_saved(updated_cfg_enabled)
        mock_watcher_instance.update_config.assert_called()
        mock_watcher_instance.start.assert_called()

    @patch("gui.app.SentinelWatcher")
    def test_graceful_on_close_teardown(self, MockWatcher):
        mock_watcher_instance = MagicMock()
        MockWatcher.return_value = mock_watcher_instance

        app = self._create_app(self.default_config)

        mock_toast = MagicMock()
        app._active_toast = mock_toast

        app._on_close()

        mock_toast.dismiss.assert_called_once()
        mock_watcher_instance.stop.assert_called_once_with(timeout=2.0)
        self.mock_root.destroy.assert_called_once()
        self.assertIsNone(app.sentinel_watcher)
        self.assertIsNone(app._active_toast)


if __name__ == "__main__":
    unittest.main()
