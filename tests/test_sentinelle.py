"""
MalyxScanner - Real-Time Sentinel (Sentinelle en Temps Réel) Test Suite
Comprehensive E2E and Unit Tests for Background Watcher, RAM Streaming, Transient Filtering,
Toast Alerts, and AppConfig Integration.

Test Tiers:
- Tier 1: Feature Coverage (Initialization, Lifecycle, Threat Callback, Passive Scan, Clean File Ignore)
- Tier 2: Boundary & Corner Cases (Transient Files, Baseline Snapshot, 0-byte/Deleted/Empty Dirs, File Lock Backoff, 100MB+ Sparse Chunking)
- Tier 3: Cross-Feature & Concurrency (Rapid 10-File Arrival, Dynamic Stop/Start Reconfiguration)
- Tier 4: Real-World Scenarios (Simulated Browser Download Lifecycle, RAM Footprint/Chunking Verification, AppConfig Schema, Toast Notification Styling/Callbacks)
"""

import hashlib
import json
import os
import shutil
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

# Ensure src directory is in sys.path
SRC_DIR = Path(__file__).resolve().parents[1] / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

# Standard EICAR test string
EICAR = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

# Minimal PE stub (MZ header + PE pointer)
MZ_STUB = b"MZ" + b"\x00" * 58 + b"\x40\x00\x00\x00" + b"\x00" * 4000

# Suspicious Script sample
SUSPICIOUS_SCRIPT = b"""
WScript.Sleep 500
Set objShell = CreateObject("WScript.Shell")
objShell.Run "powershell -WindowStyle Hidden -Enc aQB3AHIA", 0, False
"""

# Transient download extensions
KNOWN_TRANSIENT_EXTS = {".crdownload", ".tmp", ".part", ".download"}


def create_test_file(directory: Path | str, filename: str, content: bytes = b"") -> Path:
    """Helper to write test file synchronously."""
    filepath = Path(directory) / filename
    filepath.parent.mkdir(parents=True, exist_ok=True)
    with open(filepath, "wb") as f:
        f.write(content)
        f.flush()
        os.fsync(f.fileno())
    return filepath


# ============================================================================
# TIER 1: FEATURE COVERAGE
# ============================================================================

class TestTier1FeatureCoverage(unittest.TestCase):
    """
    Tier 1 - Primary Feature Coverage:
    - Sentinel initialization with default vs custom watch directory.
    - Start / Stop daemon lifecycle and is_running() status.
    - Live threat detection callback trigger when a suspect file is created.
    - Passive scanning behavior (file not locked/corrupted, can be accessed by others).
    - Clean file ignoring (risk < 20 does not trigger threat callback).
    """

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="malyx_tier1_")
        self.watch_path = Path(self.temp_dir)
        self.threat_events = []
        self.threat_event_signal = threading.Event()

    def tearDown(self):
        try:
            shutil.rmtree(self.temp_dir, ignore_errors=True)
        except Exception:
            pass

    def _threat_callback(self, file_path, scan_result):
        self.threat_events.append((Path(file_path), scan_result))
        self.threat_event_signal.set()

    def test_01_sentinel_initialization_default_vs_custom(self):
        """Verify Sentinel initialization with default vs custom watch directory and RAM parameters."""
        from core.sentinel import SentinelWatcher

        # 1. Default initialization
        default_watcher = SentinelWatcher()
        expected_default_dir = Path.home() / "Downloads"
        self.assertEqual(
            default_watcher.watch_dir,
            expected_default_dir,
            "Default watch_dir should point to user Downloads folder",
        )
        self.assertFalse(default_watcher.is_running(), "Watcher should not be running upon init")
        self.assertEqual(default_watcher.ram_limit_mb, 128, "Default RAM limit should be 128MB")
        self.assertEqual(default_watcher.stream_chunk_kb, 64, "Default stream chunk should be 64KB")

        # 2. Custom initialization
        custom_watcher = SentinelWatcher(
            watch_dir=self.watch_path,
            on_threat_detected=self._threat_callback,
            ram_limit_mb=256,
            stream_chunk_kb=128,
            poll_interval=0.1,
        )
        self.assertEqual(custom_watcher.watch_dir, self.watch_path)
        self.assertEqual(custom_watcher.ram_limit_mb, 256)
        self.assertEqual(custom_watcher.stream_chunk_kb, 128)
        self.assertEqual(custom_watcher.poll_interval, 0.1)
        self.assertFalse(custom_watcher.is_running())

    def test_02_daemon_lifecycle_start_stop_idempotent(self):
        """Verify Start / Stop daemon lifecycle and is_running() status idempotence."""
        from core.sentinel import SentinelWatcher

        watcher = SentinelWatcher(
            watch_dir=self.watch_path,
            on_threat_detected=self._threat_callback,
            poll_interval=0.05,
        )

        self.assertFalse(watcher.is_running())

        # Start daemon
        watcher.start()
        self.assertTrue(watcher.is_running(), "Watcher should report is_running() == True after start()")

        # Idempotent start
        watcher.start()
        self.assertTrue(watcher.is_running(), "Calling start() again should keep watcher running")

        # Stop daemon
        watcher.stop()
        self.assertFalse(watcher.is_running(), "Watcher should report is_running() == False after stop()")

        # Idempotent stop
        watcher.stop()
        self.assertFalse(watcher.is_running(), "Calling stop() again should be safe and idempotent")

    def test_03_live_threat_detection_callback_trigger_eicar(self):
        """Verify live threat detection callback is triggered when a suspect file (EICAR) is created."""
        from core.sentinel import SentinelWatcher

        watcher = SentinelWatcher(
            watch_dir=self.watch_path,
            on_threat_detected=self._threat_callback,
            poll_interval=0.05,
        )

        watcher.start()
        try:
            # Drop EICAR file
            eicar_file = create_test_file(self.watch_path, "eicar_test.com", EICAR.encode("ascii"))

            # Wait for callback
            triggered = self.threat_event_signal.wait(timeout=3.0)
            self.assertTrue(triggered, "Threat detection callback was not triggered within timeout")
            self.assertGreaterEqual(len(self.threat_events), 1, "At least one threat event must be captured")

            detected_path, scan_result = self.threat_events[0]
            self.assertEqual(detected_path.name, "eicar_test.com")
            self.assertIn("risk", scan_result)
            self.assertGreaterEqual(
                scan_result["risk"].get("score", 0),
                20,
                "EICAR risk score must be >= 20",
            )
            self.assertIn(
                scan_result["risk"].get("verdict"),
                ("suspicious", "malicious"),
                "EICAR verdict should be suspicious or malicious",
            )
        finally:
            watcher.stop()

    def test_04_passive_scanning_non_locking_behavior(self):
        """Verify scanned file is not locked or corrupted and can be opened/read/deleted during/after scan."""
        from core.sentinel import SentinelWatcher, scan_file_streaming

        test_file = create_test_file(self.watch_path, "passive_sample.exe", MZ_STUB + os.urandom(1024))

        # Direct streaming scan
        result = scan_file_streaming(test_file, chunk_kb=64)
        self.assertIsInstance(result, dict)
        self.assertIn("hashes", result)

        # Ensure file can be immediately opened for write and append without PermissionError
        try:
            with open(test_file, "r+b") as f:
                f.seek(0, os.SEEK_END)
                f.write(b"\x00\x00\x00")
                f.flush()
        except PermissionError as e:
            self.fail(f"Passive scan failed: file was locked after scan: {e}")

        # Ensure file can be deleted without PermissionError
        try:
            os.remove(test_file)
        except PermissionError as e:
            self.fail(f"Passive scan failed: file was locked and could not be removed: {e}")

    def test_05_clean_file_ignored(self):
        """Verify clean files (risk < 20) do not trigger the threat callback."""
        from core.sentinel import SentinelWatcher

        watcher = SentinelWatcher(
            watch_dir=self.watch_path,
            on_threat_detected=self._threat_callback,
            poll_interval=0.05,
        )

        watcher.start()
        try:
            # Create benign text file
            clean_file = create_test_file(
                self.watch_path,
                "clean_notes.txt",
                b"This is a benign text file with zero malicious markers or scripts.\n",
            )

            # Wait for poll cycles
            triggered = self.threat_event_signal.wait(timeout=0.4)
            self.assertFalse(triggered, "Clean file should NOT trigger threat callback")
            self.assertEqual(len(self.threat_events), 0, "No threat events should be recorded for clean files")
        finally:
            watcher.stop()


# ============================================================================
# TIER 2: BOUNDARY & CORNER CASES
# ============================================================================

class TestTier2BoundaryAndCornerCases(unittest.TestCase):
    """
    Tier 2 - Boundary & Corner Cases:
    - Incomplete / temporary browser download files (.crdownload, .tmp, .part, .download, ~$*) ignored until renamed.
    - Pre-existing files in Downloads folder before Sentinel startup are not retroactively flagged (baseline snapshot).
    - Zero-byte files, empty directories, and deleted files do not cause crashes.
    - File locked by another process handles PermissionError/WinError 32 gracefully with retry backoff.
    - Very large files (100MB+ sparse) stream in chunks without memory exhaustion.
    """

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="malyx_tier2_")
        self.watch_path = Path(self.temp_dir)
        self.threat_events = []
        self.threat_event_signal = threading.Event()

    def tearDown(self):
        try:
            shutil.rmtree(self.temp_dir, ignore_errors=True)
        except Exception:
            pass

    def _threat_callback(self, file_path, scan_result):
        self.threat_events.append((Path(file_path), scan_result))
        self.threat_event_signal.set()

    def test_06_transient_browser_files_ignored_until_renamed(self):
        """Verify .crdownload, .tmp, .part, .download, and ~$* are ignored until finalized."""
        from core.sentinel import SentinelWatcher

        watcher = SentinelWatcher(
            watch_dir=self.watch_path,
            on_threat_detected=self._threat_callback,
            poll_interval=0.05,
        )

        watcher.start()
        try:
            # Create transient files with malicious payload
            transient_files = [
                create_test_file(self.watch_path, "installer.exe.crdownload", EICAR.encode("ascii")),
                create_test_file(self.watch_path, "update.part", MZ_STUB),
                create_test_file(self.watch_path, "cache.tmp", EICAR.encode("ascii")),
                create_test_file(self.watch_path, "file.download", MZ_STUB),
                create_test_file(self.watch_path, "~$document.docx", b"Office temp lock file"),
            ]

            # Wait to ensure no transient file triggers threat callback
            triggered = self.threat_event_signal.wait(timeout=0.3)
            self.assertFalse(triggered, "Transient download files must be ignored")
            self.assertEqual(len(self.threat_events), 0)

            # Rename .crdownload to finalized .exe
            final_exe = self.watch_path / "installer.exe"
            transient_files[0].rename(final_exe)

            # Now detection should fire for the finalized file
            triggered = self.threat_event_signal.wait(timeout=3.0)
            self.assertTrue(triggered, "Renaming transient file to finalized file must trigger detection")
            self.assertEqual(self.threat_events[0][0].name, "installer.exe")
        finally:
            watcher.stop()

    def test_07_pre_existing_files_baseline_snapshot(self):
        """Verify pre-existing files before startup are not retroactively flagged (baseline snapshot check)."""
        from core.sentinel import SentinelWatcher

        # Create malicious file BEFORE watcher startup
        old_threat = create_test_file(self.watch_path, "pre_existing_malware.exe", MZ_STUB + os.urandom(512))

        watcher = SentinelWatcher(
            watch_dir=self.watch_path,
            on_threat_detected=self._threat_callback,
            poll_interval=0.05,
        )

        # Start watcher: should take snapshot and ignore pre_existing_malware.exe
        watcher.start()
        try:
            time.sleep(0.2)
            self.assertEqual(
                len(self.threat_events),
                0,
                "Pre-existing files must be snapshotted and not retroactively flagged",
            )

            # Now create a NEW threat after startup
            new_threat = create_test_file(self.watch_path, "newly_arrived_malware.exe", MZ_STUB + os.urandom(512))

            triggered = self.threat_event_signal.wait(timeout=3.0)
            self.assertTrue(triggered, "New file created after startup must trigger threat callback")
            self.assertEqual(len(self.threat_events), 1)
            self.assertEqual(self.threat_events[0][0].name, "newly_arrived_malware.exe")
        finally:
            watcher.stop()

    def test_08_zero_byte_empty_dirs_and_vanished_files(self):
        """Verify zero-byte files, empty directories, and deleted files during scan do not cause exceptions or crashes."""
        from core.sentinel import SentinelWatcher

        watcher = SentinelWatcher(
            watch_dir=self.watch_path,
            on_threat_detected=self._threat_callback,
            poll_interval=0.05,
        )

        watcher.start()
        try:
            # 1. Zero-byte file
            create_test_file(self.watch_path, "zero_byte.exe", b"")

            # 2. Empty directory
            empty_subdir = self.watch_path / "empty_folder"
            empty_subdir.mkdir(parents=True, exist_ok=True)

            # 3. Vanished / quickly deleted file
            quick_file = create_test_file(self.watch_path, "vanish.exe", b"short lived")
            try:
                os.remove(quick_file)
            except Exception:
                pass

            # Allow watcher loop to run multiple cycles
            time.sleep(0.2)

            self.assertTrue(watcher.is_running(), "Watcher daemon must remain running through edge-case inputs")
            self.assertEqual(len(self.threat_events), 0)
        finally:
            watcher.stop()

    def test_09_file_locked_active_write_retry_backoff(self):
        """Verify locked files handle PermissionError/WinError 32 gracefully with retry backoff."""
        from core.sentinel import SentinelWatcher

        watcher = SentinelWatcher(
            watch_dir=self.watch_path,
            on_threat_detected=self._threat_callback,
            poll_interval=0.05,
        )

        watcher.start()
        try:
            locked_path = self.watch_path / "locked_threat.exe"
            # Open file with exclusive handle
            f = open(locked_path, "wb")
            f.write(MZ_STUB)
            f.flush()

            # Sleep briefly while file is kept open
            time.sleep(0.15)
            self.assertTrue(watcher.is_running(), "Watcher must not crash when encountering locked file")

            # Release file lock
            f.close()

            # After lock release, watcher should scan and detect
            triggered = self.threat_event_signal.wait(timeout=3.0)
            self.assertTrue(triggered, "After releasing lock, watcher must successfully detect the file")
            self.assertEqual(self.threat_events[0][0].name, "locked_threat.exe")
        finally:
            watcher.stop()

    def test_10_large_file_streaming_chunked_sparse(self):
        """Verify very large files (100MB+ sparse) stream in chunks without memory exhaustion."""
        from core.sentinel import scan_file_streaming

        large_file = self.watch_path / "large_sparse_test.bin"
        file_size_bytes = 100 * 1024 * 1024  # 100 MB

        # Create sparse file
        with open(large_file, "wb") as f:
            f.seek(file_size_bytes - 1)
            f.write(b"\x00")
            f.flush()

        self.assertEqual(os.path.getsize(large_file), file_size_bytes)

        # Scan using chunked streaming
        start_time = time.time()
        result = scan_file_streaming(large_file, chunk_kb=64)
        elapsed = time.time() - start_time

        self.assertIsInstance(result, dict)
        self.assertEqual(result["file"]["size"], file_size_bytes)
        self.assertIn("hashes", result)
        self.assertIn("sha256", result["hashes"])
        self.assertLess(elapsed, 10.0, "Sparse 100MB streaming scan should complete promptly")


# ============================================================================
# TIER 3: CROSS-FEATURE & CONCURRENCY CASES
# ============================================================================

class TestTier3CrossFeatureAndConcurrency(unittest.TestCase):
    """
    Tier 3 - Concurrency and Dynamic Configuration:
    - Rapid multi-file arrival: 10 files dropped simultaneously in watch folder are processed without lost events.
    - Dynamic stop/start re-initialization with changed RAM limits or watch directories.
    """

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="malyx_tier3_")
        self.watch_path = Path(self.temp_dir)
        self.threat_events = []
        self.threat_lock = threading.Lock()
        self.all_threats_signal = threading.Event()
        self.expected_threat_count = 0

    def tearDown(self):
        try:
            shutil.rmtree(self.temp_dir, ignore_errors=True)
        except Exception:
            pass

    def _threat_callback(self, file_path, scan_result):
        with self.threat_lock:
            self.threat_events.append((Path(file_path).name, scan_result))
            if len(self.threat_events) >= self.expected_threat_count:
                self.all_threats_signal.set()

    def test_11_rapid_multi_file_arrival_concurrency(self):
        """Verify 10 files dropped simultaneously are all processed without race conditions or lost events."""
        from core.sentinel import SentinelWatcher

        watcher = SentinelWatcher(
            watch_dir=self.watch_path,
            on_threat_detected=self._threat_callback,
            poll_interval=0.05,
        )

        # 3 threats, 3 clean files, 4 transient files = 10 files total
        self.expected_threat_count = 3

        watcher.start()
        try:
            # Create files in rapid sequence
            create_test_file(self.watch_path, "rapid_threat1.com", EICAR.encode("ascii"))
            create_test_file(self.watch_path, "rapid_clean1.txt", b"Benign text document 1")
            create_test_file(self.watch_path, "rapid_transient1.crdownload", EICAR.encode("ascii"))
            create_test_file(self.watch_path, "rapid_threat2.exe", MZ_STUB + os.urandom(256))
            create_test_file(self.watch_path, "rapid_clean2.log", b"System log info clean")
            create_test_file(self.watch_path, "rapid_transient2.tmp", MZ_STUB)
            create_test_file(self.watch_path, "rapid_threat3.vbs", SUSPICIOUS_SCRIPT)
            create_test_file(self.watch_path, "rapid_clean3.json", b'{"status": "ok"}')
            create_test_file(self.watch_path, "rapid_transient3.part", MZ_STUB)
            create_test_file(self.watch_path, "rapid_transient4.download", EICAR.encode("ascii"))

            # Wait for all 3 threats to be detected
            triggered = self.all_threats_signal.wait(timeout=5.0)
            self.assertTrue(triggered, f"Expected {self.expected_threat_count} threats, got {len(self.threat_events)}")

            detected_names = {name for name, _ in self.threat_events}
            self.assertIn("rapid_threat1.com", detected_names)
            self.assertIn("rapid_threat2.exe", detected_names)
            self.assertIn("rapid_threat3.vbs", detected_names)
            self.assertEqual(len(detected_names), 3, "Only the 3 malicious files should be flagged")
        finally:
            watcher.stop()

    def test_12_dynamic_stop_start_reinitialization(self):
        """Verify dynamic stop/start re-initialization with changed RAM limits or watch directories."""
        from core.sentinel import SentinelWatcher

        dir_a = Path(tempfile.mkdtemp(prefix="malyx_dir_a_"))
        dir_b = Path(tempfile.mkdtemp(prefix="malyx_dir_b_"))

        detected_in_a = []
        detected_in_b = []

        try:
            # 1. Start on Directory A
            watcher = SentinelWatcher(
                watch_dir=dir_a,
                on_threat_detected=lambda p, r: detected_in_a.append(Path(p).name),
                ram_limit_mb=64,
                poll_interval=0.05,
            )
            watcher.start()
            self.assertEqual(watcher.watch_dir, dir_a)
            self.assertEqual(watcher.ram_limit_mb, 64)

            create_test_file(dir_a, "threat_in_a.com", EICAR.encode("ascii"))
            time.sleep(0.3)
            self.assertIn("threat_in_a.com", detected_in_a)

            # Stop watcher
            watcher.stop()
            self.assertFalse(watcher.is_running())

            # 2. Re-initialize / reconfigure with Directory B and 256MB RAM
            watcher_b = SentinelWatcher(
                watch_dir=dir_b,
                on_threat_detected=lambda p, r: detected_in_b.append(Path(p).name),
                ram_limit_mb=256,
                stream_chunk_kb=128,
                poll_interval=0.05,
            )
            watcher_b.start()
            self.assertEqual(watcher_b.watch_dir, dir_b)
            self.assertEqual(watcher_b.ram_limit_mb, 256)
            self.assertEqual(watcher_b.stream_chunk_kb, 128)

            # Drop file in A (should NOT be detected anymore)
            create_test_file(dir_a, "unwatched_threat.com", EICAR.encode("ascii"))
            # Drop file in B (should be detected)
            create_test_file(dir_b, "threat_in_b.com", EICAR.encode("ascii"))

            time.sleep(0.3)
            self.assertNotIn("unwatched_threat.com", detected_in_a)
            self.assertIn("threat_in_b.com", detected_in_b)

            watcher_b.stop()
            self.assertFalse(watcher_b.is_running())
        finally:
            shutil.rmtree(dir_a, ignore_errors=True)
            shutil.rmtree(dir_b, ignore_errors=True)


# ============================================================================
# TIER 4: REAL-WORLD APPLICATION SCENARIOS & GUI INTEGRATION
# ============================================================================

class TestTier4RealWorldScenarios(unittest.TestCase):
    """
    Tier 4 - Real-World Scenarios and Integration:
    - Full simulated browser download lifecycle (.crdownload write chunks -> atomic rename -> threat detection).
    - RAM Chunking & memory footprint verification.
    - AppConfig schema & persistence for Sentinel settings.
    - SentinelToast contract, color coding, and callback triggers.
    """

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="malyx_tier4_")
        self.watch_path = Path(self.temp_dir)
        self.threat_events = []
        self.threat_event_signal = threading.Event()

    def tearDown(self):
        try:
            shutil.rmtree(self.temp_dir, ignore_errors=True)
        except Exception:
            pass

    def _threat_callback(self, file_path, scan_result):
        self.threat_events.append((Path(file_path), scan_result))
        self.threat_event_signal.set()

    def test_13_simulated_browser_download_lifecycle(self):
        """Simulate real browser download: .crdownload creation -> partial writes -> rename -> threat report."""
        from core.sentinel import SentinelWatcher

        watcher = SentinelWatcher(
            watch_dir=self.watch_path,
            on_threat_detected=self._threat_callback,
            poll_interval=0.05,
        )

        watcher.start()
        try:
            part_path = self.watch_path / "setup_malware.exe.crdownload"

            # Stage 1: Browser creates empty 0-byte .crdownload
            with open(part_path, "wb") as f:
                f.write(b"")
                f.flush()
            time.sleep(0.1)
            self.assertEqual(len(self.threat_events), 0, "Stage 1 (empty crdownload) must not trigger alert")

            # Stage 2: Browser writes first chunk
            with open(part_path, "ab") as f:
                f.write(MZ_STUB[:100])
                f.flush()
            time.sleep(0.1)
            self.assertEqual(len(self.threat_events), 0, "Stage 2 (in-progress crdownload) must not trigger alert")

            # Stage 3: Browser writes full payload
            with open(part_path, "ab") as f:
                f.write(MZ_STUB[100:] + EICAR.encode("ascii"))
                f.flush()
            time.sleep(0.1)
            self.assertEqual(len(self.threat_events), 0, "Stage 3 (completed crdownload) must not trigger alert")

            # Stage 4: Browser atomically renames to final .exe
            final_path = self.watch_path / "setup_malware.exe"
            part_path.rename(final_path)

            # Stage 5: Sentinel detects final file and produces complete risk report
            triggered = self.threat_event_signal.wait(timeout=3.0)
            self.assertTrue(triggered, "Stage 5: Renaming to final .exe must trigger threat callback")
            self.assertEqual(len(self.threat_events), 1)

            detected_path, scan_report = self.threat_events[0]
            self.assertEqual(detected_path.name, "setup_malware.exe")
            self.assertIn("hashes", scan_report)
            self.assertIn("sha256", scan_report["hashes"])
            self.assertIn("risk", scan_report)
            self.assertGreaterEqual(scan_report["risk"]["score"], 20)
        finally:
            watcher.stop()

    def test_14_ram_chunking_verification(self):
        """Verify that streaming chunk buffer size is respected during file processing."""
        from core.sentinel import scan_file_streaming

        # Create 256KB test payload
        payload = b"A" * (256 * 1024)
        sample_path = create_test_file(self.watch_path, "chunk_test.bin", payload)

        # Scan with 64KB chunk
        res_64 = scan_file_streaming(sample_path, chunk_kb=64)
        # Scan with 128KB chunk
        res_128 = scan_file_streaming(sample_path, chunk_kb=128)

        # Both chunk sizes must produce identical hash and risk calculations
        self.assertEqual(res_64["hashes"]["sha256"], hashlib.sha256(payload).hexdigest())
        self.assertEqual(res_64["hashes"]["sha256"], res_128["hashes"]["sha256"])
        self.assertEqual(res_64["file"]["size"], len(payload))

    def test_15_app_config_sentinel_schema_and_persistence(self):
        """Verify app_config schema contains sentinel defaults and supports saving/loading."""
        import app_config

        # Check DEFAULTS schema
        self.assertIn("sentinel", app_config.DEFAULTS, "app_config.DEFAULTS must have 'sentinel' key")
        sentinel_defaults = app_config.DEFAULTS["sentinel"]

        self.assertIn("enabled", sentinel_defaults)
        self.assertIn("watch_dir", sentinel_defaults)
        self.assertIn("ram_limit_mb", sentinel_defaults)
        self.assertIn("stream_chunk_kb", sentinel_defaults)
        self.assertIn("toast_alert", sentinel_defaults)
        self.assertIn("auto_dismiss_sec", sentinel_defaults)

        # Test load_config returns full sentinel config
        cfg = app_config.load_config()
        self.assertIn("sentinel", cfg)
        self.assertIsInstance(cfg["sentinel"]["enabled"], bool)
        self.assertIsInstance(cfg["sentinel"]["ram_limit_mb"], int)
        self.assertIsInstance(cfg["sentinel"]["stream_chunk_kb"], int)

    def test_16_toast_notification_contract_and_severity_styling(self):
        """Verify SentinelToast contract, color coding (Orange vs Red/Violet), and open-scanner callback."""
        from gui.toast_notification import SentinelToast

        # Mock master widget
        mock_master = MagicMock()
        mock_callback = MagicMock()

        # 1. Medium severity / Suspicious test (Score 30 -> Orange)
        suspicious_result = {
            "risk": {"score": 30, "verdict": "suspicious"},
            "file": {"name": "suspicious_file.zip", "size": 1024},
        }

        with patch("customtkinter.CTkToplevel.__init__", return_value=None):
            toast_suspicious = SentinelToast(
                master=mock_master,
                file_path=Path("C:/Downloads/suspicious_file.zip"),
                scan_result=suspicious_result,
                on_open_scanner=mock_callback,
                auto_dismiss_ms=5000,
            )
            # Verify severity color attribute or method
            self.assertEqual(toast_suspicious.severity, "suspicious")
            self.assertIn(toast_suspicious.accent_color.lower(), ["#f97316", "#ea580c", "#ff9800", "#d97706", "orange", "#fb923c"])

        # 2. Critical danger test (Score 80 -> Red/Violet)
        danger_result = {
            "risk": {"score": 80, "verdict": "malicious"},
            "file": {"name": "ransomware.exe", "size": 4096},
        }

        with patch("customtkinter.CTkToplevel.__init__", return_value=None):
            toast_danger = SentinelToast(
                master=mock_master,
                file_path=Path("C:/Downloads/ransomware.exe"),
                scan_result=danger_result,
                on_open_scanner=mock_callback,
                auto_dismiss_ms=5000,
            )
            self.assertEqual(toast_danger.severity, "malicious")
            self.assertIn(toast_danger.accent_color.lower(), ["#dc2626", "#ef4444", "#e11d48", "#b91c1c", "red", "#7c3aed", "#9333ea"])


# ============================================================================
# STANDALONE CLI TEST RUNNER & FORMATTED SUMMARY
# ============================================================================

def run_sentinel_tests():
    """Execute all test tiers and print formatted summary."""
    print("=" * 80)
    print(" MALYXSCANNER REAL-TIME SENTINEL (SENTINELLE) TEST SUITE ".center(80, "#"))
    print("=" * 80)

    suite = unittest.TestSuite()
    loader = unittest.TestLoader()

    suite.addTests(loader.loadTestsFromTestCase(TestTier1FeatureCoverage))
    suite.addTests(loader.loadTestsFromTestCase(TestTier2BoundaryAndCornerCases))
    suite.addTests(loader.loadTestsFromTestCase(TestTier3CrossFeatureAndConcurrency))
    suite.addTests(loader.loadTestsFromTestCase(TestTier4RealWorldScenarios))

    start_time = time.time()
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    duration = time.time() - start_time

    total_tests = result.testsRun
    failures = len(result.failures)
    errors = len(result.errors)
    skipped = len(result.skipped)
    passed = total_tests - failures - errors - skipped

    print("\n" + "=" * 80)
    print(" TEST EXECUTION SUMMARY ".center(80, "="))
    print(f" Total Tests Run : {total_tests}")
    print(f" Passed         : {passed} \033[92m[OK]\033[0m")
    print(f" Failed         : {failures} " + ("\033[91m[FAIL]\033[0m" if failures else "[0]"))
    print(f" Errors         : {errors} " + ("\033[91m[ERROR]\033[0m" if errors else "[0]"))
    print(f" Skipped        : {skipped}")
    print(f" Execution Time : {duration:.3f} seconds")
    print("=" * 80)

    if failures == 0 and errors == 0:
        print("\033[92m>>> ALL SENTINEL REAL-TIME TESTS PASSED SUCCESSFULLY! <<<\033[0m\n")
        return 0
    else:
        print("\033[91m>>> SOME TESTS FAILED OR ENCOUNTERED ERRORS <<<\033[0m\n")
        return 1


if __name__ == "__main__":
    sys.exit(run_sentinel_tests())
