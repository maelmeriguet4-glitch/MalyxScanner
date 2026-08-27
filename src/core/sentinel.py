"""
MalyxScanner — Real-Time Sentinel Core & Streaming Engine
Provides a lightweight, passive background daemon for real-time monitoring of downloads
with zero UI freezing, bounded memory usage via fixed-size chunk streaming, and instant threat alerting.
"""

from __future__ import annotations

import fnmatch
import logging
import os
import stat
import sys
import threading
import time
from pathlib import Path
from typing import Callable, Dict, Optional, Set, Tuple

try:
    from .analyzer import analyze_file
except (ImportError, ValueError):
    from core.analyzer import analyze_file

logger = logging.getLogger("MalyxSentinel")

# --- Constants & Default Configuration ---
DEFAULT_POLL_INTERVAL: float = 1.5
DEFAULT_RAM_LIMIT_MB: int = 128
DEFAULT_STREAM_CHUNK_KB: int = 64
MAX_LOCK_RETRIES: int = 3

IGNORED_EXTENSIONS: Set[str] = {
    ".crdownload",  # Chrome, Edge, Brave, Opera (Chromium)
    ".part",        # Firefox
    ".download",    # Safari, macOS
    ".partial",     # Download managers, curl, wget
    ".tmp",         # Generic temporary
    ".temp",        # Generic temporary
    ".aria2",       # Aria2
    ".malyx_quarantine",  # MalyxScanner Quarantine
    ".meta.json",   # Quarantine metadata
}

IGNORED_PREFIXES: Tuple[str, ...] = (
    "~$",           # Microsoft Office lock files
    ".~",           # LibreOffice lock files
    ".tmp",         # Hidden temporary files
    ".malyx_",      # Malyx temporary/quarantine
)

IGNORED_PATTERNS: Tuple[str, ...] = (
    "*.tmp",
    "*._temp",
    "*_part*",
)


def get_default_downloads_dir() -> Path:
    """Resolves the user's Downloads directory with Windows Shell Registry support."""
    if os.name == "nt":
        try:
            import winreg
            reg_key = r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg_key) as key:
                val, _ = winreg.QueryValueEx(key, "{374DE290-123F-4565-9164-39C4925E467B}")
                expanded = os.path.expandvars(val)
                if os.path.isdir(expanded):
                    return Path(expanded).resolve()
        except Exception:
            pass

    home_downloads = Path.home() / "Downloads"
    if home_downloads.exists() and home_downloads.is_dir():
        return home_downloads.resolve()
    return Path.home().resolve()


class SentinelWatcher:
    """
    Passive background daemon monitoring a specified directory (default: Downloads)
    for new or modified files. Streams files in fixed chunk buffers to cap memory,
    and invokes a callback upon detecting suspicious or dangerous files.
    """

    def __init__(
        self,
        watch_dir: Optional[str | Path] = None,
        on_threat_detected: Optional[Callable[[Path, dict], None]] = None,
        ram_limit_mb: int = DEFAULT_RAM_LIMIT_MB,
        stream_chunk_kb: int = DEFAULT_STREAM_CHUNK_KB,
        poll_interval: float = DEFAULT_POLL_INTERVAL,
        perf_config: Optional[dict] = None,
        enabled: bool = True,
    ) -> None:
        self.watch_dir = Path(watch_dir).resolve() if watch_dir else get_default_downloads_dir()
        self.on_threat_detected = on_threat_detected
        self.ram_limit_mb = int(ram_limit_mb)
        self.stream_chunk_kb = int(stream_chunk_kb)
        self.poll_interval = float(poll_interval)
        self.perf_config = dict(perf_config or {})
        self.enabled = bool(enabled)

        self._snapshot: Dict[str, Tuple[float, int]] = {}
        self._pending_files: Dict[str, dict] = {}
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        """Starts the Sentinel background daemon thread if not already running."""
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return

            self._stop_event.clear()
            self._snapshot = self._build_snapshot()
            self._pending_files.clear()

            self._thread = threading.Thread(
                target=self._run,
                name="SentinelWatcherDaemon",
                daemon=True,
            )
            self._thread.start()
            logger.info(
                "SentinelWatcher started on %s (poll=%.1fs, RAM limit=%dMB)",
                self.watch_dir, self.poll_interval, self.ram_limit_mb
            )

    def stop(self, timeout: float = 5.0) -> None:
        """Signals the daemon thread to stop gracefully and waits for termination."""
        self._stop_event.set()
        thread = None
        with self._lock:
            thread = self._thread

        if thread is not None and thread.is_alive():
            thread.join(timeout=timeout)
            logger.info("SentinelWatcher stopped.")

    def is_running(self) -> bool:
        """Returns True if the Sentinel daemon is actively monitoring."""
        with self._lock:
            return bool(self._thread is not None and self._thread.is_alive() and not self._stop_event.is_set())

    def update_config(self, new_config: dict) -> None:
        """
        Dynamically updates Sentinel configuration (watch_dir, poll_interval, RAM limits).
        Rebuilds baseline snapshot if watch_dir changes.
        """
        with self._lock:
            if "watch_dir" in new_config and new_config["watch_dir"]:
                new_path = Path(new_config["watch_dir"]).resolve()
                if new_path != self.watch_dir:
                    self.watch_dir = new_path
                    self._snapshot = self._build_snapshot()
                    self._pending_files.clear()
                    logger.info("SentinelWatcher watch directory updated to: %s", self.watch_dir)

            if "poll_interval" in new_config:
                self.poll_interval = max(0.5, float(new_config["poll_interval"]))

            if "ram_limit_mb" in new_config:
                self.ram_limit_mb = max(16, int(new_config["ram_limit_mb"]))

            if "stream_chunk_kb" in new_config:
                self.stream_chunk_kb = max(16, int(new_config["stream_chunk_kb"]))

            if "perf_config" in new_config:
                self.perf_config.update(new_config["perf_config"])

            if "enabled" in new_config:
                self.enabled = bool(new_config["enabled"])

    def scan_file_streaming(self, file_path: Path | str, chunk_kb: Optional[int] = None) -> dict:
        """
        Directly analyzes a single file using configured streaming chunk buffers
        and RAM limits without loading the full file into memory.
        """
        return scan_file_streaming(
            file_path=file_path,
            ram_limit_mb=self.ram_limit_mb,
            stream_chunk_kb=self.stream_chunk_kb,
            chunk_kb=chunk_kb,
            perf_config=self.perf_config,
        )

    # --- Internal Private Methods ---

    def _build_snapshot(self) -> Dict[str, Tuple[float, int]]:
        """Scans the watch directory and returns a dictionary of {abs_path: (mtime, size)}."""
        snapshot: Dict[str, Tuple[float, int]] = {}
        if not self.watch_dir.exists() or not self.watch_dir.is_dir():
            return snapshot

        try:
            with os.scandir(self.watch_dir) as entries:
                for entry in entries:
                    try:
                        if entry.is_file(follow_symlinks=False):
                            st = entry.stat()
                            snapshot[os.path.abspath(entry.path)] = (st.st_mtime, st.st_size)
                    except (OSError, PermissionError):
                        continue
        except (OSError, PermissionError) as exc:
            logger.warning("Error taking baseline snapshot of %s: %s", self.watch_dir, exc)

        return snapshot

    def _is_ignored(self, filename: str) -> bool:
        """Determines if a file should be ignored based on extension, prefix, or transient patterns."""
        name_lower = filename.lower()

        # 1. Check ignored extensions
        for ext in IGNORED_EXTENSIONS:
            if name_lower.endswith(ext):
                return True

        # 2. Check ignored prefixes
        for prefix in IGNORED_PREFIXES:
            if name_lower.startswith(prefix):
                return True

        # 3. Check ignored wildcards
        for pattern in IGNORED_PATTERNS:
            if fnmatch.fnmatch(name_lower, pattern):
                return True

        # 4. Hidden or special system files
        if filename.startswith("."):
            return True

        return False

    def _check_file_stabilization(self, file_path: str, current_mtime: float, current_size: int) -> bool:
        """
        Verifies whether an arriving file has finished writing and can be read safely.
        Returns True if stable and ready to scan, False if writing is ongoing or file is locked.
        """
        now = time.time()
        info = self._pending_files.get(file_path)

        if info is None:
            # First time seeing this new file
            self._pending_files[file_path] = {
                "first_seen": now,
                "last_mtime": current_mtime,
                "last_size": current_size,
                "retries": 0,
            }
            # If 0-byte file, defer immediately to next poll cycle to see if content arrives
            if current_size == 0:
                return False
        else:
            # File was seen in previous cycle
            if current_size != info["last_size"] or current_mtime != info["last_mtime"]:
                # Size or timestamp is still actively changing
                info["last_mtime"] = current_mtime
                info["last_size"] = current_size
                info["retries"] = 0
                return False

        # Attempt to acquire a non-exclusive read handle to ensure OS write locks are released
        entry_info = self._pending_files.get(file_path)
        try:
            with open(file_path, "rb") as f:
                f.read(1024)
            return True
        except (PermissionError, OSError) as exc:
            err_str = str(exc).lower()
            winerr = getattr(exc, "winerror", None)
            errno_code = getattr(exc, "errno", None)
            # Check for AV block / quarantine on infected files (WinError 225 / [Errno 22])
            if winerr == 225 or errno_code == 22 or "virus" in err_str or "infected" in err_str:
                logger.warning("File %s is blocked or quarantined by OS/AV: %s", file_path, exc)
                return True

            if entry_info is not None:
                entry_info["retries"] += 1
                if entry_info["retries"] >= 60:
                    logger.debug("Giving up on locked file after 60 retries: %s", file_path)
                    self._snapshot[file_path] = (current_mtime, current_size)
                    self._pending_files.pop(file_path, None)
            return False

    def _evaluate_threat(self, result: dict) -> bool:
        """Evaluates whether the scan result warrants triggering an alert."""
        for err in result.get("errors", []):
            err_str = str(err).lower()
            if "225" in err_str or "errno 22" in err_str or "virus" in err_str or "infected" in err_str:
                return True

        risk_score = result.get("risk", {}).get("score", 0)
        if "risk_score" in result:
            risk_score = max(risk_score, result["risk_score"])

        verdict = result.get("risk", {}).get("verdict", "clean")
        advice_status = result.get("execution_advice", {}).get("advice_status", "safe")

        return bool(
            risk_score >= 20
            or verdict in ("suspicious", "malicious")
            or advice_status in ("caution", "danger")
        )

    def _poll_cycle(self) -> None:
        """Executes a single pass over the watched directory."""
        with self._lock:
            watch_dir = self.watch_dir
            if not watch_dir.exists() or not watch_dir.is_dir():
                return

        current_existing: Set[str] = set()

        try:
            with os.scandir(watch_dir) as entries:
                for entry in entries:
                    if self._stop_event.is_set():
                        return

                    try:
                        if not entry.is_file(follow_symlinks=False):
                            continue

                        abs_path = os.path.abspath(entry.path)
                        current_existing.add(abs_path)

                        if self._is_ignored(entry.name):
                            continue

                        st = entry.stat()
                        mtime = st.st_mtime
                        size = st.st_size

                        if size == 0:
                            continue

                        with self._lock:
                            # Check if file is already processed and unchanged
                            prev = self._snapshot.get(abs_path)
                            if prev is not None and prev == (mtime, size):
                                continue

                            # Check file write stabilization and lock release
                            if not self._check_file_stabilization(abs_path, mtime, size):
                                continue

                        # File is stable: analyze in streaming mode
                        logger.info("Sentinel analyzing new file: %s (%d bytes)", entry.name, size)
                        try:
                            scan_result = self.scan_file_streaming(abs_path)
                        except Exception as scan_err:
                            logger.error("Error during sentinel scan of %s: %s", entry.name, scan_err)
                            scan_result = {
                                "file": {"name": entry.name, "path": abs_path, "size": size},
                                "risk": {"score": 20, "verdict": "suspicious"},
                                "errors": [str(scan_err)],
                            }

                        with self._lock:
                            # Update snapshot to prevent duplicate scanning
                            self._snapshot[abs_path] = (mtime, size)
                            self._pending_files.pop(abs_path, None)

                        # Threat evaluation
                        if self._evaluate_threat(scan_result):
                            logger.warning(
                                "Sentinel detected threat in %s (score=%s)",
                                entry.name,
                                scan_result.get("risk", {}).get("score"),
                            )
                            if self.on_threat_detected and callable(self.on_threat_detected):
                                try:
                                    self.on_threat_detected(Path(abs_path), scan_result)
                                except Exception as cb_exc:
                                    logger.error(
                                        "Exception in on_threat_detected callback: %s",
                                        cb_exc,
                                        exc_info=True,
                                    )

                    except (OSError, PermissionError) as entry_exc:
                        logger.debug("Error inspecting entry %s: %s", entry.name, entry_exc)
                        continue

        except (OSError, PermissionError) as scan_exc:
            logger.warning("Error accessing watch directory %s: %s", watch_dir, scan_exc)

        # Prune deleted files from snapshot to prevent unbounded memory growth
        with self._lock:
            stale_keys = [k for k in self._snapshot if k not in current_existing]
            for k in stale_keys:
                self._snapshot.pop(k, None)
                self._pending_files.pop(k, None)

    def _run(self) -> None:
        """Main daemon worker loop."""
        while not self._stop_event.is_set():
            if self.enabled:
                try:
                    self._poll_cycle()
                except Exception as exc:
                    logger.error("Unexpected error in Sentinel poll cycle: %s", exc, exc_info=True)

            # Non-blocking wait that responds instantly to stop_event
            self._stop_event.wait(timeout=self.poll_interval)


def scan_file_streaming(
    file_path: Path | str,
    ram_limit_mb: int = DEFAULT_RAM_LIMIT_MB,
    stream_chunk_kb: int = DEFAULT_STREAM_CHUNK_KB,
    chunk_kb: Optional[int] = None,
    perf_config: Optional[dict] = None,
) -> dict:
    """
    Directly analyzes a single file in fixed streaming chunk buffers with bounded memory usage.
    Module-level function.
    """
    if chunk_kb is not None:
        stream_chunk_kb = int(chunk_kb)
    path_obj = Path(file_path).resolve()
    merged_perf = dict(perf_config or {})
    merged_perf["max_file_size_mb"] = int(ram_limit_mb)
    merged_perf["entropy_block_size_kb"] = min(int(stream_chunk_kb), 64)
    merged_perf.setdefault("enable_yara", True)
    merged_perf.setdefault("enable_strings_scan", True)

    try:
        return analyze_file(
            path=str(path_obj),
            vt_enabled=False,
            vt_api_key="",
            perf_config=merged_perf,
        )
    except Exception as exc:
        logger.error("Error analyzing file %s in streaming mode: %s", path_obj, exc)
        return {
            "file": {"name": path_obj.name, "path": str(path_obj), "size": 0},
            "risk": {"score": 20, "verdict": "suspicious"},
            "errors": [str(exc)],
            "threat": {"type": "suspicious_file"},
            "execution_advice": {"threat_type": "suspicious_file", "advice_status": "caution"},
        }


__all__ = [
    "SentinelWatcher",
    "scan_file_streaming",
    "get_default_downloads_dir",
    "DEFAULT_POLL_INTERVAL",
    "DEFAULT_RAM_LIMIT_MB",
    "DEFAULT_STREAM_CHUNK_KB",
]

