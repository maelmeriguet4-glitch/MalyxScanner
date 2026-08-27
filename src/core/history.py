"""
MalyxScanner — Detection History Engine
Persists scan and Sentinel detection records to a local JSON file.
"""

from __future__ import annotations

import json
import logging
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger("MalyxHistory")

_HISTORY_FILENAME = "detection_history.json"
_MAX_ENTRIES = 500  # Rolling cap to prevent unbounded growth


def _history_file_path() -> Path:
    """Returns the path to the history JSON file next to the config."""
    import sys
    if getattr(sys, "frozen", False):
        base = Path(sys.executable).resolve().parent
    else:
        base = Path(__file__).resolve().parents[2]
    return base / _HISTORY_FILENAME


class DetectionHistory:
    """Thread-safe, append-only detection log backed by a JSON file."""

    def __init__(self, path: Optional[Path | str] = None) -> None:
        self._path = Path(path) if path else _history_file_path()
        self._lock = threading.Lock()
        self._entries: List[Dict] = []
        self._load()

    # --- Public API ---

    def add(
        self,
        file_path: str,
        file_name: str,
        file_size: int,
        risk_score: int,
        verdict: str,
        threat_type: str = "",
        source: str = "scan",
        sha256: str = "",
    ) -> None:
        """Appends a new detection entry and persists to disk."""
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "file_path": str(file_path),
            "file_name": str(file_name),
            "file_size": int(file_size),
            "risk_score": int(risk_score),
            "verdict": str(verdict),
            "threat_type": str(threat_type),
            "source": str(source),
            "sha256": str(sha256),
        }
        with self._lock:
            self._entries.append(entry)
            # Rolling cap
            if len(self._entries) > _MAX_ENTRIES:
                self._entries = self._entries[-_MAX_ENTRIES:]
            self._save()

    def get_all(self) -> List[Dict]:
        """Returns all entries, most recent first."""
        with self._lock:
            return list(reversed(self._entries))

    def clear(self) -> None:
        """Clears all history entries."""
        with self._lock:
            self._entries.clear()
            self._save()

    def count(self) -> int:
        with self._lock:
            return len(self._entries)

    # --- Internal ---

    def _load(self) -> None:
        try:
            if self._path.exists():
                with open(self._path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, list):
                    self._entries = data
                elif isinstance(data, dict) and "entries" in data:
                    self._entries = data["entries"]
                else:
                    self._entries = []
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Failed to load history file %s: %s", self._path, exc)
            self._entries = []

    def _save(self) -> None:
        try:
            tmp_path = self._path.with_suffix(".tmp")
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(self._entries, f, ensure_ascii=False, indent=2)
            tmp_path.replace(self._path)
        except OSError as exc:
            logger.error("Failed to save history file: %s", exc)


# Singleton
_instance: Optional[DetectionHistory] = None
_instance_lock = threading.Lock()


def get_history() -> DetectionHistory:
    """Returns the global singleton DetectionHistory instance."""
    global _instance
    if _instance is None:
        with _instance_lock:
            if _instance is None:
                _instance = DetectionHistory()
    return _instance


def record_scan(result: dict, source: str = "scan") -> None:
    """Convenience function to record a scan result into history."""
    try:
        file_info = result.get("file", {})
        risk_info = result.get("risk", {})
        hashes = result.get("hashes", {})
        threat = result.get("threat", {})

        get_history().add(
            file_path=file_info.get("path", ""),
            file_name=file_info.get("name", "unknown"),
            file_size=file_info.get("size", 0),
            risk_score=risk_info.get("score", 0),
            verdict=risk_info.get("verdict", "clean"),
            threat_type=threat.get("type", ""),
            source=source,
            sha256=hashes.get("sha256", ""),
        )
    except Exception as exc:
        logger.error("Failed to record scan to history: %s", exc)
