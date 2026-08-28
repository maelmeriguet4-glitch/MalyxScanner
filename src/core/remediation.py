"""
MalyxScanner — Remediation & Quarantine Engine
Handles secure file isolation, XOR byte-level payload obfuscation (to blind host AVs),
full quarantine lifecycle (list, restore, shred), and permanent destruction.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import stat
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("MalyxRemediation")

# Fixed rolling XOR mask for quarantine payload obfuscation
QUARANTINE_XOR_KEY: bytes = b"\x5A\xA5\x55\xAA\xFF\x00\xC3\x3C"


def get_quarantine_dir() -> str:
    """Returns the persistent quarantine directory path under AppData / home."""
    appdata = os.getenv("APPDATA")
    if not appdata:
        appdata = os.path.expanduser("~")
    qdir = os.path.join(appdata, "MalyxScanner", "quarantine")
    os.makedirs(qdir, exist_ok=True)
    return qdir


def _xor_transform_file(src_path: str, dst_path: str, key: bytes = QUARANTINE_XOR_KEY) -> None:
    """
    Applies symmetric XOR streaming obfuscation between src_path and dst_path.
    Because XOR is self-inverse: XOR(XOR(bytes)) == bytes.
    """
    chunk_size = 64 * 1024  # 64 KB
    key_len = len(key)
    key_offset = 0

    with open(src_path, "rb") as f_in, open(dst_path, "wb") as f_out:
        while True:
            chunk = f_in.read(chunk_size)
            if not chunk:
                break
            
            # Vectorized XOR byte transformation
            transformed = bytearray(len(chunk))
            for i, b in enumerate(chunk):
                transformed[i] = b ^ key[(key_offset + i) % key_len]
            
            f_out.write(transformed)
            key_offset = (key_offset + len(chunk)) % key_len


def quarantine_file(file_path: str, metadata: Optional[dict] = None) -> Tuple[bool, str, Optional[str]]:
    """
    Quarantines a file:
    1. Obfuscates content via XOR stream into the quarantine folder (.malyx_quarantine).
    2. Writes .meta.json companion containing original path and scan metadata.
    3. Shreds and removes the original file from the host filesystem.
    """
    if not file_path or not os.path.isfile(file_path):
        return False, "Le fichier d'origine est introuvable ou a déjà été déplacé.", None

    try:
        qdir = get_quarantine_dir()
        ts = int(time.time())
        base_name = os.path.basename(file_path)
        safe_prefix = "".join(c for c in base_name if c.isalnum() or c in "._-")[:30]
        q_filename = f"q_{ts}_{safe_prefix}.malyx_quarantine"
        q_target = os.path.join(qdir, q_filename)

        # 1. Transform payload with XOR encryption into quarantine
        _xor_transform_file(file_path, q_target)

        # 2. Make quarantined file read-only
        try:
            os.chmod(q_target, stat.S_IREAD)
        except Exception:
            pass

        # 3. Securely shred and delete original file from source location
        delete_file_permanently(file_path)

        # 4. Write companion metadata JSON
        meta_filename = f"q_{ts}_{safe_prefix}.meta.json"
        meta_target = os.path.join(qdir, meta_filename)
        info = {
            "id": f"q_{ts}_{safe_prefix}",
            "quarantined_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "original_path": os.path.abspath(file_path),
            "original_name": base_name,
            "file_size": os.path.getsize(q_target) if os.path.exists(q_target) else 0,
            "quarantine_file": q_filename,
            "meta_file": meta_filename,
            "scan_metadata": metadata or {},
        }
        with open(meta_target, "w", encoding="utf-8") as f:
            json.dump(info, f, indent=2, ensure_ascii=False)

        logger.info("Successfully quarantined %s -> %s", file_path, q_target)
        return True, "Fichier mis en quarantaine et neutralisé avec succès (chiffrement XOR).", q_target

    except Exception as exc:
        logger.error("Failed to quarantine file %s: %s", file_path, exc, exc_info=True)
        return False, f"Impossible de mettre le fichier en quarantaine : {exc}", None


def list_quarantined_files() -> List[Dict]:
    """
    Returns a list of all quarantined files with metadata, newest first.
    """
    qdir = get_quarantine_dir()
    results: List[Dict] = []

    try:
        for entry in os.scandir(qdir):
            if entry.is_file() and entry.name.endswith(".meta.json"):
                try:
                    with open(entry.path, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    
                    q_file = os.path.join(qdir, data.get("quarantine_file", ""))
                    if os.path.isfile(q_file):
                        data["quarantine_path"] = q_file
                        data["meta_path"] = entry.path
                        results.append(data)
                except Exception as exc:
                    logger.debug("Failed reading meta file %s: %s", entry.name, exc)
    except Exception as exc:
        logger.warning("Failed scanning quarantine directory: %s", exc)

    # Sort newest first
    results.sort(key=lambda x: x.get("quarantined_at", ""), reverse=True)
    return results


def restore_quarantined_file(quarantine_id: str, custom_target_path: Optional[str] = None) -> Tuple[bool, str]:
    """
    Restores a quarantined file:
    1. Reads .meta.json to locate original path.
    2. De-XORs payload back to original binary format.
    3. Deletes the quarantine and meta files.
    """
    qdir = get_quarantine_dir()
    meta_path = os.path.join(qdir, f"{quarantine_id}.meta.json")

    if not os.path.isfile(meta_path):
        return False, "Métadonnées de quarantaine introuvables."

    try:
        with open(meta_path, "r", encoding="utf-8") as f:
            meta = json.load(f)

        q_file_name = meta.get("quarantine_file", "")
        q_path = os.path.join(qdir, q_file_name)

        if not os.path.isfile(q_path):
            return False, "Le fichier chiffré en quarantaine est introuvable."

        dest_path = custom_target_path or meta.get("original_path")
        if not dest_path:
            return False, "Chemin de destination de restauration indéterminé."

        # Ensure parent directory exists
        os.makedirs(os.path.dirname(dest_path), exist_ok=True)

        # De-XOR restore (XOR is symmetric)
        _xor_transform_file(q_path, dest_path)

        # Remove quarantine files
        try:
            os.chmod(q_path, stat.S_IWRITE | stat.S_IREAD)
        except Exception:
            pass
        os.remove(q_path)
        os.remove(meta_path)

        logger.info("Restored quarantined file %s -> %s", quarantine_id, dest_path)
        return True, f"Fichier restauré avec succès vers :\n{dest_path}"

    except Exception as exc:
        logger.error("Failed to restore quarantined file %s: %s", quarantine_id, exc, exc_info=True)
        return False, f"Erreur lors de la restauration : {exc}"


def delete_quarantined_file(quarantine_id: str) -> Tuple[bool, str]:
    """
    Permanently shreds and deletes a quarantined file and its metadata.
    """
    qdir = get_quarantine_dir()
    meta_path = os.path.join(qdir, f"{quarantine_id}.meta.json")

    if not os.path.isfile(meta_path):
        return False, "Métadonnées de quarantaine introuvables."

    try:
        with open(meta_path, "r", encoding="utf-8") as f:
            meta = json.load(f)

        q_file_name = meta.get("quarantine_file", "")
        q_path = os.path.join(qdir, q_file_name)

        # Shred and remove quarantined payload
        if os.path.isfile(q_path):
            delete_file_permanently(q_path)

        # Remove metadata
        if os.path.isfile(meta_path):
            os.remove(meta_path)

        logger.info("Permanently deleted quarantined file: %s", quarantine_id)
        return True, "Fichier supprimé définitivement et déchiqueté de la quarantaine."

    except Exception as exc:
        logger.error("Failed to delete quarantined file %s: %s", quarantine_id, exc, exc_info=True)
        return False, f"Erreur lors de la suppression : {exc}"


def purge_all_quarantine() -> Tuple[int, int]:
    """
    Purges all files currently in quarantine. Returns (deleted_count, failed_count).
    """
    items = list_quarantined_files()
    deleted = 0
    failed = 0

    for item in items:
        qid = item.get("id")
        if qid:
            success, _ = delete_quarantined_file(qid)
            if success:
                deleted += 1
            else:
                failed += 1

    return deleted, failed


def _shred_file_payload(file_path: str) -> None:
    """Overwrites file contents with random bytes then zeros before removal (secure shredding)."""
    try:
        file_size = os.path.getsize(file_path)
    except OSError:
        file_size = 0

    if file_size > 0:
        chunk_size = 64 * 1024  # 64 KB chunks
        try:
            with open(file_path, "r+b") as f:
                # Pass 1: Cryptographically secure random bytes
                f.seek(0)
                remaining = file_size
                while remaining > 0:
                    write_len = min(remaining, chunk_size)
                    f.write(os.urandom(write_len))
                    remaining -= write_len
                f.flush()
                try:
                    os.fsync(f.fileno())
                except Exception:
                    pass

                # Pass 2: Zero bytes
                f.seek(0)
                remaining = file_size
                zero_chunk = b"\x00" * chunk_size
                while remaining > 0:
                    write_len = min(remaining, chunk_size)
                    f.write(zero_chunk[:write_len])
                    remaining -= write_len
                f.flush()
                try:
                    os.fsync(f.fileno())
                except Exception:
                    pass
                f.truncate(0)
        except (PermissionError, OSError):
            pass


def delete_file_permanently(file_path: str) -> Tuple[bool, str]:
    """Securely shreds and removes the specified file from disk."""
    if not file_path or not os.path.isfile(file_path):
        return False, "Le fichier est introuvable ou a déjà été supprimé."

    try:
        # Reset read-only attribute if present
        try:
            os.chmod(file_path, stat.S_IWRITE | stat.S_IREAD)
        except Exception:
            pass

        # Perform physical multi-pass data overwrite (shredding)
        _shred_file_payload(file_path)

        # Unlink file from filesystem
        os.remove(file_path)
        return True, "Fichier déchiqueté et supprimé définitivement avec succès."
    except Exception as exc:
        return False, f"Impossible de supprimer le fichier : {exc}"
