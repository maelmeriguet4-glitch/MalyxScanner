import json
import os
import shutil
import stat
import time


def get_quarantine_dir():
    appdata = os.getenv("APPDATA")
    if not appdata:
        appdata = os.path.expanduser("~")
    qdir = os.path.join(appdata, "MalyxScanner", "quarantine")
    os.makedirs(qdir, exist_ok=True)
    return qdir


def quarantine_file(file_path, metadata=None):
    if not file_path or not os.path.isfile(file_path):
        return False, "Le fichier d'origine est introuvable ou a déjà été déplacé.", None

    try:
        qdir = get_quarantine_dir()
        ts = int(time.time())
        base_name = os.path.basename(file_path)
        safe_prefix = "".join(c for c in base_name if c.isalnum() or c in "._-")[:30]
        q_filename = f"q_{ts}_{safe_prefix}.malyx_quarantine"
        q_target = os.path.join(qdir, q_filename)

        # Move file to quarantine
        shutil.move(file_path, q_target)

        # Make quarantined file read-only to prevent accidental run
        try:
            os.chmod(q_target, stat.S_IREAD)
        except Exception:
            pass

        # Write metadata JSON
        meta_filename = f"q_{ts}_{safe_prefix}.meta.json"
        meta_target = os.path.join(qdir, meta_filename)
        info = {
            "quarantined_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "original_path": file_path,
            "original_name": base_name,
            "quarantine_file": q_filename,
            "scan_metadata": metadata or {},
        }
        with open(meta_target, "w", encoding="utf-8") as f:
            json.dump(info, f, indent=2, ensure_ascii=False)

        return True, "Fichier mis en quarantaine et neutralisé avec succès.", q_target

    except Exception as exc:
        return False, f"Impossible de mettre le fichier en quarantaine : {exc}", None


def delete_file_permanently(file_path):
    if not file_path or not os.path.isfile(file_path):
        return False, "Le fichier est introuvable ou a déjà été supprimé."

    try:
        # Reset read-only attribute if present
        try:
            os.chmod(file_path, stat.S_IWRITE | stat.S_IREAD)
        except Exception:
            pass

        os.remove(file_path)
        return True, "Fichier supprimé définitivement avec succès."
    except Exception as exc:
        return False, f"Impossible de supprimer le fichier : {exc}"
