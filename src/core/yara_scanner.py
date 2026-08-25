import os
import re
from pathlib import Path

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    yara = None
    YARA_AVAILABLE = False


def rules_dir():
    import sys
    if getattr(sys, "frozen", False):
        base = Path(getattr(sys, "_MEIPASS", Path(sys.executable).resolve().parent))
        candidate = base / "rules"
        if candidate.exists():
            return candidate
        return Path(sys.executable).resolve().parent / "rules"
    return Path(__file__).resolve().parents[2] / "rules"


_compiled_cache = None
_cache_signature = None


def _rule_count(source_text):
    return len(re.findall(r"(?m)^\s*rule\s+\w+", source_text))


def _compile_all():
    global _compiled_cache, _cache_signature
    directory = rules_dir()
    files = sorted(directory.glob("*.yar")) + sorted(directory.glob("*.yara"))
    signature = tuple((str(f), f.stat().st_mtime if f.exists() else 0) for f in files)
    if _compiled_cache is not None and _cache_signature == signature:
        return _compiled_cache

    compiled = []
    total_rules = 0
    for rule_file in files:
        try:
            source = rule_file.read_text(encoding="utf-8")
            rules = yara.compile(filepath=str(rule_file))
            compiled.append(rules)
            total_rules += _rule_count(source)
        except (yara.Error, OSError, UnicodeDecodeError):
            continue

    _compiled_cache = (compiled, total_rules, len(files))
    _cache_signature = signature
    return _compiled_cache


def scan_file(path):
    if not YARA_AVAILABLE:
        return {
            "available": False,
            "matches": [],
            "rules_count": 0,
            "rules_files": 0,
            "findings": [{"code": "yara.disabled", "severity": "info", "params": {}}],
        }

    try:
        compiled_list, total_rules, file_count = _compile_all()
    except Exception:
        return {
            "available": False,
            "matches": [],
            "rules_count": 0,
            "rules_files": 0,
            "findings": [{"code": "yara.disabled", "severity": "info", "params": {}}],
        }

    try:
        file_size = os.path.getsize(path)
    except OSError:
        file_size = 0

    matches_found = []
    findings = []

    for ruleset in compiled_list:
        try:
            # For files up to 256 MB, use fast C-level memory mapped scanning across entire file
            if file_size > 256 * 1024 * 1024:
                with open(path, "rb") as f:
                    head_data = f.read(32 * 1024 * 1024)
                matches = ruleset.match(data=head_data, timeout=10)
            else:
                matches = ruleset.match(str(path), timeout=10)
        except (yara.TimeoutError, yara.Error, OSError):
            continue

        for match in matches:
            meta = match.meta or {}
            severity = str(meta.get("severity", "medium")).lower()
            if severity not in ("critical", "high", "medium", "low"):
                severity = "medium"
            description = str(meta.get("description", ""))
            entry = {"rule": match.rule, "severity": severity, "description": description}
            matches_found.append(entry)
            findings.append({
                "code": "yara.match",
                "severity": severity,
                "params": {"rule": match.rule, "desc": description},
            })

    if not matches_found:
        findings.append({"code": "yara.none", "severity": "info", "params": {}})

    return {
        "available": True,
        "matches": matches_found,
        "rules_count": total_rules,
        "rules_files": file_count,
        "findings": findings,
    }
