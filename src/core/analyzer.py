import os
import stat as _stat
import time
from datetime import datetime

from . import filetype, hashes, entropy, pe_analysis, yara_scanner, strings_extractor, threat_classifier
from . import virustotal as vt_module
from .risk_score import compute_risk

DEFAULT_MAX_CONTENT_BYTES = 200 * 1024 * 1024


def _human_size(num_bytes):
    value = float(num_bytes)
    for unit in ("o", "Ko", "Mo", "Go"):
        if value < 1024 or unit == "Go":
            return f"{value:.1f} {unit}" if unit != "o" else f"{int(value)} o"
        value /= 1024
    return f"{value:.1f} Go"


def _get_file_attributes(path, st_mode):
    attrs = []
    if not (st_mode & _stat.S_IWRITE):
        attrs.append("Read-Only")
    try:
        import ctypes
        FILE_ATTRIBUTE_HIDDEN = 0x02
        FILE_ATTRIBUTE_SYSTEM = 0x04
        FILE_ATTRIBUTE_ARCHIVE = 0x20
        raw_attrs = ctypes.windll.kernel32.GetFileAttributesW(str(path))
        if raw_attrs != -1:
            if raw_attrs & FILE_ATTRIBUTE_HIDDEN:
                attrs.append("Hidden")
            if raw_attrs & FILE_ATTRIBUTE_SYSTEM:
                attrs.append("System")
            if raw_attrs & FILE_ATTRIBUTE_ARCHIVE:
                attrs.append("Archive")
    except Exception:
        pass
    return attrs or ["Normal"]


def analyze_file(path, vt_enabled=False, vt_api_key="", perf_config=None):
    started = time.time()
    path = os.fspath(path)
    perf = perf_config or {}

    max_bytes = int(perf.get("max_file_size_mb", 200)) * 1024 * 1024
    block_size = int(perf.get("entropy_block_size_kb", 16)) * 1024
    enable_yara = bool(perf.get("enable_yara", True))
    enable_strings = bool(perf.get("enable_strings_scan", True))

    result = {
        "schema_version": 2,
        "tool": "MalyxScanner",
        "analyzed_at": datetime.now().isoformat(timespec="seconds"),
        "file": {},
        "hashes": {},
        "identity": {},
        "entropy": {},
        "pe": {"applicable": False, "parsed": False, "info": {}, "findings": []},
        "strings": {"urls": [], "ips": [], "commands": [], "registry": [], "ransom": [], "total_strings": 0},
        "yara": {"available": False, "matches": [], "findings": []},
        "virustotal": {"status": "disabled"},
        "risk": {"score": 0, "verdict": "clean", "breakdown": []},
        "errors": [],
        "privacy": {
            "local_only": True,
            "vt_hash_only": bool(vt_enabled),
            "file_uploaded": False,
        },
    }

    try:
        stat = os.stat(path)
        size = stat.st_size
    except OSError as exc:
        result["errors"].append(f"stat: {exc}")
        return result

    created_time = getattr(stat, "st_ctime", stat.st_mtime)
    accessed_time = getattr(stat, "st_atime", stat.st_mtime)

    result["file"] = {
        "path": os.path.abspath(path),
        "name": os.path.basename(path),
        "size": size,
        "size_human": _human_size(size),
        "created": datetime.fromtimestamp(created_time).isoformat(timespec="seconds"),
        "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(timespec="seconds"),
        "accessed": datetime.fromtimestamp(accessed_time).isoformat(timespec="seconds"),
        "attributes": _get_file_attributes(path, stat.st_mode),
    }

    try:
        result["hashes"] = hashes.compute_hashes(path)
    except OSError as exc:
        result["errors"].append(f"hashes: {exc}")

    try:
        result["identity"] = filetype.analyze_identity(path)
    except (OSError, PermissionError) as exc:
        result["errors"].append(f"identity: {exc}")
        result["identity"] = {"filename": result["file"]["name"], "family": "other", "findings": [], "mismatch": False}

    family = result["identity"].get("family")

    # Entropy analysis
    try:
        ent = entropy.entropy_stream(path)
        blocks_data = entropy.entropy_blocks(path, block_size=block_size)
        result["entropy"] = {
            "global": round(ent, 3),
            "level": entropy.classify(ent),
            "blocks": blocks_data,
        }
        if result["entropy"]["level"] == "high":
            risky_family = family in ("executable", "archive")
            result["entropy"]["finding"] = {
                "code": "find.entropy_high",
                "severity": "medium" if risky_family else "info",
                "params": {"value": round(ent, 2)},
            }
    except OSError as exc:
        result["errors"].append(f"entropy: {exc}")
        result["entropy"] = {"global": None, "level": None, "blocks": {}}

    # Strings extraction
    if enable_strings:
        try:
            result["strings"] = strings_extractor.extract_strings(path)
            if result["strings"].get("ransom"):
                result["identity"]["findings"].append({
                    "code": "find.ransom_strings",
                    "severity": "high",
                    "params": {"count": len(result["strings"]["ransom"])},
                })
            elif result["strings"].get("commands"):
                result["identity"]["findings"].append({
                    "code": "find.suspicious_commands",
                    "severity": "medium",
                    "params": {"count": len(result["strings"]["commands"])},
                })
        except Exception as exc:
            result["errors"].append(f"strings: {exc}")

    # PE Analysis
    if (family == "executable" or path.lower().endswith((".exe", ".dll", ".sys", ".scr"))) and size <= max_bytes:
        try:
            result["pe"] = pe_analysis.analyze_pe(path)
            if result["pe"].get("parsed") and result["pe"].get("info", {}).get("imphash"):
                result["hashes"]["imphash"] = result["pe"]["info"]["imphash"]
        except (OSError, PermissionError) as exc:
            result["errors"].append(f"pe: {exc}")
    else:
        result["pe"] = {"applicable": False, "parsed": False, "info": {},
                        "findings": [{"code": "pe.not_pe", "severity": "info", "params": {}}]}

    # YARA
    if enable_yara:
        try:
            result["yara"] = yara_scanner.scan_file(path)
        except Exception as exc:
            result["errors"].append(f"yara: {exc}")

    # VirusTotal
    sha256 = result["hashes"].get("sha256")
    if vt_enabled and sha256:
        try:
            response = vt_module.lookup_sha256(sha256, vt_api_key)
            response["status"] = response.get("status") or ("found" if response.get("found") else "not_found")
            result["virustotal"] = response
        except vt_module.VTAuthError:
            result["virustotal"] = {"status": "error_auth"}
        except vt_module.VTRateLimitError:
            result["virustotal"] = {"status": "error_rate"}
        except vt_module.VTNetworkError:
            result["virustotal"] = {"status": "error_network"}
        except vt_module.VirusTotalError as exc:
            result["virustotal"] = {"status": "error_other", "message": str(exc)}

    result["risk"] = compute_risk(
        result["identity"],
        result["entropy"],
        result["pe"],
        result["yara"],
        result["virustotal"],
    )

    try:
        threat_info = threat_classifier.classify_threat(
            result["identity"],
            result["entropy"],
            result["pe"],
            result["yara"],
            result["virustotal"],
            result["strings"],
            result["risk"],
        )
        result["threat"] = {"type": threat_info["threat_type"]}
        result["execution_advice"] = threat_info
    except Exception as exc:
        result["errors"].append(f"threat_classifier: {exc}")
        result["threat"] = {"type": "clean" if result["risk"]["verdict"] == "clean" else "suspicious_file"}
        result["execution_advice"] = {
            "threat_type": result["threat"]["type"],
            "advice_status": "danger" if result["risk"]["score"] >= 50 else ("caution" if result["risk"]["score"] >= 20 else "safe"),
            "title_key": "execution.safe_title" if result["risk"]["verdict"] == "clean" else "execution.danger_title",
            "message_key": "execution.safe_message" if result["risk"]["verdict"] == "clean" else "execution.danger_message",
            "risks": [],
            "actions": [],
        }

    result["duration_seconds"] = round(time.time() - started, 2)
    return result
