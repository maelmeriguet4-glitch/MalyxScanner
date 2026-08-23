import datetime
import os
import pefile

from .entropy import entropy_bytes

EXEC_MASK = pefile.SECTION_CHARACTERISTICS["IMAGE_SCN_MEM_EXECUTE"]
WRITE_MASK = pefile.SECTION_CHARACTERISTICS["IMAGE_SCN_MEM_WRITE"]

STANDARD_SECTIONS = {
    ".text", ".data", ".rdata", ".rsrc", ".reloc", ".bss", ".idata", ".edata",
    ".pdata", ".tls", ".debug", ".didata", ".xdata", ".cfg", ".gfids", ".idata$",
}

MITRE_API_MAP = {
    "injection": {
        "writeprocessmemory", "virtualallocex", "virtualprotectex", "createremotethread",
        "ntcreatethreadex", "rtlcreateuserthread", "setthreadcontext", "ntunmapviewofsection",
        "queueuserapc", "mapviewoffile", "virtualalloc",
    },
    "antidebug": {
        "isdebuggerpresent", "checkremotedebuggerpresent", "ntqueryinformationprocess",
        "outputdebugstringa", "outputdebugstringw", "findwindowa", "findwindoww",
    },
    "network": {
        "urldownloadtofilea", "urldownloadtofilew", "internetopenurla", "internetopenurlw",
        "winhttpopen", "ftpgetfilea", "internetopena", "internetopenw", "winhttpconnect",
        "wsastartup", "connect", "send", "recv",
    },
    "execution": {
        "winexec", "shellexecutea", "shellexecutew", "system",
        "createprocessa", "createprocessw", "createprocessasusera",
    },
    "persistence": {
        "regsetvalueexa", "regsetvalueexw", "regcreatekeyexa", "regcreatekeyexw",
        "createservicea", "createservicew", "openscmanagera",
    },
    "crypto": {
        "cryptencrypt", "cryptdecrypt", "cryptgenrandom", "bcryptencrypt", "bcryptdecrypt",
    },
    "hooking": {
        "setwindowshookexa", "setwindowshookexw", "getasynckeystate", "getkeystate",
    },
    "privilege": {
        "adjusttokenprivileges", "openprocesstoken", "impersonateloggedonuser",
    },
}

SUBSYSTEM_NAMES = {
    1: "Native / Driver",
    2: "Windows GUI",
    3: "Windows Console (CLI)",
    5: "OS/2 Console",
    7: "POSIX Console",
    9: "Windows CE",
    10: "EFI Application",
    11: "EFI Boot Service Driver",
    12: "EFI Runtime Driver",
    14: "Xbox",
}

MACHINE_NAMES = {
    0x014C: "x86 (32-bit)",
    0x8664: "x64 (64-bit)",
    0x01C0: "ARM",
    0xAA64: "ARM64",
    0x01C4: "ARMNT",
}


def _section_flags(section):
    chars = section.Characteristics
    flags = []
    if chars & EXEC_MASK:
        flags.append("X")
    if chars & WRITE_MASK:
        flags.append("W")
    return flags


def _extract_version_info(pe):
    info = {}
    if not hasattr(pe, "FileInfo") or not pe.FileInfo:
        return info
    for file_info in pe.FileInfo:
        for entry in file_info:
            if hasattr(entry, "StringTable"):
                for st in entry.StringTable:
                    for k, v in st.entries.items():
                        key = k.decode("utf-8", errors="ignore") if isinstance(k, bytes) else str(k)
                        val = v.decode("utf-8", errors="ignore") if isinstance(v, bytes) else str(v)
                        info[key] = val
    return info


def _extract_pdb_path(pe):
    if not hasattr(pe, "DIRECTORY_ENTRY_DEBUG"):
        return None
    for dbg in pe.DIRECTORY_ENTRY_DEBUG:
        if hasattr(dbg, "entry") and dbg.entry:
            pdb = getattr(dbg.entry, "PdbFileName", None)
            if pdb:
                return pdb.decode("utf-8", errors="ignore").rstrip("\x00") if isinstance(pdb, bytes) else str(pdb)
    return None


def analyze_pe(path):
    info = {}
    findings = []

    try:
        pe = pefile.PE(str(path))
    except pefile.PEFormatError:
        findings.append({"code": "pe.parse_failed", "severity": "medium", "params": {}})
        return {"applicable": True, "parsed": False, "info": info, "findings": findings}
    except (OSError, PermissionError):
        raise

    machine = pe.FILE_HEADER.Machine
    info["machine"] = MACHINE_NAMES.get(machine, hex(machine))

    opt = getattr(pe, "OPTIONAL_HEADER", None)
    if opt:
        subsys = getattr(opt, "Subsystem", 0)
        info["subsystem"] = SUBSYSTEM_NAMES.get(subsys, f"Unknown ({subsys})")
        info["entry_point"] = hex(getattr(opt, "AddressOfEntryPoint", 0))
        info["image_base"] = hex(getattr(opt, "ImageBase", 0))

        # Check Authenticode (Directory entry 4 = IMAGE_DIRECTORY_ENTRY_SECURITY)
        sec_entry = 4
        if hasattr(opt, "DATA_DIRECTORY") and len(opt.DATA_DIRECTORY) > sec_entry:
            sec_dir = opt.DATA_DIRECTORY[sec_entry]
            info["is_signed"] = bool(sec_dir.VirtualAddress and sec_dir.Size)
        else:
            info["is_signed"] = False

        # Check .NET (Directory entry 14 = IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR)
        clr_entry = 14
        if hasattr(opt, "DATA_DIRECTORY") and len(opt.DATA_DIRECTORY) > clr_entry:
            clr_dir = opt.DATA_DIRECTORY[clr_entry]
            info["is_dotnet"] = bool(clr_dir.VirtualAddress and clr_dir.Size)
        else:
            info["is_dotnet"] = False
    else:
        info["subsystem"] = "N/A"
        info["is_signed"] = False
        info["is_dotnet"] = False

    # Imphash
    try:
        info["imphash"] = pe.get_imphash()
    except Exception:
        info["imphash"] = None

    # Version Info
    try:
        info["version_info"] = _extract_version_info(pe)
    except Exception:
        info["version_info"] = {}

    # PDB Debug Path
    try:
        info["pdb_path"] = _extract_pdb_path(pe)
    except Exception:
        info["pdb_path"] = None

    ts = pe.FILE_HEADER.TimeDateStamp
    try:
        compiled = datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc)
        info["compiled"] = compiled.strftime("%Y-%m-%d %H:%M UTC")
        if compiled > datetime.datetime.now(tz=datetime.timezone.utc) + datetime.timedelta(days=365):
            findings.append({
                "code": "pe.future_timestamp",
                "severity": "medium",
                "params": {"date": info["compiled"]},
            })
    except (OverflowError, OSError, ValueError):
        info["compiled"] = None

    # Sections
    sections = []
    exec_section_count = 0
    for idx, section in enumerate(pe.sections):
        raw_name = section.Name.decode("utf-8", errors="ignore").rstrip("\x00")
        data = section.get_data()
        ent = entropy_bytes(data)
        flags = _section_flags(section)
        is_exec = "X" in flags
        is_write = "W" in flags
        if is_exec:
            exec_section_count += 1
        sections.append({
            "name": raw_name or f"#{idx}",
            "size": len(data),
            "virtual_size": section.Misc_VirtualSize,
            "entropy": round(ent, 2),
            "flags": "".join(flags),
        })
        if ent > 7.0 and is_exec and section.SizeOfRawData > 4096:
            findings.append({
                "code": "pe.section_entropy_high",
                "severity": "high",
                "params": {"name": raw_name or f"#{idx}", "value": round(ent, 2)},
            })
        if is_exec and is_write:
            findings.append({
                "code": "pe.section_wx",
                "severity": "high",
                "params": {"name": raw_name or f"#{idx}"},
            })
        if raw_name and raw_name.lower() not in STANDARD_SECTIONS and not raw_name.startswith("."):
            findings.append({
                "code": "pe.unusual_section",
                "severity": "info",
                "params": {"name": raw_name},
            })
    info["sections"] = sections

    # Imports categorized
    dll_imports = {}
    import_names = []
    mitre_detected = {k: set() for k in MITRE_API_MAP}

    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode("utf-8", errors="ignore") if isinstance(entry.dll, bytes) else str(entry.dll)
            funcs = []
            for imp in entry.imports:
                if imp.name:
                    fn_name = imp.name.decode("utf-8", errors="ignore")
                    funcs.append(fn_name)
                    full_name = f"{dll}!{fn_name}"
                    import_names.append(full_name)
                    fn_lower = fn_name.lower()
                    for cat, apiset in MITRE_API_MAP.items():
                        if fn_lower in apiset:
                            mitre_detected[cat].add(fn_name)
            dll_imports[dll] = funcs

    info["imports_count"] = len(import_names)
    info["dll_imports"] = dll_imports
    info["mitre_apis"] = {k: sorted(v) for k, v in mitre_detected.items() if v}

    if exec_section_count >= 1 and len(import_names) == 0 and not info.get("is_dotnet"):
        findings.append({"code": "pe.no_imports", "severity": "medium", "params": {}})

    # Check Findings based on MITRE categories
    if len(mitre_detected["injection"]) >= 2:
        findings.append({
            "code": "pe.injection_imports",
            "severity": "high",
            "params": {"apis": ", ".join(sorted(mitre_detected["injection"])[:8])},
        })
    if mitre_detected["network"] and mitre_detected["execution"]:
        findings.append({
            "code": "pe.downloader_pattern",
            "severity": "high",
            "params": {"apis": ", ".join(sorted(mitre_detected["network"] | mitre_detected["execution"])[:8])},
        })
    if mitre_detected["antidebug"]:
        findings.append({
            "code": "pe.antidebug_imports",
            "severity": "low",
            "params": {"apis": ", ".join(sorted(mitre_detected["antidebug"])[:4])},
        })

    # Exports
    exports = []
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            exp_name = exp.name.decode("utf-8", errors="ignore") if exp.name else f"Ordinal_{exp.ordinal}"
            exports.append({"name": exp_name, "ordinal": exp.ordinal})
    info["exports"] = exports
    info["exports_count"] = len(exports)

    # TLS Callbacks
    tls = getattr(pe, "DIRECTORY_ENTRY_TLS", None)
    if tls is not None:
        callbacks = getattr(tls, "callbacks", []) or []
        if callbacks:
            findings.append({
                "code": "pe.tls_callbacks",
                "severity": "medium",
                "params": {"count": len(callbacks)},
            })

    # Entry Point position
    ep_val = getattr(opt, "AddressOfEntryPoint", None) if opt else None
    if ep_val is not None and ep_val > 0:
        ep_section_idx = None
        for idx, section in enumerate(pe.sections):
            start = section.VirtualAddress
            end = start + max(section.Misc_VirtualSize, section.SizeOfRawData)
            if start <= ep_val < end:
                ep_section_idx = idx
                break
        if ep_section_idx is None:
            findings.append({"code": "pe.entry_invalid", "severity": "medium", "params": {}})
        elif ep_section_idx > 0 and len(sections) > 2:
            findings.append({"code": "pe.entry_not_first", "severity": "low", "params": {}})

    # Overlay
    try:
        overlay_start = pe.get_overlay_data_start_offset()
        if overlay_start is not None:
            total = os.path.getsize(str(path))
            overlay_size = max(0, total - overlay_start)
            info["overlay_mb"] = round(overlay_size / (1024 * 1024), 2)
            if overlay_size > 5 * 1024 * 1024 and total > 0 and overlay_size / total > 0.3:
                findings.append({
                    "code": "pe.overlay_large",
                    "severity": "low",
                    "params": {"mb": round(overlay_size / (1024 * 1024), 2)},
                })
    except Exception:
        pass

    return {"applicable": True, "parsed": True, "info": info, "findings": findings}
