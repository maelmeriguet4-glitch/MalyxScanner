import os
import re
import puremagic

PE_MIMES = {
    "application/x-dosexec",
    "application/x-msdownload",
    "application/vnd.microsoft.portable-executable",
}

# 12 Universal Families Mapping
CATEGORIES = {
    "document": {
        ".txt", ".md", ".rtf", ".csv", ".tsv", ".log", ".json", ".xml",
        ".yaml", ".yml", ".ini", ".cfg", ".conf", ".inf", ".nfo"
    },
    "office": {
        ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pps", ".ppsx",
        ".odt", ".ods", ".odp", ".rtf", ".dot", ".dotx", ".docm", ".xlsm", ".pptm"
    },
    "ebook": {
        ".pdf", ".epub", ".mobi", ".azw", ".azw3", ".fb2", ".djvu", ".cbz", ".cbr"
    },
    "image": {
        ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".tiff", ".tif",
        ".ico", ".svg", ".heic", ".avif", ".raw", ".cr2", ".nef", ".arw",
        ".dng", ".psd", ".ai", ".eps", ".cur"
    },
    "audio": {
        ".mp3", ".wav", ".flac", ".aac", ".m4a", ".ogg", ".oga", ".opus",
        ".wma", ".aiff", ".mid", ".midi", ".alac", ".ape", ".ac3", ".mka"
    },
    "video": {
        ".mp4", ".mkv", ".avi", ".mov", ".wmv", ".webm", ".flv", ".mpeg",
        ".mpg", ".m4v", ".3gp", ".ts", ".m2ts", ".vob", ".ogv"
    },
    "archive": {
        ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".tar.gz",
        ".tar.bz2", ".tar.xz", ".tgz", ".tbz2", ".txz", ".iso", ".cab",
        ".arj", ".lzh", ".zst", ".lz4", ".lzma", ".cpio", ".img", ".vmdk"
    },
    "executable": {
        ".exe", ".msi", ".dll", ".sys", ".scr", ".com", ".bat", ".cmd",
        ".ps1", ".psm1", ".vbs", ".vbe", ".wsf", ".wsh", ".jar", ".app",
        ".dmg", ".deb", ".rpm", ".apk", ".aab", ".gadget", ".msc", ".cpl",
        ".pif", ".hta", ".ocx", ".drv", ".efi"
    },
    "code": {
        ".py", ".pyw", ".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx",
        ".java", ".c", ".h", ".cpp", ".hpp", ".cc", ".cxx", ".cs",
        ".go", ".rs", ".php", ".rb", ".swift", ".kt", ".kts", ".lua",
        ".sh", ".bash", ".zsh", ".html", ".htm", ".css", ".scss", ".sass",
        ".less", ".sql", ".asm", ".s", ".v", ".sv", ".pl", ".dart", ".r"
    },
    "database": {
        ".db", ".sqlite", ".sqlite3", ".mdb", ".accdb", ".dbf", ".sql",
        ".rdb", ".frm", ".ibd", ".myd", ".myi"
    },
    "system": {
        ".reg", ".dat", ".bin", ".tmp", ".bak", ".dump", ".dmp",
        ".config", ".plist", ".theme", ".manifest", ".pol", ".cat", ".inf"
    },
    "game": {
        ".pak", ".uasset", ".unity3d", ".assets", ".bundle", ".wad",
        ".bsp", ".vpk", ".gcf", ".vdf", ".arc", ".sav", ".gam", ".rom",
        ".nds", ".gba", ".sfc", ".smc", ".gcm", ".iso"
    },
}

EXECUTABLE_EXTS = CATEGORIES["executable"]

DANGEROUS_EXTS = {
    ".scr", ".pif", ".cpl", ".js", ".jse", ".vbs", ".vbe", ".wsf", ".wsh",
    ".ps1", ".bat", ".cmd", ".hta", ".lnk", ".chm", ".jar", ".msi", ".com",
    ".exe", ".dll", ".sys", ".gadget", ".msc", ".vbe", ".ws", ".jse"
}

DOUBLE_EXT_RE = re.compile(
    r"\.(jpe?g|png|gif|bmp|webp|pdf|docx?|xlsx?|pptx?|txt|mp[34]|wav|zip|rar|7z|tar|iso)"
    r"\.(exe|scr|bat|cmd|com|pif|vbs|vbe|js|jse|ps1|hta|jar|msi|cpl|gadget)$",
    re.IGNORECASE,
)

ARCHIVE_MIMES = {
    "application/zip", "application/x-rar-compressed", "application/x-7z-compressed",
    "application/x-tar", "application/gzip", "application/x-bzip2", "application/x-xz",
    "application/vnd.rar", "application/x-iso9660-image", "application/x-cab",
}

DOCUMENT_MIMES = {
    "application/pdf", "application/msword",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "application/vnd.ms-excel", "application/vnd.ms-powerpoint",
    "application/rtf", "application/epub+zip",
}

FAMILY_PREFIXES = (
    ("image/", "image"),
    ("video/", "video"),
    ("audio/", "audio"),
    ("text/", "document"),
)


def _get_extension(filename):
    lower_name = filename.lower()
    for double_ext in (".tar.gz", ".tar.bz2", ".tar.xz", ".sqlite3", ".unity3d"):
        if lower_name.endswith(double_ext):
            return double_ext
    return os.path.splitext(lower_name)[1]


def _family_for(mime, ext):
    if mime in PE_MIMES or ext in EXECUTABLE_EXTS:
        return "executable"
    
    # Check explicitly configured categories
    for fam, exts in CATEGORIES.items():
        if ext in exts:
            return fam

    if mime:
        if mime in ARCHIVE_MIMES:
            return "archive"
        if mime in DOCUMENT_MIMES:
            return "office" if ("word" in mime or "excel" in mime or "powerpoint" in mime or "msword" in mime) else "ebook"
        if mime == "text/plain":
            return "document"
        for prefix, fam in FAMILY_PREFIXES:
            if mime.startswith(prefix):
                return fam
        if "executable" in mime or "sharedlib" in mime or "elf" in mime or "mach-o" in mime:
            return "executable"
        if "database" in mime or "sqlite" in mime:
            return "database"

    return "other"


def analyze_identity(path):
    findings = []
    name = os.path.basename(path)
    ext = _get_extension(name)

    mime = None
    human = None
    try:
        mime = puremagic.from_file(str(path), mime=True)
    except Exception:
        mime = None

    try:
        candidate = puremagic.from_file(str(path))
        human = candidate
    except Exception:
        human = None

    family = _family_for(mime, ext)

    # Detect masquerading: real executable masked as doc/image/media/archive
    mismatch = False
    if mime in PE_MIMES and ext not in EXECUTABLE_EXTS:
        mismatch = True
    elif ext in CATEGORIES["image"] | CATEGORIES["document"] | CATEGORIES["ebook"] | CATEGORIES["audio"] | CATEGORIES["video"]:
        if mime in PE_MIMES or (family == "executable" and ext not in EXECUTABLE_EXTS):
            mismatch = True

    real_label = human or mime or ext or "Inconnu"
    if mismatch:
        findings.append({
            "code": "find.type_mismatch",
            "severity": "high",
            "params": {"declared": ext or "?", "real": str(real_label)},
        })
    else:
        findings.append({
            "code": "find.type_ok",
            "severity": "info",
            "params": {"real": str(real_label)},
        })

    if ext in DANGEROUS_EXTS:
        findings.append({
            "code": "find.dangerous_ext",
            "severity": "medium",
            "params": {"ext": ext},
        })

    if DOUBLE_EXT_RE.search(name):
        findings.append({
            "code": "find.double_ext",
            "severity": "high",
            "params": {},
        })

    return {
        "filename": name,
        "extension": ext,
        "mime": mime,
        "human_type": human,
        "family": family,
        "mismatch": mismatch,
        "findings": findings,
    }
