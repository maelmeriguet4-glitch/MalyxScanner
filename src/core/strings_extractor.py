import os
import re

MAX_SCAN_BYTES = 2 * 1024 * 1024  # 2 MB max for instant non-blocking extraction
MAX_STRINGS_LIMIT = 5000

ASCII_REGEX = re.compile(rb"[\x20-\x7E]{4,}")
UNICODE_REGEX = re.compile(rb"(?:[\x20-\x7E]\x00){4,}")

URL_REGEX = re.compile(r"https?://[a-zA-Z0-9_\-\.\:\@\/\?\=\#\%\&\+\~]+", re.IGNORECASE)
IP_REGEX = re.compile(r"\b(?:[1-9]\d?|1\d\d|2[0-4]\d|25[0-5])\.(?:[0-9]\d?|1\d\d|2[0-4]\d|25[0-5])\.(?:[0-9]\d?|1\d\d|2[0-4]\d|25[0-5])\.(?:[0-9]\d?|1\d\d|2[0-4]\d|25[0-5])\b")
ONION_REGEX = re.compile(r"[a-z2-7]{16,56}\.onion", re.IGNORECASE)

CMD_PATTERNS = [
    (re.compile(r"powershell(\.exe)?\s+(-[a-z]+\s+)*", re.IGNORECASE), "PowerShell"),
    (re.compile(r"cmd(\.exe)?\s+/c\s+", re.IGNORECASE), "CMD execution"),
    (re.compile(r"rundll32(\.exe)?\s+", re.IGNORECASE), "Rundll32"),
    (re.compile(r"regsvr32(\.exe)?\s+", re.IGNORECASE), "Regsvr32"),
    (re.compile(r"vssadmin(\.exe)?\s+delete\s+shadows", re.IGNORECASE), "Shadow Copy Deletion (Ransomware)"),
    (re.compile(r"certutil(\.exe)?\s+-(decode|urlcache)", re.IGNORECASE), "CertUtil Download/Decode"),
    (re.compile(r"mshta(\.exe)?\s+", re.IGNORECASE), "MSHTA execution"),
    (re.compile(r"bitsadmin(\.exe)?\s+/transfer", re.IGNORECASE), "BitsAdmin transfer"),
    (re.compile(r"schtasks(\.exe)?\s+/create", re.IGNORECASE), "Scheduled Task persistence"),
    (re.compile(r"sc(\.exe)?\s+create\s+", re.IGNORECASE), "Service creation"),
    (re.compile(r"whoami(\.exe)?", re.IGNORECASE), "Discovery (whoami)"),
    (re.compile(r"net(\.exe)?\s+(user|localgroup|stop)", re.IGNORECASE), "Net Command"),
]

REG_PATTERNS = [
    re.compile(r"(?:Software\\Microsoft\\Windows\\CurrentVersion\\(?:Run|RunOnce|Policies|Explorer))", re.IGNORECASE),
    re.compile(r"(?:System\\CurrentControlSet\\Services\\[\w\-]+)", re.IGNORECASE),
    re.compile(r"(?:SOFTWARE\\Classes\\CLSID\\[\{\}\w\-]+)", re.IGNORECASE),
]

RANSOM_KEYWORDS = [
    "decrypt", "ransom", "bitcoin", "restore files", "wallet", "personal id",
    "encrypted with", "recover your files", "all your files have been",
]


def extract_strings(path, max_bytes=MAX_SCAN_BYTES):
    if not os.path.exists(path):
        return {"urls": [], "ips": [], "commands": [], "registry": [], "ransom": [], "total_strings": 0}

    total_count = 0
    raw_strings = []

    try:
        with open(path, "rb") as f:
            data = f.read(max_bytes)
    except OSError:
        return {"urls": [], "ips": [], "commands": [], "registry": [], "ransom": [], "total_strings": 0}

    # Extract ASCII
    for m in ASCII_REGEX.finditer(data):
        try:
            s = m.group().decode("ascii", errors="ignore").strip()
            if s:
                total_count += 1
                if len(raw_strings) < MAX_STRINGS_LIMIT:
                    raw_strings.append(s)
        except Exception:
            continue

    # Extract UTF-16LE
    for m in UNICODE_REGEX.finditer(data):
        try:
            s = m.group().decode("utf-16le", errors="ignore").strip()
            if s:
                total_count += 1
                if len(raw_strings) < MAX_STRINGS_LIMIT:
                    raw_strings.append(s)
        except Exception:
            continue

    urls = set()
    ips = set()
    commands = set()
    registry = set()
    ransom = set()

    for s in raw_strings:
        # Check URLs
        for match in URL_REGEX.findall(s):
            if not match.lower().startswith(("http://schemas.", "http://www.w3.org", "http://schemas.microsoft.com")):
                urls.add(match)

        # Check IPs
        for match in IP_REGEX.findall(s):
            if not match.startswith(("0.", "127.", "255.", "1.0.0.0")):
                ips.add(match)

        # Check Onions
        for match in ONION_REGEX.findall(s):
            urls.add(match)

        # Check Commands
        for pattern, label in CMD_PATTERNS:
            if pattern.search(s):
                commands.add(f"[{label}] {s[:120]}")

        # Check Registry
        for pattern in REG_PATTERNS:
            m = pattern.search(s)
            if m:
                registry.add(m.group())

        # Check Ransom keywords
        s_lower = s.lower()
        for kw in RANSOM_KEYWORDS:
            if kw in s_lower and 10 < len(s) < 150:
                ransom.add(s)
                break

    return {
        "urls": sorted(urls)[:25],
        "ips": sorted(ips)[:25],
        "commands": sorted(commands)[:25],
        "registry": sorted(registry)[:25],
        "ransom": sorted(ransom)[:25],
        "total_strings": total_count,
    }
