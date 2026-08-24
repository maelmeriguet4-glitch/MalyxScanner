import requests

# Inject Windows certificate store so HTTPS works behind Norton 360 / corporate proxies
try:
    import truststore
    truststore.inject_into_ssl()
except Exception:
    pass

API_URL = "https://www.virustotal.com/api/v3/files/"
TIMEOUT = 20



class VirusTotalError(Exception):
    pass


class VTAuthError(VirusTotalError):
    pass


class VTRateLimitError(VirusTotalError):
    pass


class VTNetworkError(VirusTotalError):
    pass


def lookup_sha256(sha256, api_key):
    if not api_key:
        raise VTAuthError("missing api key")

    try:
        response = requests.get(
            API_URL + sha256,
            headers={"x-apikey": api_key, "accept": "application/json"},
            timeout=TIMEOUT,
        )
    except requests.exceptions.RequestException as exc:
        raise VTNetworkError(str(exc)) from exc

    if response.status_code == 404:
        return {"status": "not_found", "found": False}
    if response.status_code in (401, 403):
        raise VTAuthError("invalid api key")
    if response.status_code == 429:
        raise VTRateLimitError("quota exceeded")
    if response.status_code != 200:
        raise VirusTotalError(f"unexpected status {response.status_code}")

    try:
        attributes = response.json()["data"]["attributes"]
    except (KeyError, ValueError) as exc:
        raise VirusTotalError("malformed response") from exc

    stats = attributes.get("last_analysis_stats", {})
    malicious = int(stats.get("malicious", 0))
    suspicious = int(stats.get("suspicious", 0))
    undetected = int(stats.get("undetected", 0))
    harmless = int(stats.get("harmless", 0))
    total = malicious + suspicious + undetected + harmless

    engines = []
    for engine, result in (attributes.get("last_analysis_results") or {}).items():
        category = result.get("category")
        if category in ("malicious", "suspicious"):
            engines.append({
                "engine": engine,
                "result": result.get("result") or category,
            })
    engines.sort(key=lambda e: e["engine"].lower())

    return {
        "status": "found",
        "found": True,
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "undetected": undetected,
        "total_engines": total,
        "flagged_by": engines,
        "permalink": f"https://www.virustotal.com/gui/file/{sha256}",
    }
