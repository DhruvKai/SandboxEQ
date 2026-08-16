"""Shared helpers for locating and safely reading/writing config.env.

Used by both hash_lookup.py (reader) and app.py (reader + writer) so the
CLI/backend and the Settings tab always agree on where config.env lives,
including when running as a frozen PyInstaller EXE.
"""

import os
import re
import sys
import tempfile

from dotenv import dotenv_values

# (env_var, service_key, display_label, groups) - service_key matches
# HashLookupTool.apis / URLLookupTool.apis dict keys / the results card keys
# used throughout templates/index.html. `groups` is a tuple of ("hash",
# "url") saying which Settings sub-tab(s) the key should show up under -
# several providers (VirusTotal, MetaDefender, OTX, MalwareBazaar/URLhaus,
# Hybrid Analysis, Triage) use the same key to unlock both a hash-scanning
# and a URL-scanning provider class, so they appear in both groups.
KNOWN_KEYS = [
    ("VT_API_KEY", "virustotal", "VirusTotal", ("hash", "url")),
    ("METADEFENDER_API_KEY", "metadefender", "MetaDefender", ("hash", "url")),
    ("OTX_API_KEY", "otx", "OTX AlienVault", ("hash", "url")),
    ("MB_API_KEY", "malwarebazaar", "MalwareBazaar / URLhaus", ("hash", "url")),
    ("THREATFOX_API_KEY", "threatfox", "ThreatFox", ("hash",)),
    ("HYBRID_API_KEY", "hybrid_analysis", "Hybrid Analysis", ("hash", "url")),
    # "url" deliberately not in groups here - Triage's free/community tier
    # rejects URL submissions (confirmed: 401 on a key that submits files
    # fine), so it's hash/file-scanning only. See url_lookup.py's note where
    # TriageURLAPI used to be.
    ("TRIAGE_API_KEY", "triage_sandbox", "Triage Sandbox", ("hash",)),
    # No Google Safe Browsing entry - its free tier is licensed for
    # non-commercial use only, not appropriate for a corporate BU tool.
    # See url_lookup.py's note where SafeBrowsingAPI used to be.
    # No OpenPhish entry here - its community feed needs no key (see url_lookup.py's OpenPhishAPI).
    ("IPQS_API_KEY", "ipqualityscore", "IPQualityScore", ("url",)),
    ("URLSCAN_API_KEY", "urlscan", "urlscan.io", ("url",)),
    ("CHECKPHISH_API_KEY", "checkphish", "CheckPhish", ("url",)),
    ("ABUSEIPDB_API_KEY", "hosting_reputation", "AbuseIPDB (hosting reputation)", ("url",)),
]

_KEY_NAMES = [env_var for env_var, _, _, _ in KNOWN_KEYS]

_TEMPLATE = """# SandBoxEQ - API Configuration
# Fill these in from the Settings tab, or edit this file directly.

# VirusTotal API Key - https://www.virustotal.com/gui/join-us
VT_API_KEY=

# MetaDefender API Key - https://metadefender.com/
METADEFENDER_API_KEY=

# AlienVault OTX API Key - https://otx.alienvault.com/
OTX_API_KEY=

# MalwareBazaar API Key (Auth-Key) - https://auth.abuse.ch/
MB_API_KEY=

# ThreatFox API Key (same Auth-Key as MalwareBazaar) - https://auth.abuse.ch/
THREATFOX_API_KEY=

# Hybrid Analysis API Key - https://www.hybrid-analysis.com/
HYBRID_API_KEY=

# Triage Sandbox API Key - https://tria.ge/
TRIAGE_API_KEY=

# --- URL scanning ---

# (No key for Google Safe Browsing - deliberately not integrated, see config_store.py's KNOWN_KEYS comment.)

# (No key for OpenPhish - its community feed at openphish.com/feed.txt is open, no signup needed.)

# IPQualityScore API Key - https://www.ipqualityscore.com/
IPQS_API_KEY=

# urlscan.io API Key - https://urlscan.io/
URLSCAN_API_KEY=

# CheckPhish (Bolster) API Key - https://checkphish.ai/
CHECKPHISH_API_KEY=

# AbuseIPDB API Key (hosting IP reputation) - https://www.abuseipdb.com/register
ABUSEIPDB_API_KEY=
"""

_KEY_LINE_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\s*=")


def get_config_path() -> str:
    """Directory containing the running EXE (frozen) or this script (dev)."""
    if getattr(sys, "frozen", False):
        base_dir = os.path.dirname(sys.executable)
    else:
        base_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base_dir, "config.env")


def ensure_config_env_exists() -> str:
    """Create a blank config.env template next to the app if none exists."""
    path = get_config_path()
    if not os.path.exists(path):
        _atomic_write(path, _TEMPLATE)
    return path


def read_masked_keys() -> list:
    """Return which known keys are configured, without exposing values."""
    path = ensure_config_env_exists()
    values = dotenv_values(path)

    result = []
    for env_var, service_key, label, groups in KNOWN_KEYS:
        value = values.get(env_var)
        result.append({
            "env_var": env_var,
            "service": service_key,
            "label": label,
            "groups": list(groups),
            "configured": bool(value and value.strip()),
        })
    return result


def write_keys(updates: dict) -> list:
    """Write only the provided non-empty keys, preserving all other lines.

    Returns the list of env var names actually changed/added.
    """
    path = ensure_config_env_exists()

    sanitized = {}
    for env_var in _KEY_NAMES:
        raw = updates.get(env_var)
        if raw is None:
            continue
        value = raw.strip().replace("\n", "").replace("\r", "")
        if value:
            sanitized[env_var] = value

    if not sanitized:
        return []

    with open(path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    remaining = dict(sanitized)
    new_lines = []
    for line in lines:
        match = _KEY_LINE_RE.match(line)
        key = match.group(1) if match else None
        if key in remaining:
            new_lines.append(f"{key}={remaining.pop(key)}\n")
        else:
            new_lines.append(line)

    for key, value in remaining.items():
        new_lines.append(f"{key}={value}\n")

    _atomic_write(path, "".join(new_lines))
    return list(sanitized.keys())


def _atomic_write(path: str, content: str) -> None:
    directory = os.path.dirname(path) or "."
    fd, tmp_path = tempfile.mkstemp(dir=directory, prefix=".config_env_", text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
        os.replace(tmp_path, path)
    except BaseException:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        raise
