"""
config.py — API Keys & Configuration
=====================================
Set API keys via environment variables (recommended) or directly here.

Environment Variables:
  ABUSEIPDB_KEY      → https://www.abuseipdb.com/api
  VIRUSTOTAL_KEY     → https://www.virustotal.com/gui/my-apikey
  OTX_KEY            → https://otx.alienvault.com/ → API Key
  GOOGLE_SAFEBROWSING_KEY → https://developers.google.com/safe-browsing
"""

import os
from rich.console import Console

console = Console()

# ─── DEMO MODE DATA ───────────────────────────────────────────────────────────
# When no API keys are present, these mock responses are used for demonstration.
DEMO_MODE_IPS = {
    "1.1.1.1": {"abuse_score": 0, "country": "AU", "isp": "Cloudflare", "reports": 0, "tags": []},
    "185.220.101.45": {
        "abuse_score": 95,
        "country": "DE",
        "isp": "Tor Exit Node",
        "reports": 3847,
        "tags": ["Tor Exit Node", "Botnet", "Hacking"],
    },
    "192.168.1.1": {"abuse_score": 0, "country": "Private", "isp": "Private", "reports": 0, "tags": []},
}

DEMO_MODE_URLS = {
    "paypa1.com": {"phishing": True, "score": 95, "categories": ["Phishing", "Typosquatting"]},
    "google.com": {"phishing": False, "score": 0, "categories": []},
    "secure-bankofamerica-login.tk": {"phishing": True, "score": 98, "categories": ["Phishing", "Brand Impersonation"]},
}


class Config:
    def __init__(self):
        # AbuseIPDB
        self.abuseipdb_key = os.getenv("ABUSEIPDB_KEY", "dca62c0a75ef27d2c274b99ce7af0017c8d0de7c69d53a93ac453a8635f8665e182e1849322b9935")

        # VirusTotal
        self.virustotal_key = os.getenv("VIRUSTOTAL_KEY", "93ef95dcea60765f55ce2aad548c7a2d9c3d749ccb628fbb8c4a20f871374d4c")

        # AlienVault OTX
        self.otx_key = os.getenv("OTX_KEY", "89aeef520330d20c9506ab1b785ad6870c9f3e0659ad9bcb35c62bf42df2372b")

        # Google Safe Browsing
        self.google_safebrowsing_key = os.getenv("GOOGLE_SAFEBROWSING_KEY", "AIzaSyDjLgau_tzBFJMbji1qgu4uV25F0ae5t5k")

        # PhishTank (no auth required, but key gives higher rate limits)
        self.phishtank_key = os.getenv("PHISHTANK_KEY", "")

        # Settings
        self.timeout = int(os.getenv("CS_TIMEOUT", "10"))
        self.max_retries = int(os.getenv("CS_MAX_RETRIES", "3"))
        self.demo_mode = False

    def validate(self) -> bool:
        """Returns True if at least one API key is configured."""
        keys = [
            self.abuseipdb_key,
            self.virustotal_key,
            self.otx_key,
            self.google_safebrowsing_key,
        ]
        has_keys = any(k for k in keys)
        if not has_keys:
            self.demo_mode = True
        return has_keys

    def has_abuseipdb(self) -> bool:
        return bool(self.abuseipdb_key)

    def has_virustotal(self) -> bool:
        return bool(self.virustotal_key)

    def has_otx(self) -> bool:
        return bool(self.otx_key)

    def has_google_safebrowsing(self) -> bool:
        return bool(self.google_safebrowsing_key)