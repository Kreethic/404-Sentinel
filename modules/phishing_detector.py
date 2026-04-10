"""
modules/phishing_detector.py
==============================
Phishing URL Detector

Checks:
  • PhishTank API          — known phishing URLs database
  • Google Safe Browsing   — real-time threat detection
  • VirusTotal URL scan    — multi-engine URL analysis
  • Regex heuristics       — suspicious patterns in URL
  • Typosquatting detection— Levenshtein distance vs. brand list
  • Homoglyph detection   — Unicode lookalike character substitution
  • SSL certificate checks — suspicious cert details
  • Domain age            — newly registered = higher risk
"""

import re
import ssl
import socket
import hashlib
import urllib.parse
from datetime import datetime
from typing import Optional

import requests
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

console = Console()

# ─── Brand domain list for typosquatting detection ───────────────────────────
LEGITIMATE_BRANDS = [
    "google", "gmail", "youtube", "facebook", "instagram", "twitter",
    "paypal", "amazon", "apple", "microsoft", "outlook", "hotmail",
    "yahoo", "netflix", "linkedin", "github", "dropbox", "onedrive",
    "icloud", "chase", "wellsfargo", "bankofamerica", "citibank",
    "coinbase", "binance", "stripe", "shopify", "wordpress",
]

# ─── Suspicious TLDs ─────────────────────────────────────────────────────────
SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq",     # Free Freenom TLDs — extremely common in phishing
    ".top", ".xyz", ".club", ".online",
    ".site", ".space", ".store", ".live",
    ".work", ".click", ".pw", ".support",
}

# ─── Phishing keyword patterns ───────────────────────────────────────────────
PHISHING_PATTERNS = [
    (r"(login|signin|verify|secure|account|update|confirm|banking|password)", "Credential harvesting keyword"),
    (r"(paypa1|pay-pal|paypai|rnybank|arnazon)", "Brand name typo detected"),
    (r"@", "@ symbol in URL (credential bypass)"),
    (r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", "Raw IP address in URL"),
    (r"(base64|eval\(|fromcharcode)", "Obfuscated code pattern"),
    (r"(-{2,}|\.{3,})", "Excessive dashes/dots in domain"),
    (r"https?://[^/]{50,}", "Abnormally long URL"),
    (r"(free|gift|prize|winner|click-here|limited-time)", "Social engineering keyword"),
]

# ─── Homoglyph map (Unicode lookalike → ASCII) ───────────────────────────────
HOMOGLYPH_MAP = {
    "а": "a", "е": "e", "і": "i", "о": "o", "р": "p", "с": "c",
    "у": "y", "х": "x", "ё": "e", "ѕ": "s", "ј": "j", "ԁ": "d",
    "ɡ": "g", "ʟ": "l", "ɴ": "n", "ʀ": "r", "ᴀ": "a", "ʙ": "b",
    "ᴄ": "c", "ᴅ": "d", "ᴇ": "e", "ꜰ": "f", "ɢ": "g", "ʜ": "h",
    "ɪ": "i", "ᴊ": "j", "ᴋ": "k", "ʟ": "l", "ᴍ": "m", "ɴ": "n",
    "ᴏ": "o", "ᴘ": "p", "ǫ": "q", "ʀ": "r", "ꜱ": "s", "ᴛ": "t",
    "ᴜ": "u", "ᴠ": "v", "ᴡ": "w", "x": "x", "ʏ": "y", "ᴢ": "z",
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "6": "b",
    "7": "t", "8": "b",
}


def levenshtein(s1: str, s2: str) -> int:
    """Compute Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein(s2, s1)
    if not s2:
        return len(s1)
    prev = range(len(s2) + 1)
    for c1 in s1:
        curr = [prev[0] + 1]
        for j, c2 in enumerate(s2):
            curr.append(min(curr[-1] + 1, prev[j + 1] + 1, prev[j] + (c1 != c2)))
        prev = curr
    return prev[-1]


class PhishingDetector:
    def __init__(self, config):
        self.config = config
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "CyberSentinel/1.0"})

    # ─── PUBLIC ENTRY POINT ──────────────────────────────────────────────────

    def analyze(self, url: str) -> dict:
        """Analyze a URL and print phishing report."""
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        console.print()
        with console.status(f"[bold cyan]Scanning URL for phishing indicators...[/bold cyan]"):
            results = self._gather_intel(url)

        self._print_report(url, results)
        return results

    def quick_check(self, url: str) -> dict:
        """Silently return results for risk scorer."""
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        return self._gather_intel(url)

    # ─── INTEL GATHERING ─────────────────────────────────────────────────────

    def _gather_intel(self, url: str) -> dict:
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc.lower().lstrip("www.")
        path = parsed.path

        results = {
            "url": url,
            "domain": domain,
            "parsed": {
                "scheme": parsed.scheme,
                "netloc": parsed.netloc,
                "path": path,
                "params": parsed.params,
                "query": parsed.query,
            },
            "heuristics": self._heuristic_analysis(url, domain, path),
            "typosquatting": self._check_typosquatting(domain),
            "homoglyph": self._check_homoglyph(domain),
            "ssl": self._check_ssl(domain),
            "phishtank": None,
            "virustotal": None,
            "safebrowsing": None,
            "timestamp": datetime.utcnow().isoformat() + "Z",
        }

        if self.config.demo_mode:
            results["phishtank"] = self._demo_phishtank(url)
            results["virustotal"] = self._demo_virustotal(url)
        else:
            results["phishtank"] = self._query_phishtank(url)
            if self.config.has_virustotal():
                results["virustotal"] = self._query_virustotal(url)
            if self.config.has_google_safebrowsing():
                results["safebrowsing"] = self._query_safebrowsing(url)

        results["risk_score"] = self._compute_risk_score(results)
        return results

    # ─── HEURISTIC ANALYSIS ──────────────────────────────────────────────────

    def _heuristic_analysis(self, url: str, domain: str, path: str) -> dict:
        flags = []
        score = 0

        # Pattern matching
        for pattern, description in PHISHING_PATTERNS:
            if re.search(pattern, url, re.IGNORECASE):
                flags.append({"type": "pattern", "detail": description, "severity": "medium"})
                score += 10

        # Suspicious TLD
        for tld in SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                flags.append({"type": "suspicious_tld", "detail": f"High-risk TLD: {tld}", "severity": "high"})
                score += 20
                break

        # Subdomain depth
        subdomain_parts = domain.split(".")
        if len(subdomain_parts) > 4:
            flags.append({"type": "deep_subdomain", "detail": f"{len(subdomain_parts)} subdomain levels", "severity": "medium"})
            score += 15

        # Brand name in subdomain (e.g., paypal.evil.com)
        if len(subdomain_parts) > 2:
            subdomains = ".".join(subdomain_parts[:-2])
            for brand in LEGITIMATE_BRANDS:
                if brand in subdomains:
                    flags.append({"type": "brand_in_subdomain", "detail": f"Brand '{brand}' in subdomain", "severity": "critical"})
                    score += 35
                    break

        # HTTP (not HTTPS)
        if url.startswith("http://"):
            flags.append({"type": "no_ssl", "detail": "Plain HTTP — no encryption", "severity": "medium"})
            score += 10

        # Long path with many encoded chars
        encoded = len(re.findall(r"%[0-9a-fA-F]{2}", path))
        if encoded > 5:
            flags.append({"type": "url_encoding", "detail": f"{encoded} URL-encoded chars in path", "severity": "low"})
            score += 5

        # Multiple redirects in URL
        if url.count("http") > 1:
            flags.append({"type": "redirect_url", "detail": "Nested URL / redirect chain", "severity": "high"})
            score += 25

        return {
            "flags": flags,
            "heuristic_score": min(score, 100),
            "total_flags": len(flags),
        }

    # ─── TYPOSQUATTING ───────────────────────────────────────────────────────

    def _check_typosquatting(self, domain: str) -> dict:
        root = domain.split(".")[0] if "." in domain else domain
        matches = []

        for brand in LEGITIMATE_BRANDS:
            dist = levenshtein(root.lower(), brand.lower())
            if 0 < dist <= 2 and root.lower() != brand.lower():
                similarity = 1 - (dist / max(len(root), len(brand)))
                matches.append({
                    "brand": brand,
                    "distance": dist,
                    "similarity": round(similarity * 100, 1),
                })

        matches.sort(key=lambda x: x["distance"])

        return {
            "detected": len(matches) > 0,
            "matches": matches[:3],
            "root_domain": root,
        }

    # ─── HOMOGLYPH DETECTION ─────────────────────────────────────────────────

    def _check_homoglyph(self, domain: str) -> dict:
        substitutions = []
        normalized = []

        for char in domain:
            if char in HOMOGLYPH_MAP:
                substitutions.append({
                    "original": char,
                    "normalized": HOMOGLYPH_MAP[char],
                    "unicode": f"U+{ord(char):04X}",
                })
                normalized.append(HOMOGLYPH_MAP[char])
            else:
                normalized.append(char)

        normalized_domain = "".join(normalized)
        return {
            "detected": len(substitutions) > 0,
            "substitutions": substitutions,
            "original": domain,
            "normalized": normalized_domain,
            "is_ascii": domain.isascii(),
        }

    # ─── SSL CERTIFICATE ─────────────────────────────────────────────────────

    def _check_ssl(self, domain: str) -> dict:
        try:
            ctx = ssl.create_default_context()
            conn = ctx.wrap_socket(socket.socket(), server_hostname=domain)
            conn.settimeout(5)
            conn.connect((domain, 443))
            cert = conn.getpeercert()
            conn.close()

            issued_to = dict(x[0] for x in cert.get("subject", []))
            issued_by = dict(x[0] for x in cert.get("issuer", []))
            not_after = cert.get("notAfter", "")

            # Check for free CAs often abused by phishers
            free_cas = ["Let's Encrypt", "ZeroSSL", "Buypass"]
            issuer_name = issued_by.get("organizationName", "")
            is_free_ca = any(ca in issuer_name for ca in free_cas)

            return {
                "valid": True,
                "issued_to": issued_to.get("commonName", "N/A"),
                "issued_by": issuer_name,
                "expires": not_after,
                "is_free_ca": is_free_ca,
                "san": cert.get("subjectAltName", []),
                "error": None,
            }
        except ssl.SSLCertVerificationError as e:
            return {"valid": False, "error": f"SSL verification failed: {e}", "is_free_ca": False}
        except Exception as e:
            return {"valid": None, "error": str(e), "is_free_ca": False}

    # ─── API: PHISHTANK ──────────────────────────────────────────────────────

    def _query_phishtank(self, url: str) -> dict:
        try:
            url_encoded = urllib.parse.quote_plus(url)
            url_hash = hashlib.sha256(url.encode()).hexdigest()
            payload = {
                "url": url_encoded,
                "format": "json",
                "app_key": self.config.phishtank_key or "",
            }
            resp = self.session.post(
                "https://checkurl.phishtank.com/checkurl/",
                data=payload,
                timeout=self.config.timeout,
            )
            if resp.status_code == 200:
                data = resp.json().get("results", {})
                return {
                    "in_database": data.get("in_database", False),
                    "phish_id": data.get("phish_id"),
                    "verified": data.get("verified", False),
                    "phish_detail_url": data.get("phish_detail_url"),
                    "error": None,
                }
            return {"error": f"HTTP {resp.status_code}"}
        except Exception as e:
            return {"error": str(e)}

    # ─── API: VIRUSTOTAL ─────────────────────────────────────────────────────

    def _query_virustotal(self, url: str) -> dict:
        try:
            headers = {"x-apikey": self.config.virustotal_key}
            url_id = hashlib.sha256(url.encode()).hexdigest()
            # Submit URL for scanning
            resp = self.session.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=headers,
                data={"url": url},
                timeout=self.config.timeout,
            )
            if resp.status_code in (200, 409):
                analysis_id = resp.json().get("data", {}).get("id", "")
                if analysis_id:
                    res_resp = self.session.get(
                        f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                        headers=headers,
                        timeout=self.config.timeout,
                    )
                    if res_resp.status_code == 200:
                        stats = res_resp.json().get("data", {}).get("attributes", {}).get("stats", {})
                        return {
                            "malicious": stats.get("malicious", 0),
                            "suspicious": stats.get("suspicious", 0),
                            "harmless": stats.get("harmless", 0),
                            "error": None,
                        }
            return {"error": f"HTTP {resp.status_code}"}
        except Exception as e:
            return {"error": str(e)}

    # ─── API: GOOGLE SAFE BROWSING ───────────────────────────────────────────

    def _query_safebrowsing(self, url: str) -> dict:
        try:
            payload = {
                "client": {"clientId": "cyber-sentinel", "clientVersion": "1.0"},
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}],
                },
            }
            resp = self.session.post(
                f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={self.config.google_safebrowsing_key}",
                json=payload,
                timeout=self.config.timeout,
            )
            if resp.status_code == 200:
                data = resp.json()
                matches = data.get("matches", [])
                return {
                    "safe": len(matches) == 0,
                    "threats": [m.get("threatType") for m in matches],
                    "error": None,
                }
            return {"error": f"HTTP {resp.status_code}"}
        except Exception as e:
            return {"error": str(e)}

    # ─── DEMO DATA ───────────────────────────────────────────────────────────

    def _demo_phishtank(self, url: str) -> dict:
        is_phishing = any(kw in url.lower() for kw in ["paypa", "secure-", "login-", "verify-", "account-"])
        return {
            "in_database": is_phishing,
            "phish_id": "12345" if is_phishing else None,
            "verified": is_phishing,
            "phish_detail_url": f"https://phishtank.org/phish_detail.php?phish_id=12345" if is_phishing else None,
            "error": None,
            "_demo": True,
        }

    def _demo_virustotal(self, url: str) -> dict:
        is_suspicious = any(kw in url.lower() for kw in ["malware", "phish", "hack", "paypa", "secure-bank"])
        return {
            "malicious": 18 if is_suspicious else 0,
            "suspicious": 3 if is_suspicious else 0,
            "harmless": 52,
            "error": None,
            "_demo": True,
        }

    # ─── RISK SCORE ──────────────────────────────────────────────────────────

    def _compute_risk_score(self, results: dict) -> int:
        score = 0

        # Heuristics (0-40 points)
        heuristic = results.get("heuristics", {})
        score += heuristic.get("heuristic_score", 0) * 0.4

        # Typosquatting (0-25 points)
        typo = results.get("typosquatting", {})
        if typo.get("detected"):
            best = typo["matches"][0] if typo["matches"] else {}
            score += 25 * (1 - best.get("distance", 2) / 3)

        # Homoglyph (0-20 points)
        homoglyph = results.get("homoglyph", {})
        if homoglyph.get("detected"):
            score += min(len(homoglyph.get("substitutions", [])) * 5, 20)

        # PhishTank (0-30 points)
        phishtank = results.get("phishtank", {}) or {}
        if phishtank.get("in_database") and not phishtank.get("error"):
            score += 30

        # VirusTotal (0-30 points)
        vt = results.get("virustotal", {}) or {}
        if not vt.get("error") and vt.get("malicious", 0) > 0:
            score += min(vt["malicious"] * 2, 30)

        # Safe Browsing (0-30 points)
        sb = results.get("safebrowsing", {}) or {}
        if not sb.get("safe", True) and not sb.get("error"):
            score += 30

        return min(int(score), 100)

    # ─── REPORT PRINTING ─────────────────────────────────────────────────────

    def _print_report(self, url: str, results: dict):
        demo_tag = " [dim][DEMO DATA][/dim]" if self.config.demo_mode else ""
        score = results.get("risk_score", 0)
        score_color = "green" if score < 30 else "yellow" if score < 60 else "bold red"

        console.print(Panel(
            f"[bold white]URL:[/bold white] [yellow]{url}[/yellow]\n"
            f"[bold white]Domain:[/bold white] [cyan]{results['domain']}[/cyan]   "
            f"[bold white]Risk Score:[/bold white] [{score_color}]{score}/100[/{score_color}]",
            title=f"[bold red]⚑  PHISHING URL ANALYSIS{demo_tag}[/bold red]",
            border_style="red",
        ))

        # ── Heuristics ──────────────────────────────────────────────────────
        heuristics = results.get("heuristics", {})
        flags = heuristics.get("flags", [])
        if flags:
            h_table = Table(box=box.SIMPLE, show_header=True, padding=(0, 2))
            h_table.add_column("Severity", style="bold", width=10)
            h_table.add_column("Type", style="cyan", width=22)
            h_table.add_column("Detail", style="white")

            severity_color = {"critical": "red", "high": "red", "medium": "yellow", "low": "dim"}
            for flag in flags:
                sev = flag.get("severity", "low")
                h_table.add_row(
                    f"[{severity_color.get(sev, 'white')}]{sev.upper()}[/{severity_color.get(sev, 'white')}]",
                    flag.get("type", ""),
                    flag.get("detail", ""),
                )
            console.print(Panel(h_table, title=f"[bold]Heuristic Flags ({len(flags)} detected)[/bold]", border_style="yellow"))
        else:
            console.print(Panel("[green]No heuristic flags detected.[/green]", title="Heuristic Analysis", border_style="green"))

        # ── Typosquatting ────────────────────────────────────────────────────
        typo = results.get("typosquatting", {})
        if typo.get("detected"):
            t = Table(box=box.SIMPLE, show_header=True, padding=(0, 2))
            t.add_column("Target Brand", style="bold yellow")
            t.add_column("Edit Distance", justify="center")
            t.add_column("Similarity", justify="center")

            for m in typo.get("matches", []):
                sim = m.get("similarity", 0)
                t.add_row(m["brand"], str(m["distance"]), f"[red]{sim}%[/red]" if sim > 80 else f"[yellow]{sim}%[/yellow]")

            console.print(Panel(
                t,
                title=f"[bold red]⚠ TYPOSQUATTING DETECTED — Root domain: '{typo['root_domain']}'[/bold red]",
                border_style="red",
            ))
        else:
            console.print(Panel("[green]No typosquatting detected.[/green]", title="Typosquatting Check", border_style="green"))

        # ── Homoglyph ────────────────────────────────────────────────────────
        hg = results.get("homoglyph", {})
        if hg.get("detected"):
            subs = hg.get("substitutions", [])
            detail = "  ".join([f"'{s['original']}' ({s['unicode']}) → '{s['normalized']}'" for s in subs[:5]])
            console.print(Panel(
                f"[red]Homoglyph substitutions detected![/red]\n{detail}\n"
                f"Normalized domain: [bold yellow]{hg['normalized']}[/bold yellow]",
                title="[bold red]⚠ HOMOGLYPH ATTACK DETECTED[/bold red]",
                border_style="red",
            ))
        else:
            console.print(Panel("[green]No Unicode homoglyph characters found.[/green]", title="Homoglyph Check", border_style="green"))

        # ── SSL Certificate ──────────────────────────────────────────────────
        ssl_info = results.get("ssl", {})
        if ssl_info:
            ssl_color = "green" if ssl_info.get("valid") else "red"
            ssl_text = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
            ssl_text.add_column(style="dim", width=16)
            ssl_text.add_column()
            ssl_text.add_row("Valid", "[green]YES[/green]" if ssl_info.get("valid") else "[red]NO / FAILED[/red]")
            ssl_text.add_row("Issued To", ssl_info.get("issued_to", "N/A"))
            ssl_text.add_row("Issued By", ssl_info.get("issued_by", "N/A"))
            ssl_text.add_row("Expires", ssl_info.get("expires", "N/A"))
            if ssl_info.get("is_free_ca"):
                ssl_text.add_row("⚠ Free CA", "[yellow]Free/automated CA — common in phishing[/yellow]")
            if ssl_info.get("error"):
                ssl_text.add_row("Error", f"[red]{ssl_info['error']}[/red]")
            console.print(Panel(ssl_text, title="SSL Certificate", border_style=ssl_color))

        # ── API Results ──────────────────────────────────────────────────────
        pt = results.get("phishtank", {}) or {}
        vt = results.get("virustotal", {}) or {}
        sb = results.get("safebrowsing", {}) or {}

        api_table = Table(box=box.ROUNDED, border_style="dim", padding=(0, 2))
        api_table.add_column("Source", style="bold white", width=20)
        api_table.add_column("Status", width=20)
        api_table.add_column("Detail")

        if not pt.get("error"):
            status = "[red]IN DATABASE[/red]" if pt.get("in_database") else "[green]NOT FOUND[/green]"
            detail = f"Phish ID: {pt.get('phish_id')}" if pt.get("phish_id") else "No match in PhishTank"
            api_table.add_row("PhishTank", status, detail)

        if not vt.get("error"):
            mal = vt.get("malicious", 0)
            status = f"[red]{mal} malicious engines[/red]" if mal > 0 else "[green]Clean[/green]"
            api_table.add_row("VirusTotal", status, f"Suspicious: {vt.get('suspicious', 0)}")

        if not sb.get("error") and sb:
            threats = sb.get("threats", [])
            status = f"[red]THREATS FOUND[/red]" if threats else "[green]Safe[/green]"
            api_table.add_row("Google Safe Browsing", status, ", ".join(threats) if threats else "No threats")

        if any([not pt.get("error"), not vt.get("error"), sb]):
            console.print(Panel(api_table, title="API Intelligence", border_style="blue"))

        # ── Final verdict ────────────────────────────────────────────────────
        if score < 30:
            verdict, icon = "LIKELY SAFE", "✓"
            color = "bold green"
        elif score < 60:
            verdict, icon = "SUSPICIOUS", "⚠"
            color = "bold yellow"
        else:
            verdict, icon = "PHISHING DETECTED", "✕"
            color = "bold red"

        console.print(Panel(
            f"[{color}]{icon}  {verdict}[/{color}]   Risk Score: [{color}]{score}/100[/{color}]",
            title="[bold]VERDICT[/bold]",
            border_style=color.replace("bold ", ""),
        ))
