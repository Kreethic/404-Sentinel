"""
modules/ip_reputation.py
=========================
IP & Domain Reputation Checker

APIs used:
  • AbuseIPDB   — abuse confidence score, reports, categories
  • VirusTotal  — malicious votes from 70+ AV engines
  • AlienVault OTX — threat intel pulses, geolocation, tags
  • Fallback    — DNS + WHOIS basic checks (no API key needed)
"""

import re
import socket
import ipaddress
from datetime import datetime
from typing import Optional

import requests
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box
from rich.columns import Columns

console = Console()

# AbuseIPDB category codes → human readable
ABUSE_CATEGORIES = {
    1: "DNS Compromise",
    2: "DNS Poisoning",
    3: "Fraud Orders",
    4: "DDoS Attack",
    5: "FTP Brute-Force",
    6: "Ping of Death",
    7: "Phishing",
    8: "Fraud VoIP",
    9: "Open Proxy",
    10: "Web Spam",
    11: "Email Spam",
    12: "Blog Spam",
    13: "VPN IP",
    14: "Port Scan",
    15: "Hacking",
    16: "SQL Injection",
    17: "Spoofing",
    18: "Brute Force",
    19: "Bad Web Bot",
    20: "Exploited Host",
    21: "Web App Attack",
    22: "SSH Brute Force",
    23: "IoT Targeted",
}


class IPReputationChecker:
    def __init__(self, config):
        self.config = config
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "CyberSentinel/1.0"})

    # ─── PUBLIC ENTRY POINT ──────────────────────────────────────────────────

    def analyze(self, target: str) -> dict:
        """Analyze an IP address or domain and print a full report."""
        target_type = self._detect_type(target)
        console.print()

        with console.status(f"[bold cyan]Analyzing {target_type}: [yellow]{target}[/yellow]...[/bold cyan]"):
            results = self._gather_intel(target, target_type)

        self._print_report(target, target_type, results)
        return results

    def quick_check(self, target: str) -> dict:
        """Return a simplified dict for use by the risk scorer (no printing)."""
        target_type = self._detect_type(target)
        return self._gather_intel(target, target_type)

    # ─── DETECTION ───────────────────────────────────────────────────────────

    def _detect_type(self, target: str) -> str:
        target = target.strip()
        try:
            ipaddress.ip_address(target)
            return "IP"
        except ValueError:
            pass
        if re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", target):
            return "Domain"
        return "Unknown"

    # ─── INTEL GATHERING ─────────────────────────────────────────────────────

    def _gather_intel(self, target: str, target_type: str) -> dict:
        results = {
            "target": target,
            "type": target_type,
            "abuseipdb": None,
            "virustotal": None,
            "otx": None,
            "basic": self._basic_lookup(target, target_type),
            "timestamp": datetime.utcnow().isoformat() + "Z",
        }

        # Resolve domain to IP for IP-based lookups
        ip_target = target
        if target_type == "Domain":
            ip_target = self._resolve_domain(target)

        if self.config.demo_mode:
            results["abuseipdb"] = self._demo_abuseipdb(target)
            results["virustotal"] = self._demo_virustotal(target)
            results["otx"] = self._demo_otx(target)
        else:
            if self.config.has_abuseipdb() and ip_target:
                results["abuseipdb"] = self._query_abuseipdb(ip_target)
            if self.config.has_virustotal():
                results["virustotal"] = self._query_virustotal(target, target_type)
            if self.config.has_otx():
                results["otx"] = self._query_otx(target, target_type)

        return results

    def _resolve_domain(self, domain: str) -> Optional[str]:
        try:
            return socket.gethostbyname(domain)
        except Exception:
            return None

    def _basic_lookup(self, target: str, target_type: str) -> dict:
        info = {}
        if target_type == "IP":
            try:
                ip = ipaddress.ip_address(target)
                info["is_private"] = ip.is_private
                info["is_loopback"] = ip.is_loopback
                info["is_multicast"] = ip.is_multicast
                info["version"] = f"IPv{ip.version}"
                info["resolved_hostname"] = self._reverse_dns(target)
            except Exception:
                pass
        elif target_type == "Domain":
            info["resolved_ip"] = self._resolve_domain(target)
            if info["resolved_ip"]:
                info["is_private_ip"] = ipaddress.ip_address(info["resolved_ip"]).is_private
        return info

    def _reverse_dns(self, ip: str) -> Optional[str]:
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return None

    # ─── API: ABUSEIPDB ──────────────────────────────────────────────────────

    def _query_abuseipdb(self, ip: str) -> dict:
        try:
            resp = self.session.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": self.config.abuseipdb_key, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
                timeout=self.config.timeout,
            )
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                return {
                    "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                    "total_reports": data.get("totalReports", 0),
                    "distinct_users": data.get("numDistinctUsers", 0),
                    "country_code": data.get("countryCode", "N/A"),
                    "isp": data.get("isp", "N/A"),
                    "domain": data.get("domain", "N/A"),
                    "usage_type": data.get("usageType", "N/A"),
                    "is_tor": data.get("isTor", False),
                    "is_whitelisted": data.get("isWhitelisted", False),
                    "categories": [
                        ABUSE_CATEGORIES.get(c, str(c))
                        for c in (data.get("reports") or [{}])[0].get("categories", [])
                    ] if data.get("reports") else [],
                    "last_reported": data.get("lastReportedAt", "N/A"),
                    "error": None,
                }
            return {"error": f"HTTP {resp.status_code}: {resp.text[:100]}"}
        except Exception as e:
            return {"error": str(e)}

    # ─── API: VIRUSTOTAL ─────────────────────────────────────────────────────

    def _query_virustotal(self, target: str, target_type: str) -> dict:
        try:
            headers = {"x-apikey": self.config.virustotal_key}
            if target_type == "IP":
                url = f"https://www.virustotal.com/api/v3/ip_addresses/{target}"
            else:
                url = f"https://www.virustotal.com/api/v3/domains/{target}"

            resp = self.session.get(url, headers=headers, timeout=self.config.timeout)
            if resp.status_code == 200:
                data = resp.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                return {
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                    "total_engines": sum(stats.values()),
                    "reputation": data.get("reputation", 0),
                    "categories": list(data.get("categories", {}).values()),
                    "tags": data.get("tags", []),
                    "country": data.get("country", "N/A"),
                    "as_owner": data.get("as_owner", "N/A"),
                    "error": None,
                }
            return {"error": f"HTTP {resp.status_code}"}
        except Exception as e:
            return {"error": str(e)}

    # ─── API: ALIENVAULT OTX ─────────────────────────────────────────────────

    def _query_otx(self, target: str, target_type: str) -> dict:
        try:
            headers = {"X-OTX-API-KEY": self.config.otx_key}
            ioc_type = "IPv4" if target_type == "IP" else "domain"
            base = f"https://otx.alienvault.com/api/v1/indicators/{ioc_type}/{target}"

            general = self.session.get(f"{base}/general", headers=headers, timeout=self.config.timeout).json()
            geo = self.session.get(f"{base}/geo", headers=headers, timeout=self.config.timeout).json()

            return {
                "pulse_count": general.get("pulse_info", {}).get("count", 0),
                "malware_families": general.get("pulse_info", {}).get("references", [])[:3],
                "tags": general.get("pulse_info", {}).get("tags", [])[:8],
                "country": geo.get("country_name", "N/A"),
                "city": geo.get("city", "N/A"),
                "asn": geo.get("asn", "N/A"),
                "reputation": general.get("reputation", 0),
                "related_urls": general.get("url_list", [])[:3],
                "error": None,
            }
        except Exception as e:
            return {"error": str(e)}

    # ─── DEMO DATA ───────────────────────────────────────────────────────────

    def _demo_abuseipdb(self, target: str) -> dict:
        from config import DEMO_MODE_IPS
        demo = DEMO_MODE_IPS.get(target, {
            "abuse_score": 42,
            "country": "RU",
            "isp": "Unknown ISP",
            "reports": 127,
            "tags": ["Port Scan", "Brute Force"],
        })
        return {
            "abuse_confidence_score": demo.get("abuse_score", 42),
            "total_reports": demo.get("reports", 127),
            "distinct_users": demo.get("reports", 127) // 3,
            "country_code": demo.get("country", "XX"),
            "isp": demo.get("isp", "Demo ISP"),
            "domain": target if "." in target else "N/A",
            "usage_type": "Data Center/Web Hosting/Transit",
            "is_tor": demo.get("abuse_score", 0) > 80,
            "is_whitelisted": demo.get("abuse_score", 0) == 0,
            "categories": demo.get("tags", ["Port Scan"]),
            "last_reported": "2025-01-15T08:23:11+00:00",
            "error": None,
            "_demo": True,
        }

    def _demo_virustotal(self, target: str) -> dict:
        score = 5 if "google" in target or target == "1.1.1.1" else 12
        return {
            "malicious": score,
            "suspicious": 2,
            "harmless": 58,
            "undetected": 10,
            "total_engines": 70,
            "reputation": -score * 2,
            "categories": ["malware", "botnet"] if score > 8 else [],
            "tags": ["scanner", "proxy"] if score > 5 else [],
            "country": "DE",
            "as_owner": "Demo AS Organization",
            "error": None,
            "_demo": True,
        }

    def _demo_otx(self, target: str) -> dict:
        pulses = 47 if "malicious" in target.lower() else 3
        return {
            "pulse_count": pulses,
            "malware_families": ["Mirai", "Emotet"] if pulses > 10 else [],
            "tags": ["botnet", "scanner", "ssh-brute-force"] if pulses > 10 else [],
            "country": "China",
            "city": "Hangzhou",
            "asn": "AS4134 CHINANET-BACKBONE",
            "reputation": -pulses,
            "related_urls": [],
            "error": None,
            "_demo": True,
        }

    # ─── REPORTING ───────────────────────────────────────────────────────────

    def _print_report(self, target: str, target_type: str, results: dict):
        demo_tag = " [dim][DEMO DATA][/dim]" if self.config.demo_mode else ""

        # ── Header ──────────────────────────────────────────────────────────
        header = Table.grid(padding=(0, 2))
        header.add_column()
        header.add_column()
        header.add_row(
            f"[bold white]Target:[/bold white] [bold yellow]{target}[/bold yellow]",
            f"[bold white]Type:[/bold white] [cyan]{target_type}[/cyan]",
        )
        header.add_row(
            f"[bold white]Scanned:[/bold white] [dim]{results['timestamp']}[/dim]",
            f"[bold white]Mode:[/bold white] {'[yellow]DEMO[/yellow]' if self.config.demo_mode else '[green]LIVE[/green]'}",
        )

        console.print(Panel(header, title=f"[bold red]⚑  IP/DOMAIN REPUTATION REPORT{demo_tag}[/bold red]", border_style="red"))

        # ── Basic Info ──────────────────────────────────────────────────────
        basic = results.get("basic", {})
        if basic:
            b_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
            b_table.add_column(style="dim", width=20)
            b_table.add_column(style="bold white")
            for k, v in basic.items():
                k_fmt = k.replace("_", " ").title()
                v_fmt = str(v) if v is not None else "N/A"
                b_table.add_row(k_fmt, v_fmt)
            console.print(Panel(b_table, title="[cyan]Basic Lookup[/cyan]", border_style="dim"))

        # ── AbuseIPDB ───────────────────────────────────────────────────────
        abuse = results.get("abuseipdb")
        if abuse and not abuse.get("error"):
            self._print_abuseipdb_card(abuse)

        # ── VirusTotal ──────────────────────────────────────────────────────
        vt = results.get("virustotal")
        if vt and not vt.get("error"):
            self._print_virustotal_card(vt)

        # ── OTX ─────────────────────────────────────────────────────────────
        otx = results.get("otx")
        if otx and not otx.get("error"):
            self._print_otx_card(otx)

        # ── Overall verdict ─────────────────────────────────────────────────
        self._print_verdict(results)

    def _print_abuseipdb_card(self, data: dict):
        score = data.get("abuse_confidence_score", 0)
        score_color = "green" if score < 25 else "yellow" if score < 60 else "bold red"
        bar = self._score_bar(score)

        t = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
        t.add_column(style="dim", width=22)
        t.add_column(style="white")

        t.add_row("Abuse Score", f"[{score_color}]{score}/100[/{score_color}]  {bar}")
        t.add_row("Total Reports", str(data.get("total_reports", 0)))
        t.add_row("Distinct Users", str(data.get("distinct_users", 0)))
        t.add_row("Country", data.get("country_code", "N/A"))
        t.add_row("ISP", data.get("isp", "N/A"))
        t.add_row("Usage Type", data.get("usage_type", "N/A"))
        t.add_row("Is Tor Node", "[red]YES[/red]" if data.get("is_tor") else "[green]NO[/green]")
        t.add_row("Whitelisted", "[green]YES[/green]" if data.get("is_whitelisted") else "[dim]NO[/dim]")

        cats = data.get("categories", [])
        if cats:
            t.add_row("Attack Categories", "[red]" + "  •  ".join(cats) + "[/red]")

        last_rep = data.get("last_reported", "N/A")
        t.add_row("Last Reported", last_rep)

        console.print(Panel(t, title="[bold]AbuseIPDB[/bold]", border_style="yellow"))

    def _print_virustotal_card(self, data: dict):
        mal = data.get("malicious", 0)
        sus = data.get("suspicious", 0)
        total = data.get("total_engines", 70)
        clean = data.get("harmless", 0)

        verdict_color = "green" if mal == 0 else "yellow" if mal < 5 else "bold red"

        t = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
        t.add_column(style="dim", width=22)
        t.add_column(style="white")

        t.add_row("Malicious Engines", f"[{verdict_color}]{mal}/{total}[/{verdict_color}]")
        t.add_row("Suspicious", f"[yellow]{sus}[/yellow]")
        t.add_row("Harmless", f"[green]{clean}[/green]")
        t.add_row("Reputation", str(data.get("reputation", "N/A")))
        t.add_row("Country", data.get("country", "N/A"))
        t.add_row("AS Owner", data.get("as_owner", "N/A"))

        cats = data.get("categories", [])
        if cats:
            t.add_row("Categories", "[red]" + "  •  ".join(set(cats)) + "[/red]")

        tags = data.get("tags", [])
        if tags:
            t.add_row("Tags", "[yellow]" + "  ".join(f"#{t}" for t in tags) + "[/yellow]")

        console.print(Panel(t, title="[bold]VirusTotal[/bold]", border_style="blue"))

    def _print_otx_card(self, data: dict):
        pulses = data.get("pulse_count", 0)
        pulse_color = "green" if pulses == 0 else "yellow" if pulses < 10 else "bold red"

        t = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
        t.add_column(style="dim", width=22)
        t.add_column(style="white")

        t.add_row("Threat Pulses", f"[{pulse_color}]{pulses}[/{pulse_color}]")
        t.add_row("Country", data.get("country", "N/A"))
        t.add_row("City", data.get("city", "N/A"))
        t.add_row("ASN", data.get("asn", "N/A"))

        families = data.get("malware_families", [])
        if families:
            t.add_row("Malware Families", "[red]" + "  ".join(families) + "[/red]")

        tags = data.get("tags", [])
        if tags:
            t.add_row("Tags", "[yellow]" + "  ".join(f"#{tg}" for tg in tags) + "[/yellow]")

        console.print(Panel(t, title="[bold]AlienVault OTX[/bold]", border_style="magenta"))

    def _print_verdict(self, results: dict):
        score = self._compute_risk_score(results)
        if score < 30:
            verdict, color, icon = "CLEAN", "bold green", "✓"
        elif score < 60:
            verdict, color, icon = "SUSPICIOUS", "bold yellow", "⚠"
        else:
            verdict, color, icon = "MALICIOUS", "bold red", "✕"

        console.print(
            Panel(
                f"[{color}]{icon}  {verdict}[/{color}]   Risk Score: [{color}]{score}/100[/{color}]\n\n"
                f"[dim]{self._verdict_detail(score, results)}[/dim]",
                title="[bold]VERDICT[/bold]",
                border_style=color.replace("bold ", ""),
            )
        )

    def _compute_risk_score(self, results: dict) -> int:
        score = 0
        abuse = results.get("abuseipdb") or {}
        if not abuse.get("error"):
            score += abuse.get("abuse_confidence_score", 0) * 0.4

        vt = results.get("virustotal") or {}
        if not vt.get("error"):
            total = max(vt.get("total_engines", 70), 1)
            mal = vt.get("malicious", 0)
            score += (mal / total) * 100 * 0.4

        otx = results.get("otx") or {}
        if not otx.get("error"):
            pulses = otx.get("pulse_count", 0)
            score += min(pulses * 2, 20)

        return min(int(score), 100)

    def _verdict_detail(self, score: int, results: dict) -> str:
        parts = []
        abuse = results.get("abuseipdb") or {}
        if abuse.get("is_tor"):
            parts.append("Tor exit node detected")
        if (abuse.get("abuse_confidence_score") or 0) > 80:
            parts.append(f"High abuse confidence ({abuse['abuse_confidence_score']}%)")

        vt = results.get("virustotal") or {}
        mal = vt.get("malicious", 0)
        if mal > 0:
            parts.append(f"Flagged by {mal} VirusTotal engines")

        otx = results.get("otx") or {}
        pulses = otx.get("pulse_count", 0)
        if pulses > 5:
            parts.append(f"{pulses} OTX threat intelligence pulses")

        return "  |  ".join(parts) if parts else "No significant threats detected."

    @staticmethod
    def _score_bar(score: int, width: int = 20) -> str:
        filled = int(score / 100 * width)
        color = "green" if score < 25 else "yellow" if score < 60 else "red"
        bar = f"[{color}]{'█' * filled}[/{color}]{'░' * (width - filled)}"
        return bar
