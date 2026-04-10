"""
modules/risk_scorer.py
========================
Unified Risk Scoring Engine

Aggregates signals from:
  • IP Reputation (AbuseIPDB + VirusTotal + OTX)
  • Phishing URL Detection
  • Email Header Analysis (if applicable)

Produces:
  • Composite risk score (0–100)
  • Risk breakdown by category
  • Evidence-based threat narrative
  • Recommended actions
"""

import re
from datetime import datetime
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

console = Console()

RISK_CATEGORIES = {
    "reputation": ("IP/Domain Reputation", 30),
    "phishing": ("Phishing Indicators", 35),
    "network": ("Network Behavior", 20),
    "infrastructure": ("Infrastructure Risk", 15),
}

RECOMMENDATIONS = {
    (0, 30): [
        "No immediate action required",
        "Continue monitoring with standard security controls",
        "Log this indicator for baseline reference",
    ],
    (30, 60): [
        "Flag for manual review",
        "Do not click URLs or open attachments",
        "Block at perimeter firewall if confirmed malicious",
        "Notify security team for investigation",
        "Check for lateral movement indicators",
    ],
    (60, 101): [
        "BLOCK IMMEDIATELY at all network perimeters",
        "Quarantine any emails from this source",
        "Run endpoint scan if user interacted with this indicator",
        "Escalate to Incident Response team",
        "Preserve logs for forensic investigation",
        "File report with relevant authorities (AbuseIPDB, PhishTank)",
        "Notify affected users immediately",
    ],
}

MITRE_MAPPING = {
    "phishing": "T1566 — Phishing",
    "typosquatting": "T1583.001 — Acquire Infrastructure: Domain",
    "spoofing": "T1534 — Internal Spearphishing",
    "botnet": "T1583.005 — Acquire Infrastructure: Botnet",
    "port_scan": "T1046 — Network Service Scanning",
    "brute_force": "T1110 — Brute Force",
    "tor": "T1090.003 — Proxy: Multi-hop Proxy",
    "malware": "T1204 — User Execution",
    "credential_harvesting": "T1056 — Input Capture",
}


class RiskScorer:
    def __init__(self, config, ip_checker, phishing_detector, email_analyzer):
        self.config = config
        self.ip_checker = ip_checker
        self.phishing_detector = phishing_detector
        self.email_analyzer = email_analyzer

    # ─── PUBLIC ENTRY POINTS ─────────────────────────────────────────────────

    def full_report(self, target: str):
        """Run all applicable modules and produce a unified risk report."""
        target_type = self._classify_target(target)
        console.print()
        console.print(Panel(
            f"[bold white]Target:[/bold white] [yellow]{target}[/yellow]\n"
            f"[bold white]Type:[/bold white] [cyan]{target_type}[/cyan]\n"
            f"[bold white]Initiated:[/bold white] [dim]{datetime.utcnow().isoformat()}Z[/dim]",
            title="[bold red]⚑  FULL THREAT INTELLIGENCE REPORT[/bold red]",
            border_style="red",
        ))

        all_results = {}

        # ── Phase 1: IP / Domain Reputation ─────────────────────────────────
        console.print("\n[bold cyan]Phase 1/2 → IP/Domain Reputation Analysis[/bold cyan]")
        ip_results = self.ip_checker.analyze(target)
        all_results["ip_reputation"] = ip_results

        # ── Phase 2: Phishing URL check (if URL or domain) ──────────────────
        if target_type in ("URL", "Domain"):
            console.print("\n[bold cyan]Phase 2/2 → Phishing URL Analysis[/bold cyan]")
            url = target if target.startswith("http") else f"https://{target}"
            phish_results = self.phishing_detector.analyze(url)
            all_results["phishing"] = phish_results

        # ── Aggregate scoring ────────────────────────────────────────────────
        self._print_aggregate_report(target, all_results)

    def quick_score(self, target: str) -> dict:
        """Fast scoring without printing — used by batch scanner."""
        target_type = self._classify_target(target)
        score = 0
        flags = []
        verdict = "CLEAN"

        try:
            if target_type in ("IP", "Domain"):
                ip_res = self.ip_checker.quick_check(target)
                ip_score = self.ip_checker._compute_risk_score(ip_res)
                score = max(score, ip_score)

                abuse = ip_res.get("abuseipdb") or {}
                if abuse.get("is_tor"):
                    flags.append("Tor Node")
                if (abuse.get("abuse_confidence_score") or 0) > 50:
                    flags.append(f"Abuse Score {abuse['abuse_confidence_score']}%")

                vt = ip_res.get("virustotal") or {}
                if (vt.get("malicious") or 0) > 0:
                    flags.append(f"VT: {vt['malicious']} engines")

            if target_type in ("URL", "Domain"):
                url = target if target.startswith("http") else f"https://{target}"
                ph_res = self.phishing_detector.quick_check(url)
                ph_score = ph_res.get("risk_score", 0)
                score = max(score, ph_score)

                if ph_res.get("typosquatting", {}).get("detected"):
                    flags.append("Typosquatting")
                if ph_res.get("homoglyph", {}).get("detected"):
                    flags.append("Homoglyph")
                phishtank = ph_res.get("phishtank", {}) or {}
                if phishtank.get("in_database"):
                    flags.append("PhishTank Hit")

        except Exception as e:
            flags.append(f"Error: {str(e)[:30]}")

        score = min(score, 100)
        if score < 30:
            verdict = "CLEAN"
        elif score < 60:
            verdict = "SUSPICIOUS"
        else:
            verdict = "MALICIOUS"

        return {
            "score": score,
            "verdict": verdict,
            "flags": flags,
            "type": target_type,
        }

    # ─── AGGREGATE REPORT ────────────────────────────────────────────────────

    def _print_aggregate_report(self, target: str, all_results: dict):
        ip_res = all_results.get("ip_reputation", {})
        ph_res = all_results.get("phishing", {})
        email_res = all_results.get("email", {})

        # Compute category scores
        rep_score = self.ip_checker._compute_risk_score(ip_res) if ip_res else 0
        phish_score = ph_res.get("risk_score", 0) if ph_res else 0
        email_score = email_res.get("risk_score", 0) if email_res else 0

        # Weighted aggregate
        total_weight = 0
        weighted_sum = 0

        if ip_res:
            weighted_sum += rep_score * 0.4
            total_weight += 0.4
        if ph_res:
            weighted_sum += phish_score * 0.4
            total_weight += 0.4
        if email_res:
            weighted_sum += email_score * 0.2
            total_weight += 0.2

        composite = int(weighted_sum / total_weight) if total_weight > 0 else 0
        composite = min(composite, 100)

        # Determine verdict
        if composite < 30:
            verdict, verdict_color, icon = "CLEAN", "green", "✓"
        elif composite < 60:
            verdict, verdict_color, icon = "SUSPICIOUS", "yellow", "⚠"
        else:
            verdict, verdict_color, icon = "MALICIOUS / HIGH RISK", "red", "✕"

        # ── Score breakdown table ────────────────────────────────────────────
        breakdown = Table(
            title="Risk Score Breakdown",
            box=box.DOUBLE_EDGE,
            border_style="cyan",
            show_lines=True,
        )
        breakdown.add_column("Module", style="bold white", width=28)
        breakdown.add_column("Score", justify="center", width=12)
        breakdown.add_column("Weight", justify="center", width=10)
        breakdown.add_column("Weighted", justify="center", width=12)
        breakdown.add_column("Visual", width=25)

        def score_color(s):
            return "green" if s < 30 else "yellow" if s < 60 else "red"

        if ip_res:
            sc = rep_score
            breakdown.add_row(
                "IP/Domain Reputation",
                f"[{score_color(sc)}]{sc}/100[/{score_color(sc)}]",
                "40%",
                f"[{score_color(sc)}]{int(sc * 0.4)}[/{score_color(sc)}]",
                self._mini_bar(sc),
            )
        if ph_res:
            sc = phish_score
            breakdown.add_row(
                "Phishing URL Analysis",
                f"[{score_color(sc)}]{sc}/100[/{score_color(sc)}]",
                "40%",
                f"[{score_color(sc)}]{int(sc * 0.4)}[/{score_color(sc)}]",
                self._mini_bar(sc),
            )
        if email_res:
            sc = email_score
            breakdown.add_row(
                "Email Header Analysis",
                f"[{score_color(sc)}]{sc}/100[/{score_color(sc)}]",
                "20%",
                f"[{score_color(sc)}]{int(sc * 0.2)}[/{score_color(sc)}]",
                self._mini_bar(sc),
            )

        # Composite row
        breakdown.add_row(
            "[bold]COMPOSITE RISK SCORE[/bold]",
            f"[bold {score_color(composite)}]{composite}/100[/bold {score_color(composite)}]",
            "100%",
            f"[bold {score_color(composite)}]{composite}[/bold {score_color(composite)}]",
            self._mini_bar(composite),
        )

        console.print()
        console.print(breakdown)

        # ── Evidence summary ─────────────────────────────────────────────────
        evidence = self._collect_evidence(all_results)
        if evidence:
            ev_table = Table(box=box.SIMPLE, show_header=True, padding=(0, 2))
            ev_table.add_column("Category", style="bold", width=24)
            ev_table.add_column("Evidence", style="white")
            ev_table.add_column("Severity", justify="center", width=12)

            sev_colors = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "dim"}
            for ev in evidence:
                sev = ev.get("severity", "MEDIUM")
                ev_table.add_row(
                    ev.get("category", ""),
                    ev.get("detail", ""),
                    f"[{sev_colors.get(sev, 'white')}]{sev}[/{sev_colors.get(sev, 'white')}]",
                )
            console.print(Panel(ev_table, title="[bold]Evidence Summary[/bold]", border_style="yellow"))

        # ── MITRE ATT&CK mapping ─────────────────────────────────────────────
        mitre_hits = self._map_mitre(all_results)
        if mitre_hits:
            mitre_panel = "\n".join(f"  [cyan]•[/cyan] {m}" for m in mitre_hits)
            console.print(Panel(mitre_panel, title="[bold]MITRE ATT&CK Techniques[/bold]", border_style="dim"))

        # ── Recommendations ──────────────────────────────────────────────────
        recs = []
        for (low, high), items in RECOMMENDATIONS.items():
            if low <= composite < high:
                recs = items
                break
        if recs:
            rec_text = "\n".join(f"  {'[red]' if composite >= 60 else '[yellow]' if composite >= 30 else '[green]'}{'→' if composite < 60 else '⚡'}[/] {r}" for r in recs)
            console.print(Panel(rec_text, title="[bold]Recommended Actions[/bold]", border_style=verdict_color))

        # ── Final verdict ────────────────────────────────────────────────────
        bar = self._full_bar(composite)
        console.print(Panel(
            f"[bold {verdict_color}]{icon}  {verdict}[/bold {verdict_color}]\n\n"
            f"Composite Risk: {bar} [{verdict_color}]{composite}/100[/{verdict_color}]\n\n"
            f"[dim]Target: {target}  |  Scanned: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC[/dim]",
            title="[bold]⚑  FINAL VERDICT[/bold]",
            border_style=verdict_color,
        ))

    # ─── HELPERS ─────────────────────────────────────────────────────────────

    def _collect_evidence(self, all_results: dict) -> list:
        evidence = []

        ip_res = all_results.get("ip_reputation", {})
        abuse = ip_res.get("abuseipdb") or {}
        if not abuse.get("error"):
            score = abuse.get("abuse_confidence_score", 0)
            if score > 50:
                evidence.append({"category": "AbuseIPDB", "detail": f"Confidence score: {score}%", "severity": "HIGH" if score > 75 else "MEDIUM"})
            if abuse.get("is_tor"):
                evidence.append({"category": "AbuseIPDB", "detail": "Confirmed Tor exit node", "severity": "HIGH"})

        vt = ip_res.get("virustotal") or {}
        if not vt.get("error") and (vt.get("malicious") or 0) > 0:
            evidence.append({"category": "VirusTotal", "detail": f"{vt['malicious']} engines flagged as malicious", "severity": "HIGH" if vt["malicious"] > 5 else "MEDIUM"})

        ph_res = all_results.get("phishing", {})
        if ph_res:
            if ph_res.get("typosquatting", {}).get("detected"):
                matches = ph_res["typosquatting"]["matches"]
                best = matches[0] if matches else {}
                evidence.append({"category": "Typosquatting", "detail": f"Mimics '{best.get('brand')}' (similarity {best.get('similarity')}%)", "severity": "CRITICAL"})
            if ph_res.get("homoglyph", {}).get("detected"):
                evidence.append({"category": "Homoglyph Attack", "detail": "Unicode lookalike chars in domain", "severity": "CRITICAL"})
            phishtank = ph_res.get("phishtank") or {}
            if phishtank.get("in_database"):
                evidence.append({"category": "PhishTank", "detail": f"Known phishing URL (ID: {phishtank.get('phish_id')})", "severity": "CRITICAL"})
            heuristics = ph_res.get("heuristics", {}).get("flags", [])
            critical_flags = [f for f in heuristics if f.get("severity") in ("critical", "high")]
            for cf in critical_flags[:3]:
                evidence.append({"category": "URL Heuristics", "detail": cf.get("detail"), "severity": cf["severity"].upper()})

        return evidence

    def _map_mitre(self, all_results: dict) -> list:
        techniques = set()

        ph_res = all_results.get("phishing", {})
        if ph_res:
            if ph_res.get("risk_score", 0) > 30:
                techniques.add(MITRE_MAPPING["phishing"])
            if ph_res.get("typosquatting", {}).get("detected"):
                techniques.add(MITRE_MAPPING["typosquatting"])
            heuristics = ph_res.get("heuristics", {}).get("flags", [])
            for f in heuristics:
                if "credential" in f.get("detail", "").lower():
                    techniques.add(MITRE_MAPPING["credential_harvesting"])

        ip_res = all_results.get("ip_reputation", {})
        abuse = ip_res.get("abuseipdb") or {}
        cats = abuse.get("categories", [])
        if abuse.get("is_tor"):
            techniques.add(MITRE_MAPPING["tor"])
        for cat in cats:
            if "brute" in cat.lower():
                techniques.add(MITRE_MAPPING["brute_force"])
            if "scan" in cat.lower():
                techniques.add(MITRE_MAPPING["port_scan"])
            if "botnet" in cat.lower():
                techniques.add(MITRE_MAPPING["botnet"])

        vt = ip_res.get("virustotal") or {}
        if "malware" in (vt.get("categories") or []):
            techniques.add(MITRE_MAPPING["malware"])

        return sorted(techniques)

    def _classify_target(self, target: str) -> str:
        if target.startswith(("http://", "https://")):
            return "URL"
        try:
            import ipaddress
            ipaddress.ip_address(target)
            return "IP"
        except ValueError:
            pass
        if re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", target):
            return "Domain"
        return "Unknown"

    @staticmethod
    def _mini_bar(score: int, width: int = 20) -> str:
        filled = int(score / 100 * width)
        color = "green" if score < 30 else "yellow" if score < 60 else "red"
        return f"[{color}]{'█' * filled}[/{color}]{'░' * (width - filled)}"

    @staticmethod
    def _full_bar(score: int, width: int = 30) -> str:
        filled = int(score / 100 * width)
        color = "green" if score < 30 else "yellow" if score < 60 else "red"
        return f"[{color}]{'█' * filled}[/{color}]{'░' * (width - filled)}"
