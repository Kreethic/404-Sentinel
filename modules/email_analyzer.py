"""
modules/email_analyzer.py
===========================
Email Header Analyzer

Analyzes:
  • Received headers          — trace full email route
  • SPF record check          — sender policy framework
  • DKIM signature validation — DomainKeys identified mail
  • DMARC policy check        — domain-based message authentication
  • Reply-To vs From mismatch — common spoofing indicator
  • X-Originating-IP          — extract sender's real IP
  • Message-ID anomalies      — unusual patterns
  • Encoding / obfuscation    — base64, quoted-printable payloads
  • Display name spoofing     — detect name ≠ email domain
"""

import re
import email
import socket
import email.policy
import email.parser
import email.header
from datetime import datetime
from typing import Optional, List, Tuple

import requests
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

console = Console()


# ─── SPF / DMARC / DKIM result strings ──────────────────────────────────────
SPF_RESULTS = {"pass", "fail", "softfail", "neutral", "none", "permerror", "temperror"}
DKIM_PASS_PATTERN = re.compile(r"dkim=pass", re.IGNORECASE)
DKIM_FAIL_PATTERN = re.compile(r"dkim=fail", re.IGNORECASE)
DMARC_PASS_PATTERN = re.compile(r"dmarc=pass", re.IGNORECASE)
DMARC_FAIL_PATTERN = re.compile(r"dmarc=fail", re.IGNORECASE)
SPF_PASS_PATTERN = re.compile(r"spf=pass", re.IGNORECASE)
SPF_FAIL_PATTERN = re.compile(r"spf=fail|spf=softfail", re.IGNORECASE)

SUSPICIOUS_MAILERS = [
    "sendgrid", "mailchimp", "phpmailer", "mass mail", "postfix",
    "exim", "qmail", "bulk mailer",
]

SAMPLE_PHISHING_EMAIL = """\
Delivered-To: victim@example.com
Received: from mail-ot1-f53.google.com (mail-ot1-f53.google.com [209.85.210.53])
        by mx.example.com with ESMTPS id abc123
        for <victim@example.com>; Mon, 15 Jan 2025 08:23:11 +0000
Received: from attacker-server.ru (attacker-server.ru [185.220.101.45])
        by smtp.gmail.com with ESMTP id xyz456
        for <victim@example.com>; Mon, 15 Jan 2025 08:23:09 +0000
Authentication-Results: mx.example.com;
       dkim=fail (signature verification failed) header.i=@paypal.com;
       spf=softfail (google.com: domain of attacker@attacker-server.ru does not designate 185.220.101.45 as permitted sender);
       dmarc=fail (p=REJECT sp=REJECT dis=REJECT) header.from=paypal.com
Return-Path: <attacker@attacker-server.ru>
From: "PayPal Security Team" <security@paypal.com>
Reply-To: collect-your-data@evil-domain.tk
To: victim@example.com
Subject: =?UTF-8?B?VVJHRU5UOiBZb3VyIGFjY291bnQgaGFzIGJlZW4gc3VzcGVuZGVk?=
Date: Mon, 15 Jan 2025 08:23:09 +0000
Message-ID: <20250115082309.12345@attacker-server.ru>
X-Originating-IP: [185.220.101.45]
X-Mailer: PHPMailer 6.0.0 (https://github.com/PHPMailer/PHPMailer)
MIME-Version: 1.0
Content-Type: text/html; charset=UTF-8
Content-Transfer-Encoding: base64
"""


class EmailHeaderAnalyzer:
    def __init__(self, config):
        self.config = config

    # ─── PUBLIC ENTRY POINTS ─────────────────────────────────────────────────

    def analyze_file(self, filepath: str) -> dict:
        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                raw = f.read()
            return self.analyze_raw(raw)
        except FileNotFoundError:
            console.print(f"[red]File not found: {filepath}[/red]")
            return {}

    def analyze_raw(self, raw_headers: str) -> dict:
        console.print()
        if not raw_headers.strip():
            console.print("[yellow]Using sample phishing email for demo...[/yellow]")
            raw_headers = SAMPLE_PHISHING_EMAIL

        with console.status("[bold cyan]Parsing and analyzing email headers...[/bold cyan]"):
            results = self._analyze(raw_headers)

        self._print_report(results)
        return results

    # ─── CORE ANALYSIS ───────────────────────────────────────────────────────

    def _analyze(self, raw: str) -> dict:
        msg = email.message_from_string(raw, policy=email.policy.compat32)

        results = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "envelope": self._extract_envelope(msg),
            "routing": self._extract_routing(msg),
            "authentication": self._check_authentication(msg),
            "spoofing": self._check_spoofing(msg),
            "encoding": self._check_encoding(msg),
            "anomalies": self._detect_anomalies(msg, raw),
            "originating_ip": self._extract_originating_ip(msg, raw),
        }

        results["risk_score"] = self._compute_risk(results)
        results["flags"] = self._collect_flags(results)
        return results

    # ─── ENVELOPE ────────────────────────────────────────────────────────────

    def _extract_envelope(self, msg) -> dict:
        def decode_header_value(val):
            if not val:
                return None
            decoded_parts = email.header.decode_header(val)
            parts = []
            for part, enc in decoded_parts:
                if isinstance(part, bytes):
                    parts.append(part.decode(enc or "utf-8", errors="replace"))
                else:
                    parts.append(part)
            return "".join(parts)

        return {
            "from": decode_header_value(msg.get("From")),
            "to": decode_header_value(msg.get("To")),
            "reply_to": decode_header_value(msg.get("Reply-To")),
            "return_path": decode_header_value(msg.get("Return-Path")),
            "subject": decode_header_value(msg.get("Subject")),
            "date": decode_header_value(msg.get("Date")),
            "message_id": decode_header_value(msg.get("Message-ID")),
            "x_mailer": decode_header_value(msg.get("X-Mailer")),
            "mime_version": decode_header_value(msg.get("MIME-Version")),
        }

    # ─── ROUTING / RECEIVED HEADERS ──────────────────────────────────────────

    def _extract_routing(self, msg) -> dict:
        received_headers = msg.get_all("Received") or []
        hops = []

        for header in received_headers:
            hop = {"raw": header.strip()}

            # Extract FROM clause
            from_match = re.search(r"from\s+(\S+)\s+\(([^)]+)\)", header, re.IGNORECASE)
            if from_match:
                hop["from_hostname"] = from_match.group(1)
                bracket_content = from_match.group(2)
                ip_match = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", bracket_content)
                hop["from_ip"] = ip_match.group(1) if ip_match else None

            # Extract BY clause
            by_match = re.search(r"by\s+(\S+)", header, re.IGNORECASE)
            if by_match:
                hop["by"] = by_match.group(1)

            # Extract timestamp
            ts_match = re.search(r";\s*(.+)$", header, re.MULTILINE)
            if ts_match:
                hop["timestamp"] = ts_match.group(1).strip()

            hops.append(hop)

        # The last "Received" header (bottom) contains origin
        origin_ip = None
        if hops:
            for hop in reversed(hops):
                if hop.get("from_ip"):
                    origin_ip = hop["from_ip"]
                    break

        return {
            "hops": hops,
            "hop_count": len(hops),
            "origin_ip": origin_ip,
            "origin_hostname": hops[-1].get("from_hostname") if hops else None,
        }

    # ─── AUTHENTICATION ───────────────────────────────────────────────────────

    def _check_authentication(self, msg) -> dict:
        auth_results = msg.get("Authentication-Results", "") or ""
        auth_results_lower = auth_results.lower()

        spf_pass = bool(SPF_PASS_PATTERN.search(auth_results))
        spf_fail = bool(SPF_FAIL_PATTERN.search(auth_results))
        dkim_pass = bool(DKIM_PASS_PATTERN.search(auth_results))
        dkim_fail = bool(DKIM_FAIL_PATTERN.search(auth_results))
        dmarc_pass = bool(DMARC_PASS_PATTERN.search(auth_results))
        dmarc_fail = bool(DMARC_FAIL_PATTERN.search(auth_results))

        # Extract SPF domain
        spf_domain = None
        spf_match = re.search(r"spf=\S+.*?smtp\.mailfrom=(\S+)", auth_results, re.IGNORECASE)
        if spf_match:
            spf_domain = spf_match.group(1)

        # Extract DKIM domain
        dkim_domain = None
        dkim_match = re.search(r"header\.i=@(\S+)", auth_results, re.IGNORECASE)
        if dkim_match:
            dkim_domain = dkim_match.group(1)

        return {
            "raw": auth_results,
            "spf": {
                "pass": spf_pass,
                "fail": spf_fail,
                "result": "PASS" if spf_pass else ("FAIL" if spf_fail else "NONE"),
                "domain": spf_domain,
            },
            "dkim": {
                "pass": dkim_pass,
                "fail": dkim_fail,
                "result": "PASS" if dkim_pass else ("FAIL" if dkim_fail else "NONE"),
                "domain": dkim_domain,
            },
            "dmarc": {
                "pass": dmarc_pass,
                "fail": dmarc_fail,
                "result": "PASS" if dmarc_pass else ("FAIL" if dmarc_fail else "NONE"),
            },
        }

    # ─── SPOOFING DETECTION ──────────────────────────────────────────────────

    def _check_spoofing(self, msg) -> dict:
        indicators = []

        from_raw = msg.get("From", "")
        reply_to = msg.get("Reply-To", "")
        return_path = msg.get("Return-Path", "")

        # Extract email addresses
        from_addr = self._extract_email(from_raw)
        reply_addr = self._extract_email(reply_to)
        return_addr = self._extract_email(return_path)

        from_domain = self._extract_domain(from_addr) if from_addr else None
        reply_domain = self._extract_domain(reply_addr) if reply_addr else None
        return_domain = self._extract_domain(return_addr) if return_addr else None

        # Display name vs email domain mismatch
        display_name = self._extract_display_name(from_raw)
        if display_name and from_domain:
            display_lower = display_name.lower()
            known_brands = ["paypal", "amazon", "google", "microsoft", "apple", "bank", "netflix"]
            for brand in known_brands:
                if brand in display_lower and brand not in (from_domain or ""):
                    indicators.append({
                        "type": "display_name_spoofing",
                        "detail": f"Display name '{display_name}' implies '{brand}' but domain is '{from_domain}'",
                        "severity": "critical",
                    })
                    break

        # Reply-To ≠ From domain
        if reply_addr and from_addr and reply_domain != from_domain:
            indicators.append({
                "type": "reply_to_mismatch",
                "detail": f"Reply-To domain '{reply_domain}' differs from From domain '{from_domain}'",
                "severity": "high",
            })

        # Return-Path ≠ From domain
        if return_addr and from_addr and return_domain and return_domain != from_domain:
            indicators.append({
                "type": "return_path_mismatch",
                "detail": f"Return-Path domain '{return_domain}' differs from From domain '{from_domain}'",
                "severity": "high",
            })

        return {
            "indicators": indicators,
            "from_address": from_addr,
            "from_domain": from_domain,
            "from_display_name": display_name,
            "reply_to_address": reply_addr,
            "reply_to_domain": reply_domain,
            "return_path_address": return_addr,
            "return_path_domain": return_domain,
        }

    # ─── ENCODING ANALYSIS ───────────────────────────────────────────────────

    def _check_encoding(self, msg) -> dict:
        subject = msg.get("Subject", "")
        cte = msg.get("Content-Transfer-Encoding", "")
        ct = msg.get("Content-Type", "")

        flags = []

        # Encoded subject (=?UTF-8?B?...?=)
        if "=?" in subject:
            flags.append("Subject is encoded (Base64/QP) — common in phishing")

        # Base64 body
        if "base64" in cte.lower():
            flags.append("Email body encoded in Base64")

        # HTML with no plain text alternative
        if "text/html" in ct.lower() and "multipart/alternative" not in ct.lower():
            flags.append("HTML-only email (no plain text alternative)")

        return {
            "subject_encoded": "=?" in subject,
            "content_transfer_encoding": cte,
            "content_type": ct,
            "flags": flags,
        }

    # ─── ANOMALY DETECTION ───────────────────────────────────────────────────

    def _detect_anomalies(self, msg, raw: str) -> list:
        anomalies = []

        # Suspicious mailer
        x_mailer = msg.get("X-Mailer", "").lower()
        for mailer in SUSPICIOUS_MAILERS:
            if mailer in x_mailer:
                anomalies.append(f"Suspicious mailer detected: '{msg.get('X-Mailer')}'")
                break

        # Message-ID with unknown domain
        msg_id = msg.get("Message-ID", "")
        if msg_id:
            mid_match = re.search(r"@([^>]+)", msg_id)
            if mid_match:
                mid_domain = mid_match.group(1)
                from_domain = self._extract_domain(self._extract_email(msg.get("From", "")))
                if from_domain and mid_domain and mid_domain != from_domain:
                    anomalies.append(f"Message-ID domain '{mid_domain}' ≠ From domain '{from_domain}'")

        # Very old or future dates
        date_raw = msg.get("Date", "")
        if date_raw:
            try:
                from email.utils import parsedate_to_datetime
                dt = parsedate_to_datetime(date_raw)
                now = datetime.utcnow()
                age_days = abs((now - dt.replace(tzinfo=None)).days)
                if age_days > 30:
                    anomalies.append(f"Email dated {age_days} days ago — possibly delayed/replay")
            except Exception:
                anomalies.append("Could not parse email Date header")

        # Suspicious URLs in raw content
        urls_found = re.findall(r"https?://[^\s\"'<>]+", raw)
        suspicious_urls = [u for u in urls_found if any(t in u.lower() for t in [".tk", ".ml", "login", "verify", "secure-"])]
        if suspicious_urls:
            anomalies.append(f"{len(suspicious_urls)} suspicious URL(s) in body: {suspicious_urls[0][:60]}")

        return anomalies

    # ─── ORIGINATING IP ──────────────────────────────────────────────────────

    def _extract_originating_ip(self, msg, raw: str) -> Optional[str]:
        # Check X-Originating-IP header first
        x_orig = msg.get("X-Originating-IP", "")
        if x_orig:
            ip_match = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", x_orig)
            if ip_match:
                return ip_match.group(1)

        # Fall back to last Received header
        received = msg.get_all("Received") or []
        if received:
            last = received[-1]
            ip_match = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", last)
            if ip_match:
                return ip_match.group(1)

        return None

    # ─── HELPERS ─────────────────────────────────────────────────────────────

    @staticmethod
    def _extract_email(header_value: str) -> Optional[str]:
        if not header_value:
            return None
        match = re.search(r"<([^>]+)>", header_value)
        if match:
            return match.group(1).strip()
        # Plain email without angle brackets
        match2 = re.search(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b", header_value)
        return match2.group(0) if match2 else None

    @staticmethod
    def _extract_display_name(from_raw: str) -> Optional[str]:
        match = re.match(r'^"?([^"<]+)"?\s*<', from_raw)
        if match:
            return match.group(1).strip().strip('"')
        return None

    @staticmethod
    def _extract_domain(email_addr: Optional[str]) -> Optional[str]:
        if not email_addr or "@" not in email_addr:
            return None
        return email_addr.split("@")[-1].lower()

    # ─── RISK SCORING ────────────────────────────────────────────────────────

    def _compute_risk(self, results: dict) -> int:
        score = 0
        auth = results.get("authentication", {})

        if auth.get("spf", {}).get("fail"):
            score += 25
        if auth.get("dkim", {}).get("fail"):
            score += 25
        if auth.get("dmarc", {}).get("fail"):
            score += 20

        spoofing = results.get("spoofing", {})
        for indicator in spoofing.get("indicators", []):
            sev = indicator.get("severity")
            score += {"critical": 30, "high": 20, "medium": 10, "low": 5}.get(sev, 5)

        anomalies = results.get("anomalies", [])
        score += len(anomalies) * 5

        encoding = results.get("encoding", {})
        score += len(encoding.get("flags", [])) * 5

        return min(score, 100)

    def _collect_flags(self, results: dict) -> list:
        flags = []
        auth = results.get("authentication", {})
        if auth.get("spf", {}).get("fail"):
            flags.append("SPF FAIL")
        if auth.get("dkim", {}).get("fail"):
            flags.append("DKIM FAIL")
        if auth.get("dmarc", {}).get("fail"):
            flags.append("DMARC FAIL")
        for ind in results.get("spoofing", {}).get("indicators", []):
            flags.append(ind["type"].upper())
        return flags

    # ─── REPORT PRINTING ─────────────────────────────────────────────────────

    def _print_report(self, results: dict):
        score = results.get("risk_score", 0)
        score_color = "green" if score < 30 else "yellow" if score < 60 else "bold red"
        flags = results.get("flags", [])
        flag_str = "  ".join(f"[red]{f}[/red]" for f in flags) if flags else "[green]None[/green]"

        console.print(Panel(
            f"[bold white]Scanned:[/bold white] [dim]{results['timestamp']}[/dim]\n"
            f"[bold white]Risk Score:[/bold white] [{score_color}]{score}/100[/{score_color}]\n"
            f"[bold white]Flags:[/bold white] {flag_str}",
            title="[bold red]⚑  EMAIL HEADER ANALYSIS REPORT[/bold red]",
            border_style="red",
        ))

        # ── Envelope ──────────────────────────────────────────────────────────
        env = results.get("envelope", {})
        e_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
        e_table.add_column(style="dim", width=16)
        e_table.add_column(style="white", overflow="fold")
        for k, v in env.items():
            if v:
                e_table.add_row(k.replace("_", "-").title(), v)
        console.print(Panel(e_table, title="[cyan]Envelope[/cyan]", border_style="dim"))

        # ── Authentication ────────────────────────────────────────────────────
        auth = results.get("authentication", {})
        auth_table = Table(box=box.ROUNDED, border_style="dim", padding=(0, 3))
        auth_table.add_column("Protocol", style="bold white", width=10)
        auth_table.add_column("Result", justify="center", width=12)
        auth_table.add_column("Detail", style="dim")

        def auth_result_fmt(result_str):
            if result_str == "PASS":
                return "[bold green]✓ PASS[/bold green]"
            elif result_str == "FAIL":
                return "[bold red]✕ FAIL[/bold red]"
            return "[dim]NONE[/dim]"

        auth_table.add_row("SPF", auth_result_fmt(auth.get("spf", {}).get("result", "NONE")),
                           f"Domain: {auth.get('spf', {}).get('domain', 'N/A')}")
        auth_table.add_row("DKIM", auth_result_fmt(auth.get("dkim", {}).get("result", "NONE")),
                           f"Signing domain: {auth.get('dkim', {}).get('domain', 'N/A')}")
        auth_table.add_row("DMARC", auth_result_fmt(auth.get("dmarc", {}).get("result", "NONE")), "")
        console.print(Panel(auth_table, title="[bold]Email Authentication (SPF / DKIM / DMARC)[/bold]", border_style="yellow"))

        # ── Spoofing indicators ───────────────────────────────────────────────
        spoof = results.get("spoofing", {})
        indicators = spoof.get("indicators", [])
        sp_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
        sp_table.add_column(style="dim", width=24)
        sp_table.add_column(style="white", overflow="fold")
        sp_table.add_row("From", spoof.get("from_address") or "N/A")
        sp_table.add_row("Display Name", spoof.get("from_display_name") or "N/A")
        sp_table.add_row("From Domain", spoof.get("from_domain") or "N/A")
        sp_table.add_row("Reply-To", spoof.get("reply_to_address") or "N/A")
        sp_table.add_row("Return-Path", spoof.get("return_path_address") or "N/A")

        if indicators:
            sp_table.add_row("", "")
            for ind in indicators:
                sev = ind.get("severity", "medium")
                sev_colors = {"critical": "bold red", "high": "red", "medium": "yellow"}
                color = sev_colors.get(sev, "white")
                sp_table.add_row(
                    f"[{color}]⚠ {ind['type'].upper()}[/{color}]",
                    f"[{color}]{ind['detail']}[/{color}]",
                )

        border = "red" if indicators else "green"
        title = "[bold red]Spoofing Analysis — INDICATORS FOUND[/bold red]" if indicators else "[bold green]Spoofing Analysis — Clean[/bold green]"
        console.print(Panel(sp_table, title=title, border_style=border))

        # ── Routing ──────────────────────────────────────────────────────────
        routing = results.get("routing", {})
        hops = routing.get("hops", [])
        if hops:
            r_table = Table(box=box.SIMPLE, show_header=True, padding=(0, 2))
            r_table.add_column("#", style="dim", width=3)
            r_table.add_column("From", style="cyan", width=30)
            r_table.add_column("IP", style="yellow", width=18)
            r_table.add_column("By", style="dim", width=30)
            for i, hop in enumerate(reversed(hops), 1):
                r_table.add_row(
                    str(i),
                    hop.get("from_hostname", "N/A"),
                    hop.get("from_ip", "N/A") or "N/A",
                    hop.get("by", "N/A"),
                )
            origin_ip = routing.get("origin_ip")
            origin_note = f"\n[bold white]Originating IP:[/bold white] [bold yellow]{origin_ip}[/bold yellow]" if origin_ip else ""
            console.print(Panel(r_table, title=f"[cyan]Email Routing — {len(hops)} hops{origin_note}[/cyan]", border_style="dim"))

        # ── Originating IP ───────────────────────────────────────────────────
        orig_ip = results.get("originating_ip")
        if orig_ip:
            console.print(Panel(
                f"[bold yellow]Originating IP (X-Originating-IP / Last Received):[/bold yellow] [bold red]{orig_ip}[/bold red]\n"
                f"[dim]Run IP Reputation check on this address for attribution.[/dim]",
                title="[bold]Sender IP Extraction[/bold]",
                border_style="yellow",
            ))

        # ── Encoding anomalies ────────────────────────────────────────────────
        enc = results.get("encoding", {})
        enc_flags = enc.get("flags", [])
        anomalies = results.get("anomalies", [])
        all_notes = enc_flags + anomalies
        if all_notes:
            note_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
            note_table.add_column(style="dim", width=3)
            note_table.add_column(style="yellow")
            for note in all_notes:
                note_table.add_row("⚠", note)
            console.print(Panel(note_table, title="[yellow]Anomalies & Encoding[/yellow]", border_style="yellow"))

        # ── Verdict ──────────────────────────────────────────────────────────
        if score < 30:
            verdict, icon, color = "LIKELY LEGITIMATE", "✓", "bold green"
        elif score < 60:
            verdict, icon, color = "SUSPICIOUS", "⚠", "bold yellow"
        else:
            verdict, icon, color = "SPOOFED / PHISHING EMAIL", "✕", "bold red"

        console.print(Panel(
            f"[{color}]{icon}  {verdict}[/{color}]   Risk Score: [{color}]{score}/100[/{color}]",
            title="[bold]VERDICT[/bold]",
            border_style=color.replace("bold ", ""),
        ))
