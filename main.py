#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════╗
║       404 SENTINEL - Threat Intelligence CLI          ║
║      • IP/Domain Reputation • Phishing Detection      ║
║      • Email Header Analysis • Risk Scoring           ║
╚═══════════════════════════════════════════════════════╝
"""

import argparse
import sys
import os

# Ensure the script directory is in the Python path
script_dir = os.path.dirname(os.path.abspath(__file__))
if script_dir not in sys.path:
    sys.path.insert(0, script_dir)

# Also add current working directory
if os.getcwd() not in sys.path:
    sys.path.insert(0, os.getcwd())

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from rich import box
from rich.prompt import Prompt, Confirm
from rich.live import Live
from rich.spinner import Spinner

try:
    from modules.ip_reputation import IPReputationChecker
    from modules.phishing_detector import PhishingDetector
    from modules.email_analyzer import EmailHeaderAnalyzer
    from modules.risk_scorer import RiskScorer
    from modules.domain_whois_analyzer import create_domain_analyzer
    from modules.file_hash_analyzer import create_file_analyzer
    from modules.subdomain_enumerator import create_subdomain_enumerator
except ModuleNotFoundError as e:
    print(f"[ERROR] Cannot find modules: {e}")
    print(f"[INFO] Script location: {script_dir}")
    print(f"[INFO] Current directory: {os.getcwd()}")
    print(f"[INFO] Checking for modules folder...")
    modules_path = os.path.join(script_dir, "modules")
    if os.path.exists(modules_path):
        print(f"[OK] Modules folder found at: {modules_path}")
    else:
        print(f"[ERROR] Modules folder NOT found at: {modules_path}")
    sys.exit(1)

from config import Config

console = Console()


BANNER = """
[bold red]
██╗  ██╗ ██████╗ ██╗  ██╗
██║  ██║██╔═████╗██║  ██║
███████║██║██╔██║███████║
╚════██║████╔╝██║╚════██║
     ██║╚██████╔╝     ██║
     ╚═╝ ╚═════╝      ╚═╝
[/bold red]
[bold yellow]
███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗     
██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║     
███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║     
╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║     
███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝[/bold yellow]
"""

TAGLINE = "[dim]Threat Intelligence Platform • v1.0.0 •[/dim]"


def print_banner():
    console.print(BANNER)
    console.print(TAGLINE, justify="center")
    console.print()


def print_menu():
    menu = Table(box=box.ROUNDED, border_style="dim cyan", show_header=False, padding=(0, 2))
    menu.add_column(justify="center", style="bold cyan", width=4)
    menu.add_column(style="bold white")
    menu.add_column(style="dim")

    menu.add_row("1", "IP / Domain Reputation", "AbuseIPDB + VirusTotal + AlienVault OTX")
    menu.add_row("2", "Phishing URL Detector", "PhishTank + Safe Browsing + Typosquatting")
    menu.add_row("3", "Email Header Analyzer", "SPF / DKIM / DMARC + Spoofing Detection")
    menu.add_row("4", "Full Risk Score Report", "Aggregate all modules into a single report")
    menu.add_row("5", "Domain / WHOIS Analyzer", "Registration info, DNS records, SSL certs")
    menu.add_row("6", "File / Hash Analyzer", "Hash calculations, VirusTotal lookup, malware check")
    menu.add_row("7", "Subdomain Enumeration", "Discover all subdomains for target domain")
    menu.add_row("8", "Batch Scan (from file)", "Scan multiple IPs/URLs from a text file")
    menu.add_row("0", "Exit", "")

    console.print(Panel(menu, title="[bold red][ MAIN MENU ][/bold red]", border_style="red"))


def run_interactive():
    print_banner()

    cfg = Config()
    if not cfg.validate():
        console.print(
            Panel(
                "[yellow]⚠  No API keys configured.[/yellow]\n"
                "Edit [bold]config.py[/bold] or set environment variables.\n"
                "Running in [bold cyan]DEMO MODE[/bold cyan] with mock data.",
                title="Configuration Warning",
                border_style="yellow",
            )
        )

    ip_checker = IPReputationChecker(cfg)
    phishing_detector = PhishingDetector(cfg)
    email_analyzer = EmailHeaderAnalyzer(cfg)
    risk_scorer = RiskScorer(cfg, ip_checker, phishing_detector, email_analyzer)
    domain_analyzer = create_domain_analyzer(cfg)
    file_analyzer = create_file_analyzer(cfg)
    subdomain_enumerator = create_subdomain_enumerator(cfg)

    while True:
        console.print()
        print_menu()
        choice = Prompt.ask("[bold cyan]Select option[/bold cyan]", default="0")

        if choice == "0":
            console.print("\n[bold red]Goodbye. Stay secure!.[/bold red]\n")
            sys.exit(0)

        elif choice == "1":
            target = Prompt.ask("[bold]Enter IP address or domain[/bold]")
            if target:
                ip_checker.analyze(target.strip())

        elif choice == "2":
            url = Prompt.ask("[bold]Enter URL to check[/bold]")
            if url:
                phishing_detector.analyze(url.strip())

        elif choice == "3":
            console.print("[dim]Provide path to .eml file OR paste raw headers (empty line to finish):[/dim]")
            source = Prompt.ask("[bold]File path or 'paste'[/bold]", default="paste")
            if source.lower() == "paste":
                console.print("[dim]Paste headers below. Enter blank line when done:[/dim]")
                lines = []
                while True:
                    line = input()
                    if line == "":
                        break
                    lines.append(line)
                raw_headers = "\n".join(lines)
                email_analyzer.analyze_raw(raw_headers)
            else:
                email_analyzer.analyze_file(source.strip())

        elif choice == "4":
            target = Prompt.ask("[bold]Enter IP, domain, or URL for full risk analysis[/bold]")
            if target:
                risk_scorer.full_report(target.strip())

        elif choice == "5":
            domain = Prompt.ask("[bold]Enter domain name to analyze[/bold]")
            if domain:
                result = domain_analyzer.analyze_domain(domain.strip())
                domain_analyzer.display_report(result)

        elif choice == "6":
            console.print("\n[bold cyan]File/Hash Analysis Mode[/bold cyan]")
            console.print("1. Analyze file by path")
            console.print("2. Analyze file hash directly")
            mode = Prompt.ask("[bold]Select mode[/bold]", choices=["1", "2"], default="1")
            
            if mode == "1":
                file_path = Prompt.ask("[bold]Enter file path[/bold]")
                if file_path and os.path.exists(file_path):
                    result = file_analyzer.analyze_file(file_path)
                    file_analyzer.display_file_report(result)
                else:
                    console.print("[red]File not found.[/red]")
            else:
                hash_value = Prompt.ask("[bold]Enter hash value (MD5/SHA1/SHA256)[/bold]")
                if hash_value:
                    result = file_analyzer.analyze_hash(hash_value.strip())
                    file_analyzer.display_hash_report(result)

        elif choice == "7":
            domain = Prompt.ask("[bold]Enter domain for subdomain enumeration[/bold]")
            if domain:
                result = subdomain_enumerator.enumerate(domain.strip())
                subdomain_enumerator.display_report(result)

        elif choice == "8":
            filepath = Prompt.ask("[bold]Path to targets file (one per line)[/bold]")
            if filepath:
                run_batch(filepath, ip_checker, phishing_detector, risk_scorer)

        else:
            console.print("[red]Invalid option. Please try again.[/red]")


def run_batch(filepath: str, ip_checker, phishing_detector, risk_scorer):
    if not os.path.exists(filepath):
        console.print(f"[red]File not found: {filepath}[/red]")
        return

    with open(filepath, encoding='utf-8', errors='replace') as f:
        targets = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    console.print(f"\n[bold cyan]Batch scanning {len(targets)} targets...[/bold cyan]\n")

    summary = Table(
        title="Batch Scan Summary",
        box=box.DOUBLE_EDGE,
        border_style="cyan",
        show_lines=True,
    )
    summary.add_column("Target", style="bold white", width=35)
    summary.add_column("Type", style="cyan", width=10)
    summary.add_column("Risk Score", justify="center", width=12)
    summary.add_column("Verdict", justify="center", width=15)
    summary.add_column("Flags", style="dim", width=30)

    for target in targets:
        result = risk_scorer.quick_score(target)
        score = result["score"]
        verdict = result["verdict"]
        flags = ", ".join(result["flags"][:3]) if result["flags"] else "None"

        score_color = "green" if score < 30 else "yellow" if score < 60 else "red"
        verdict_color = "green" if verdict == "CLEAN" else "yellow" if verdict == "SUSPICIOUS" else "red"

        summary.add_row(
            target,
            result["type"],
            f"[{score_color}]{score}/100[/{score_color}]",
            f"[bold {verdict_color}]{verdict}[/bold {verdict_color}]",
            flags,
        )

    console.print(summary)


def run_cli(args):
    """Non-interactive CLI mode."""
    cfg = Config()
    ip_checker = IPReputationChecker(cfg)
    phishing_detector = PhishingDetector(cfg)
    email_analyzer = EmailHeaderAnalyzer(cfg)
    risk_scorer = RiskScorer(cfg, ip_checker, phishing_detector, email_analyzer)
    domain_analyzer = create_domain_analyzer(cfg)
    file_analyzer = create_file_analyzer(cfg)

    if args.ip:
        ip_checker.analyze(args.ip)
    elif args.url:
        phishing_detector.analyze(args.url)
    elif args.email:
        email_analyzer.analyze_file(args.email)
    elif args.risk:
        risk_scorer.full_report(args.risk)
    elif args.domain:
        result = domain_analyzer.analyze_domain(args.domain)
        domain_analyzer.display_report(result)
    elif args.file:
        result = file_analyzer.analyze_file(args.file)
        file_analyzer.display_file_report(result)
    elif args.hash:
        result = file_analyzer.analyze_hash(args.hash)
        file_analyzer.display_hash_report(result)
    elif args.subdomain:
        subdomain_enumerator = create_subdomain_enumerator(cfg)
        result = subdomain_enumerator.enumerate(args.subdomain)
        subdomain_enumerator.display_report(result)
    elif args.batch:
        run_batch(args.batch, ip_checker, phishing_detector, risk_scorer)


def main():
    parser = argparse.ArgumentParser(
        prog="cyber-sentinel",
        description="Cyber Sentinel - Threat Intelligence Platform",
    )
    parser.add_argument("--ip", metavar="IP/DOMAIN", help="Check IP or domain reputation")
    parser.add_argument("--url", metavar="URL", help="Check URL for phishing")
    parser.add_argument("--email", metavar="FILE", help="Analyze .eml email file")
    parser.add_argument("--risk", metavar="TARGET", help="Full risk score report")
    parser.add_argument("--domain", metavar="DOMAIN", help="Analyze domain WHOIS and DNS records")
    parser.add_argument("--file", metavar="FILE", help="Analyze file hashes and metadata")
    parser.add_argument("--hash", metavar="HASH", help="Analyze file hash (MD5/SHA1/SHA256)")
    parser.add_argument("--subdomain", metavar="DOMAIN", help="Enumerate subdomains for target domain")
    parser.add_argument("--batch", metavar="FILE", help="Batch scan from file")
    parser.add_argument("--no-banner", action="store_true", help="Suppress banner")

    args = parser.parse_args()

    if not args.no_banner and not any([args.ip, args.url, args.email, args.risk, args.domain, args.file, args.hash, args.subdomain, args.batch]):
        pass  # banner printed in interactive mode

    # If any CLI args provided, run non-interactive
    if any([args.ip, args.url, args.email, args.risk, args.domain, args.file, args.hash, args.subdomain, args.batch]):
        if not args.no_banner:
            print_banner()
        run_cli(args)
    else:
        run_interactive()


if __name__ == "__main__":
    main()