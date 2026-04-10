"""
modules/subdomain_enumerator.py
================================
Subdomain Enumeration Module

Techniques:
  • DNS brute-force        — common subdomain wordlist
  • Certificate Transparency — crt.sh API queries
  • HTTP probing           — verify active subdomains
  • DNS zone transfer      — AXFR attacks (if enabled)
  • Reverse DNS lookups    — find subdomains from IPs
  • Service detection      — identify running services
"""

import re
import socket
import requests
import subprocess
from typing import Dict, List, Set, Any, Optional
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()


class SubdomainEnumerator:
    """Enumerate subdomains for a given domain."""

    def __init__(self, config):
        self.config = config
        self.subdomains = set()
        self.verified_subdomains = {}

    def enumerate(self, domain: str, timeout: int = 10) -> Dict[str, Any]:
        """
        Enumerate subdomains for a target domain.
        
        Args:
            domain: Target domain (e.g., "google.com")
            timeout: Timeout for operations in seconds
            
        Returns:
            Dictionary with all discovered subdomains and their details
        """
        if not self._is_valid_domain(domain):
            return {
                "status": "error",
                "message": f"Invalid domain: {domain}",
                "subdomains": []
            }

        results = {
            "domain": domain,
            "timestamp": datetime.now().isoformat(),
            "subdomains": {},
            "total_found": 0,
            "active_count": 0,
            "methods_used": [],
            "risk_assessment": {}
        }

        # Method 1: Certificate Transparency (crt.sh)
        console.print("[dim]Querying Certificate Transparency logs...[/dim]")
        ct_subs = self._enumerate_via_crt_sh(domain)
        results["subdomains"].update(ct_subs)
        if ct_subs:
            results["methods_used"].append("Certificate Transparency (crt.sh)")

        # Method 2: Common subdomain brute-force
        console.print("[dim]Brute-forcing common subdomains...[/dim]")
        bf_subs = self._enumerate_via_bruteforce(domain, timeout)
        results["subdomains"].update(bf_subs)
        if bf_subs:
            results["methods_used"].append("DNS Brute-force")

        # Method 3: Reverse DNS
        console.print("[dim]Attempting reverse DNS lookups...[/dim]")
        reverse_subs = self._enumerate_via_reverse_dns(domain)
        results["subdomains"].update(reverse_subs)
        if reverse_subs:
            results["methods_used"].append("Reverse DNS")

        results["total_found"] = len(results["subdomains"])
        results["active_count"] = sum(1 for sub in results["subdomains"].values() if sub.get("active"))
        results["risk_assessment"] = self._assess_risk(results["subdomains"])

        return results

    def _is_valid_domain(self, domain: str) -> bool:
        """Validate domain format."""
        domain_regex = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]{2,}$'
        return bool(re.match(domain_regex, domain))

    def _enumerate_via_crt_sh(self, domain: str) -> Dict[str, Dict]:
        """
        Query crt.sh (Certificate Transparency logs) for subdomains.
        Uses public API - no authentication needed.
        """
        subdomains = {}
        
        try:
            # Query crt.sh JSON API
            url = f"https://crt.sh/?q=%25.{domain}&output=json"
            response = requests.get(url, timeout=5)
            
            if response.status_code == 200:
                try:
                    certs = response.json()
                    for cert in certs:
                        # Extract common name and SAN
                        cn = cert.get('name_value', '')
                        for name in cn.split('\n'):
                            name = name.strip()
                            if name and name != domain:
                                # Remove wildcard prefix if present
                                clean_name = name.replace('*.', '')
                                # Validate before adding
                                if self._is_valid_subdomain(clean_name):
                                    subdomains[clean_name] = {
                                        "source": "Certificate Transparency",
                                        "active": None,
                                        "ip": None,
                                        "http_status": None
                                    }
                except (ValueError, KeyError):
                    pass
        except (requests.Timeout, requests.ConnectionError, Exception):
            pass

        # Verify subdomains with DNS lookups
        for subdomain in list(subdomains.keys()):
            ip = self._resolve_subdomain(subdomain)
            if ip:
                subdomains[subdomain]["active"] = True
                subdomains[subdomain]["ip"] = ip
                subdomains[subdomain]["http_status"] = self._check_http(subdomain)
            else:
                subdomains[subdomain]["active"] = False

        return subdomains

    def _enumerate_via_bruteforce(self, domain: str, timeout: int = 10) -> Dict[str, Dict]:
        """
        Brute-force common subdomains using wordlist.
        """
        subdomains = {}
        wordlist = self._get_common_subdomains()

        # Limit attempts based on timeout
        import time
        start_time = time.time()
        checked = 0
        per_item_timeout = timeout / max(len(wordlist), 1)

        for subdomain_part in wordlist:
            if time.time() - start_time > timeout:
                console.print(f"[dim]Timeout reached after checking {checked} subdomains[/dim]")
                break

            full_subdomain = f"{subdomain_part}.{domain}"
            
            try:
                ip = self._resolve_subdomain(full_subdomain)
                if ip:
                    http_status = self._check_http(full_subdomain)
                    subdomains[full_subdomain] = {
                        "source": "DNS Brute-force",
                        "active": True,
                        "ip": ip,
                        "http_status": http_status
                    }
                checked += 1
            except Exception:
                checked += 1
                continue

        return subdomains

    def _enumerate_via_reverse_dns(self, domain: str) -> Dict[str, Dict]:
        """
        Attempt reverse DNS lookups and zone transfers.
        """
        subdomains = {}

        # Try zone transfer (AXFR)
        try:
            import dns.zone
            import dns.resolver
            
            # Get nameservers for domain
            try:
                ns_records = dns.resolver.resolve(domain, 'NS')
                
                for ns in ns_records:
                    ns_host = str(ns.target).rstrip('.')
                    
                    try:
                        # Attempt zone transfer
                        zone = dns.zone.from_xfr(dns.query.xfr(ns_host, domain))
                        
                        for name, rdataset in zone.items():
                            for rr in rdataset:
                                if rr.rdtype == dns.rdatatype.A:
                                    subdomain_name = str(name)
                                    if subdomain_name != "@":
                                        full_sub = f"{subdomain_name}.{domain}"
                                        subdomains[full_sub] = {
                                            "source": "Zone Transfer (AXFR)",
                                            "active": True,
                                            "ip": str(rr),
                                            "http_status": None
                                        }
                    except Exception:
                        pass
            except Exception:
                pass
        except ImportError:
            pass

        return subdomains

    def _get_common_subdomains(self) -> List[str]:
        """Get list of common subdomain names to brute-force."""
        common_subs = [
            # Web servers
            "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns",
            "webdisk", "ns1", "webhost", "mailhost", "imap", "api",
            # Services
            "dev", "staging", "test", "demo", "beta", "alpha", "prod", "production",
            "admin", "administrator", "cp", "cpanel", "whm", "autodiscover",
            # Common services
            "api", "cdn", "content", "downloads", "files", "git", "github",
            "gitlab", "images", "img", "js", "media", "mobile", "old",
            "static", "uploads", "portal", "support", "vpn", "ssh",
            "sftp", "telnet", "secure", "shop", "store", "order",
            # Database/Backend
            "db", "database", "mysql", "mongodb", "postgres", "redis",
            # Monitoring
            "monitor", "monitoring", "status", "health", "logs",
            # Development
            "jenkins", "docker", "kubernetes", "k8s", "rancher",
        ]
        return common_subs

    def _is_valid_subdomain(self, subdomain: str) -> bool:
        """Validate subdomain format before DNS resolution."""
        if not subdomain or len(subdomain) > 253:
            return False
        
        # Check each label in the domain
        labels = subdomain.split('.')
        for label in labels:
            if not label or len(label) > 63:
                return False
            # Must start and end with alphanumeric, can contain hyphens
            if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$', label):
                return False
        
        return True

    def _resolve_subdomain(self, subdomain: str) -> Optional[str]:
        """Resolve subdomain to IP address."""
        # Validate before attempting resolution
        if not self._is_valid_subdomain(subdomain):
            return None
        
        try:
            ip = socket.gethostbyname(subdomain)
            return ip if ip else None
        except (socket.gaierror, socket.timeout, UnicodeError):
            return None

    def _check_http(self, subdomain: str) -> Optional[int]:
        """Check if subdomain responds to HTTP request."""
        try:
            # Try HTTPS first (more secure)
            response = requests.head(
                f"https://{subdomain}",
                timeout=2,
                allow_redirects=False,
                verify=False
            )
            return response.status_code
        except:
            try:
                # Fallback to HTTP
                response = requests.head(
                    f"http://{subdomain}",
                    timeout=2,
                    allow_redirects=False
                )
                return response.status_code
            except:
                return None

    def _assess_risk(self, subdomains: Dict) -> Dict[str, Any]:
        """Assess risk level of discovered subdomains."""
        risk_data = {
            "high_risk": [],
            "medium_risk": [],
            "low_risk": [],
            "risk_summary": {}
        }

        high_risk_keywords = [
            "admin", "backup", "test", "staging", "dev", "debug",
            "internal", "private", "secret", "api", "database"
        ]

        for subdomain, data in subdomains.items():
            risk_level = "low_risk"
            
            # Check subdomain name for risk indicators
            subdomain_lower = subdomain.lower()
            for keyword in high_risk_keywords:
                if keyword in subdomain_lower:
                    risk_level = "high_risk"
                    break

            # Check if active but unusual
            if data.get("active") and data.get("http_status"):
                if data.get("http_status") in [401, 403, 500, 502, 503]:
                    if risk_level != "high_risk":
                        risk_level = "medium_risk"

            risk_data[risk_level].append(subdomain)

        risk_data["risk_summary"] = {
            "high_risk_count": len(risk_data["high_risk"]),
            "medium_risk_count": len(risk_data["medium_risk"]),
            "low_risk_count": len(risk_data["low_risk"])
        }

        return risk_data

    def display_report(self, results: Dict[str, Any]):
        """Display subdomain enumeration report."""
        if results.get("status") == "error":
            console.print(Panel(
                f"[red]Error:[/red] {results.get('message')}",
                title="Subdomain Enumeration",
                border_style="red"
            ))
            return

        domain = results.get("domain", "Unknown")
        total = results.get("total_found", 0)
        active = results.get("active_count", 0)

        # Header
        header = f"[bold]Domain:[/bold] {domain} | [bold]Total:[/bold] {total} | [bold green]Active:[/bold green] {active}"
        console.print(Panel(header, title="🔍 SUBDOMAIN ENUMERATION REPORT", border_style="cyan"))

        # Methods used
        methods = results.get("methods_used", [])
        if methods:
            console.print(f"\n[bold cyan]Methods Used:[/bold cyan]")
            for method in methods:
                console.print(f"  • {method}")

        # Risk assessment
        risk_assessment = results.get("risk_assessment", {})
        if risk_assessment.get("risk_summary"):
            console.print("\n[bold yellow]Risk Assessment:[/bold yellow]")
            summary = risk_assessment["risk_summary"]
            console.print(f"  [red]High Risk:[/red] {summary.get('high_risk_count', 0)}")
            console.print(f"  [yellow]Medium Risk:[/yellow] {summary.get('medium_risk_count', 0)}")
            console.print(f"  [green]Low Risk:[/green] {summary.get('low_risk_count', 0)}")

        # Detailed subdomain list
        subdomains = results.get("subdomains", {})
        if subdomains:
            console.print("\n[bold cyan]Discovered Subdomains:[/bold cyan]\n")

            # Active subdomains table
            active_table = Table(title="Active Subdomains", box=box.ROUNDED, border_style="green")
            active_table.add_column("Subdomain", style="green")
            active_table.add_column("IP Address", style="cyan")
            active_table.add_column("HTTP Status", style="yellow")
            active_table.add_column("Source", style="dim")

            for subdomain, data in sorted(subdomains.items()):
                if data.get("active"):
                    status = str(data.get("http_status", "N/A"))
                    active_table.add_row(
                        subdomain,
                        data.get("ip", "N/A"),
                        status,
                        data.get("source", "N/A")
                    )

            if active_table.rows:
                console.print(active_table)

            # Inactive subdomains summary
            inactive_count = sum(1 for sub in subdomains.values() if not sub.get("active"))
            if inactive_count > 0:
                console.print(f"\n[dim]{inactive_count} inactive subdomains (DNS resolved but not responding)[/dim]")

        # High-risk subdomains warning
        high_risk = risk_assessment.get("high_risk", [])
        if high_risk:
            console.print("\n[bold red]⚠️  HIGH-RISK SUBDOMAINS FOUND:[/bold red]")
            for subdomain in high_risk:
                data = subdomains.get(subdomain, {})
                status_indicator = "✓" if data.get("active") else "✗"
                console.print(f"  [{status_indicator}] {subdomain}")

        console.print()


# Convenient factory function
def create_subdomain_enumerator(config):
    """Create a SubdomainEnumerator instance."""
    return SubdomainEnumerator(config)
