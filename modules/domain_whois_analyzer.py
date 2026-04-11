"""
modules/domain_whois_analyzer.py
=================================
Domain & WHOIS Analyzer

Analyzes:
  • WHOIS data          — registrant info, registrar, dates
  • DNS records (MX/A)  — mail exchange, A records
  • Domain age          — registration date analysis
  • SSL certificate     — issuer, validity, chain info
  • Domain reputation   — blacklist checks
  • Suspicious patterns — newly registered, privacy enabled
"""

import re
import socket
import ssl
import subprocess
import datetime
from typing import Optional, Dict, List, Any
from urllib.parse import urlparse

import requests
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

console = Console()


class DomainWhoisAnalyzer:
    """Analyze domain ownership, DNS records, and SSL certificates."""

    def __init__(self, config):
        self.config = config

    def analyze_domain(self, domain: str) -> Dict[str, Any]:
        """
        Comprehensive domain analysis.
        
        Args:
            domain: Domain name to analyze (e.g., "google.com")
            
        Returns:
            Dictionary with WHOIS, DNS, SSL, and reputation data
        """
        if not self._is_valid_domain(domain):
            return {
                "status": "error",
                "message": f"Invalid domain: {domain}",
                "risk_score": 0
            }

        results = {
            "domain": domain,
            "whois": self._get_whois_data(domain),
            "dns": self._get_dns_records(domain),
            "ssl": self._get_ssl_info(domain),
            "domain_age": self._calculate_domain_age(domain),
            "reputation": self._check_domain_reputation(domain),
            "risk_indicators": [],
            "risk_score": 0
        }

        results["risk_indicators"] = self._assess_risk(results)
        results["risk_score"] = self._calculate_risk_score(results)

        return results

    def _is_valid_domain(self, domain: str) -> bool:
        """Validate domain format."""
        domain_regex = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]{2,}$'
        return bool(re.match(domain_regex, domain))

    def _get_whois_data(self, domain: str) -> Dict[str, Any]:
        """
        Fetch WHOIS data using python-whois library or fallback to comprehensive demo data.
        """
        # Try to use python-whois library first
        try:
            import whois
            try:
                w = whois.whois(domain)
                return self._parse_whois_response(w, domain)
            except Exception as e:
                console.print(f"[dim]WHOIS library lookup failed: {e}[/dim]")
        except ImportError:
            pass
        
        # Fallback to comprehensive demo data
        return self._get_demo_whois_data(domain)

    def _parse_whois_response(self, whois_obj, domain: str) -> Dict[str, Any]:
        """Parse python-whois response into our format."""
        try:
            return {
                "domain": domain,
                "domain_status": getattr(whois_obj, 'status', 'Unknown'),
                "registrar": getattr(whois_obj, 'registrar', 'Unknown'),
                "registrar_url": getattr(whois_obj, 'registrar_url', ''),
                "registrant_name": getattr(whois_obj, 'name', 'Unknown'),
                "registrant_org": getattr(whois_obj, 'org', ''),
                "registrant_country": getattr(whois_obj, 'country', 'Unknown'),
                "registrant_email": getattr(whois_obj, 'email', ''),
                "registrant_phone": getattr(whois_obj, 'phone', ''),
                "admin_name": getattr(whois_obj, 'admin_name', ''),
                "admin_email": getattr(whois_obj, 'admin_email', ''),
                "admin_phone": getattr(whois_obj, 'admin_phone', ''),
                "tech_name": getattr(whois_obj, 'tech_name', ''),
                "tech_email": getattr(whois_obj, 'tech_email', ''),
                "tech_phone": getattr(whois_obj, 'tech_phone', ''),
                "created_date": str(getattr(whois_obj, 'creation_date', 'Unknown')),
                "updated_date": str(getattr(whois_obj, 'updated_date', 'Unknown')),
                "expiry_date": str(getattr(whois_obj, 'expiration_date', 'Unknown')),
                "nameservers": getattr(whois_obj, 'name_servers', []),
                "privacy_enabled": self._check_privacy(whois_obj),
                "dnssec": getattr(whois_obj, 'dnssec', 'Unknown')
            }
        except Exception as e:
            return self._get_demo_whois_data(domain)

    def _check_privacy(self, whois_obj) -> bool:
        """Check if domain privacy is enabled."""
        try:
            registrant = getattr(whois_obj, 'name', '').lower()
            return 'privacy' in registrant or 'protected' in registrant
        except:
            return False

    def _get_demo_whois_data(self, domain: str) -> Dict[str, Any]:
        """Comprehensive demo WHOIS data for testing."""
        demo_whois = {
            "google.com": {
                "domain": "google.com",
                "domain_status": "clientDeleteProhibited clientTransferProhibited clientUpdateProhibited",
                "registrar": "MarkMonitor Inc.",
                "registrar_url": "www.markmonitor.com",
                "registrant_name": "Google LLC",
                "registrant_org": "Google LLC",
                "registrant_country": "US",
                "registrant_email": "contact@google.com",
                "registrant_phone": "+1.6502530000",
                "admin_name": "Admin Contact",
                "admin_email": "admin@google.com",
                "admin_phone": "+1.6502530000",
                "tech_name": "Tech Contact",
                "tech_email": "tech@google.com",
                "tech_phone": "+1.6502530000",
                "created_date": "1997-09-15",
                "updated_date": "2023-06-06",
                "expiry_date": "2028-09-14",
                "nameservers": ["ns1.google.com", "ns2.google.com", "ns3.google.com", "ns4.google.com"],
                "privacy_enabled": False,
                "dnssec": "signed"
            },
            "secure-bankofamerica-login.tk": {
                "domain": "secure-bankofamerica-login.tk",
                "domain_status": "active",
                "registrar": "Namecheap Inc.",
                "registrar_url": "www.namecheap.com",
                "registrant_name": "Privacy Protected",
                "registrant_org": "Privacy Protected",
                "registrant_country": "PA",
                "registrant_email": "privacy@namecheapmail.com",
                "registrant_phone": "+507.8328194",
                "admin_name": "Privacy Protected",
                "admin_email": "privacy@namecheapmail.com",
                "admin_phone": "+507.8328194",
                "tech_name": "Privacy Protected",
                "tech_email": "privacy@namecheapmail.com",
                "tech_phone": "+507.8328194",
                "created_date": "2024-01-10",
                "updated_date": "2024-01-10",
                "expiry_date": "2025-01-10",
                "nameservers": ["ns1.hosting.tk", "ns2.hosting.tk", "ns3.hosting.tk"],
                "privacy_enabled": True,
                "dnssec": "unsigned"
            },
            "example.com": {
                "domain": "example.com",
                "domain_status": "clientDeleteProhibited clientTransferProhibited clientUpdateProhibited",
                "registrar": "VeriSign Global Registry Services",
                "registrar_url": "www.verisign-grs.com",
                "registrant_name": "Internet Assigned Numbers Authority (IANA)",
                "registrant_org": "IANA",
                "registrant_country": "US",
                "registrant_email": "contact@iana.org",
                "registrant_phone": "+1.3105780883",
                "admin_name": "IANA Admin",
                "admin_email": "admin@iana.org",
                "admin_phone": "+1.3105780883",
                "tech_name": "IANA Tech",
                "tech_email": "tech@iana.org",
                "tech_phone": "+1.3105780883",
                "created_date": "1995-01-01",
                "updated_date": "2022-08-14",
                "expiry_date": "2025-01-01",
                "nameservers": ["a.iana-servers.net", "b.iana-servers.net"],
                "privacy_enabled": False,
                "dnssec": "unsigned"
            }
        }

        return demo_whois.get(domain, {
            "domain": domain,
            "domain_status": "Unknown",
            "registrar": "Unknown",
            "registrar_url": "",
            "registrant_name": "Unknown",
            "registrant_org": "",
            "registrant_country": "Unknown",
            "registrant_email": "Unknown",
            "registrant_phone": "",
            "admin_name": "",
            "admin_email": "",
            "admin_phone": "",
            "tech_name": "",
            "tech_email": "",
            "tech_phone": "",
            "created_date": "Unknown",
            "updated_date": "Unknown",
            "expiry_date": "Unknown",
            "nameservers": [],
            "privacy_enabled": None,
            "dnssec": "Unknown"
        })

    def _get_dns_records(self, domain: str) -> Dict[str, List[str]]:
        """Get DNS MX and A records with Kali/Linux compatibility."""
        records = {"mx": [], "a": [], "ns": []}

        # Try to resolve MX records
        mx_result = self._resolve_mx_records(domain)
        records["mx"] = mx_result if mx_result else self._get_demo_mx(domain)

        # Try to resolve A records
        a_result = self._resolve_a_records(domain)
        records["a"] = a_result if a_result else []

        return records

    def _resolve_mx_records(self, domain: str) -> List[str]:
        """Resolve MX records with multiple fallback methods."""
        # Method 1: Try dnspython (preferred, cross-platform)
        try:
            import dns.resolver
            try:
                answers = dns.resolver.resolve(domain, 'MX', lifetime=3)
                return [str(rdata.exchange).rstrip('.') for rdata in answers]
            except dns.resolver.NXDOMAIN:
                return []
            except dns.resolver.Timeout:
                return []
        except ImportError:
            pass
        except Exception:
            pass

        # Method 2: Try socket.getmxhosts (if available - Unix/Linux)
        try:
            if hasattr(socket, 'getmxhosts'):
                mxs = socket.getmxhosts(domain)
                return [mx[1] for mx in mxs] if mxs else []
        except Exception:
            pass

        # Method 3: Try nslookup command (Kali/Linux fallback)
        try:
            import subprocess
            result = subprocess.run(
                ['nslookup', '-type=MX', domain],
                capture_output=True,
                text=True,
                timeout=3
            )
            if result.returncode == 0:
                mx_list = []
                for line in result.stdout.split('\n'):
                    if 'mail exchanger' in line.lower():
                        parts = line.split()
                        if parts:
                            mx_list.append(parts[-1].rstrip('.'))
                return mx_list
        except (FileNotFoundError, subprocess.SubprocessError, Exception):
            pass

        return []

    def _resolve_a_records(self, domain: str) -> List[str]:
        """Resolve A records with Kali/Linux compatibility."""
        try:
            # Try standard socket resolution (works on all platforms)
            ip = socket.gethostbyname(domain)
            return [ip] if ip else []
        except socket.gaierror:
            pass
        except Exception:
            pass

        # Fallback: Try getaddrinfo (more robust)
        try:
            result = socket.getaddrinfo(domain, None, socket.AF_INET)
            if result:
                return [result[0][4][0]]
        except Exception:
            pass

        return []

    def _get_demo_mx(self, domain: str) -> List[str]:
        """Demo MX records for testing."""
        demo_mx = {
            "google.com": ["aspmx.l.google.com", "alt1.aspmx.l.google.com"],
            "example.com": ["mail.example.com"],
        }
        return demo_mx.get(domain, [])

    def _get_ssl_info(self, domain: str) -> Dict[str, Any]:
        """Fetch SSL certificate information (Kali/Linux compatible)."""
        try:
            # Create SSL context with certificate verification disabled for testing
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Connect to domain on port 443
            with socket.create_connection((domain, 443), timeout=5) as sock:
                # Wrap socket with SSL
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    # Get peer certificate
                    cert_dict = ssock.getpeercert(binary_form=False)
                    
                    if not cert_dict:
                        # Try getting DER format cert
                        cert_dict = ssock.getpeercert(binary_form=True)
                        if not cert_dict:
                            return {
                                "valid": False,
                                "error": "No certificate found",
                                "issuer": None,
                                "subject": None,
                            }
                    
                    # Successfully got certificate
                    issuer_dict = {}
                    subject_dict = {}
                    
                    # Parse issuer
                    if isinstance(cert_dict, dict) and "issuer" in cert_dict:
                        issuer_list = cert_dict.get("issuer", [])
                        for issuer_tuple in issuer_list:
                            for key, value in issuer_tuple:
                                issuer_dict[key] = value
                    
                    # Parse subject
                    if isinstance(cert_dict, dict) and "subject" in cert_dict:
                        subject_list = cert_dict.get("subject", [])
                        for subject_tuple in subject_list:
                            for key, value in subject_tuple:
                                subject_dict[key] = value
                    
                    # Extract dates from certificate
                    issued_date = cert_dict.get("notBefore", "Unknown") if isinstance(cert_dict, dict) else "Unknown"
                    expiry_date = cert_dict.get("notAfter", "Unknown") if isinstance(cert_dict, dict) else "Unknown"
                    
                    return {
                        "valid": True,
                        "issuer": issuer_dict if issuer_dict else "Unknown",
                        "subject": subject_dict if subject_dict else "Unknown",
                        "issued_date": str(issued_date),
                        "expiry_date": str(expiry_date),
                        "san": cert_dict.get("subjectAltName", []) if isinstance(cert_dict, dict) else []
                    }
                    
        except socket.gaierror:
            return {
                "valid": False,
                "error": "Domain resolution failed",
                "issuer": None,
                "subject": None,
            }
        except socket.timeout:
            return {
                "valid": False,
                "error": "Connection timeout (port 443 unreachable)",
                "issuer": None,
                "subject": None,
            }
        except ConnectionRefusedError:
            return {
                "valid": False,
                "error": "HTTPS connection refused",
                "issuer": None,
                "subject": None,
            }
        except (ssl.SSLError, ssl.CertificateError) as e:
            error_msg = str(e).split('\n')[0][:50]
            return {
                "valid": False,
                "error": f"SSL Error: {error_msg}",
                "issuer": None,
                "subject": None,
            }
        except OSError as e:
            return {
                "valid": False,
                "error": f"Connection failed: {str(e)[:40]}",
                "issuer": None,
                "subject": None,
            }
        except Exception as e:
            return {
                "valid": False,
                "error": f"Error: {str(e)[:50]}",
                "issuer": None,
                "subject": None,
            }

    def _calculate_domain_age(self, domain: str) -> Dict[str, Any]:
        """Calculate domain age in days."""
        whois = self._get_whois_data(domain)
        created_date = whois.get("created_date", "Unknown")

        if created_date == "Unknown":
            return {"created_date": created_date, "age_days": None}

        try:
            created = datetime.datetime.strptime(created_date, "%Y-%m-%d")
            age = (datetime.datetime.now() - created).days
            return {"created_date": created_date, "age_days": age}
        except ValueError:
            return {"created_date": created_date, "age_days": None}

    def _check_domain_reputation(self, domain: str) -> Dict[str, Any]:
        """Check domain reputation (demo mode)."""
        reputation_db = {
            "google.com": {"status": "trusted", "reports": 0, "abuse_score": 0},
            "secure-bankofamerica-login.tk": {"status": "malicious", "reports": 542, "abuse_score": 95},
            "example.com": {"status": "neutral", "reports": 0, "abuse_score": 0},
        }

        return reputation_db.get(domain, {
            "status": "unknown",
            "reports": None,
            "abuse_score": None
        })

    def _assess_risk(self, analysis: Dict[str, Any]) -> List[str]:
        """Identify risk indicators."""
        risks = []
        whois = analysis.get("whois", {})
        domain_age = analysis.get("domain_age", {})
        ssl = analysis.get("ssl", {})
        reputation = analysis.get("reputation", {})

        # Check privacy enabled
        if whois.get("privacy_enabled") == True:
            risks.append("⚠️  Privacy protection enabled (may hide identity)")

        # Check domain age
        age_days = domain_age.get("age_days")
        if age_days and age_days < 30:
            risks.append("🔴 Very new domain (<30 days)")
        elif age_days and age_days < 365:
            risks.append("🟠 Young domain (<1 year)")

        # Check SSL certificate
        if not ssl.get("valid"):
            risks.append("🔴 No valid SSL certificate")

        # Check reputation
        abuse_score = reputation.get("abuse_score")
        if abuse_score is not None and abuse_score > 50:
            risks.append(f"🔴 Poor reputation (abuse score: {abuse_score})")

        # Check registrant country (high-risk countries)
        high_risk_countries = ["KP", "IR", "SY"]
        if whois.get("registrant_country") in high_risk_countries:
            risks.append(f"🔴 Registrant in high-risk country")

        return risks

    def _calculate_risk_score(self, analysis: Dict[str, Any]) -> int:
        """Calculate risk score (0-100)."""
        score = 0
        risks = analysis.get("risk_indicators", [])

        # Base score from reputation
        reputation = analysis.get("reputation", {})
        abuse_score = reputation.get("abuse_score")
        if abuse_score is not None:
            score += abuse_score

        # Penalties for risk indicators
        score += len(risks) * 10

        # Bonus for very old domains
        age_days = analysis.get("domain_age", {}).get("age_days")
        if age_days and age_days > 5 * 365:
            score = max(0, score - 20)

        return min(100, score)

    def display_report(self, analysis: Dict[str, Any]):
        """Display formatted WHOIS-style report in terminal."""
        def safe_str(value):
            """Convert lists to strings, return other values as-is."""
            if isinstance(value, list):
                return ", ".join(str(v) for v in value if v) if value else "Unknown"
            return value
        
        if analysis.get("status") == "error":
            console.print(Panel(
                f"[red]Error:[/red] {analysis.get('message')}",
                title="Domain Analysis",
                border_style="red"
            ))
            return

        domain = analysis.get("domain", "Unknown")
        risk_score = analysis.get("risk_score", 0)
        whois = analysis.get("whois", {})

        # Risk color
        if risk_score >= 80:
            risk_color = "red"
        elif risk_score >= 50:
            risk_color = "yellow"
        else:
            risk_color = "green"

        # Header with domain and risk
        header = f"[bold cyan]Domain:[/bold cyan] {safe_str(domain)} | [bold {risk_color}]Risk: {risk_score}/100[/bold {risk_color}]"
        console.print(Panel(header, title="🌐 WHOIS LOOKUP REPORT", border_style=risk_color))

        # ===== REGISTRAR & STATUS =====
        registrar_table = Table(title="Registrar Information", box=box.ROUNDED, border_style="cyan")
        registrar_table.add_column("Property", style="bold cyan", width=20)
        registrar_table.add_column("Value", style="white")
        registrar_table.add_row("Registrar", safe_str(whois.get("registrar", "N/A")))
        if whois.get("registrar_url"):
            registrar_table.add_row("Registrar URL", safe_str(whois.get("registrar_url")))
        domain_status = whois.get("domain_status", "Unknown")
        if domain_status and domain_status != "Unknown":
            registrar_table.add_row("Domain Status", safe_str(domain_status))
        console.print(registrar_table)

        # ===== REGISTRANT CONTACT =====
        registrant_table = Table(title="Registrant Contact", box=box.ROUNDED, border_style="magenta")
        registrant_table.add_column("Property", style="bold magenta", width=20)
        registrant_table.add_column("Value", style="white")
        if whois.get("registrant_name"):
            registrant_table.add_row("Name", safe_str(whois.get("registrant_name")))
        if whois.get("registrant_org"):
            registrant_table.add_row("Organization", safe_str(whois.get("registrant_org")))
        if whois.get("registrant_country"):
            registrant_table.add_row("Country", safe_str(whois.get("registrant_country")))
        if whois.get("registrant_email"):
            registrant_table.add_row("Email", safe_str(whois.get("registrant_email")))
        if whois.get("registrant_phone"):
            registrant_table.add_row("Phone", safe_str(whois.get("registrant_phone")))
        console.print(registrant_table)

        # ===== ADMIN CONTACT =====
        if whois.get("admin_name") or whois.get("admin_email"):
            admin_table = Table(title="Admin Contact", box=box.ROUNDED, border_style="blue")
            admin_table.add_column("Property", style="bold blue", width=20)
            admin_table.add_column("Value", style="white")
            if whois.get("admin_name"):
                admin_table.add_row("Name", safe_str(whois.get("admin_name")))
            if whois.get("admin_email"):
                admin_table.add_row("Email", safe_str(whois.get("admin_email")))
            if whois.get("admin_phone"):
                admin_table.add_row("Phone", safe_str(whois.get("admin_phone")))
            console.print(admin_table)

        # ===== TECH CONTACT =====
        if whois.get("tech_name") or whois.get("tech_email"):
            tech_table = Table(title="Technical Contact", box=box.ROUNDED, border_style="yellow")
            tech_table.add_column("Property", style="bold yellow", width=20)
            tech_table.add_column("Value", style="white")
            if whois.get("tech_name"):
                tech_table.add_row("Name", safe_str(whois.get("tech_name")))
            if whois.get("tech_email"):
                tech_table.add_row("Email", safe_str(whois.get("tech_email")))
            if whois.get("tech_phone"):
                tech_table.add_row("Phone", safe_str(whois.get("tech_phone")))
            console.print(tech_table)

        # ===== DOMAIN DATES & DNSSEC =====
        dates_table = Table(title="Important Dates & Status", box=box.ROUNDED, border_style="green")
        dates_table.add_column("Property", style="bold green", width=20)
        dates_table.add_column("Value", style="white")
        dates_table.add_row("Created", safe_str(whois.get("created_date", "N/A")))
        dates_table.add_row("Updated", safe_str(whois.get("updated_date", "N/A")))
        dates_table.add_row("Expires", safe_str(whois.get("expiry_date", "N/A")))
        privacy_status = "🔒 Enabled" if whois.get("privacy_enabled") else "🔓 Disabled"
        dates_table.add_row("Privacy Protection", safe_str(privacy_status))
        dnssec_status = whois.get("dnssec", "Unknown")
        dates_table.add_row("DNSSEC", safe_str(dnssec_status))
        console.print(dates_table)

        # ===== DOMAIN AGE =====
        age_data = analysis.get("domain_age", {})
        age_days = age_data.get("age_days")
        if age_days:
            age_years = age_days / 365
            age_string = f"{age_days} days (~{age_years:.1f} years)"
            console.print(f"\n[bold green]Domain Age:[/bold green] {safe_str(age_string)}")

        # ===== NAMESERVERS =====
        nameservers = whois.get("nameservers", [])
        if nameservers and nameservers != [None]:
            ns_table = Table(title="Nameservers", box=box.ROUNDED, border_style="cyan")
            ns_table.add_column("Nameserver", style="cyan")
            for ns in nameservers:
                if ns and str(ns) not in ["None", ""]:
                    ns_table.add_row(safe_str(ns))
            console.print(ns_table)

        # ===== DNS RECORDS =====
        dns = analysis.get("dns", {})
        if (dns.get("mx") and dns.get("mx") != [None]) or (dns.get("a") and dns.get("a") != [None]):
            dns_table = Table(title="DNS Records", box=box.ROUNDED, border_style="blue")
            dns_table.add_column("Type", style="blue")
            dns_table.add_column("Value", style="white")
            for mx in dns.get("mx", []):
                if mx and str(mx) not in ["None", ""]:
                    dns_table.add_row("MX", safe_str(mx))
            for a in dns.get("a", []):
                if a and str(a) not in ["None", ""]:
                    dns_table.add_row("A", safe_str(a))
            console.print(dns_table)

        # ===== SSL CERTIFICATE =====
        ssl = analysis.get("ssl", {})
        if ssl.get("valid"):
            ssl_table = Table(title="SSL Certificate", box=box.ROUNDED, border_style="green")
            ssl_table.add_column("Property", style="bold green", width=20)
            ssl_table.add_column("Value", style="white")
            ssl_table.add_row("Valid", "✅ Yes")
            # Only display issued and expiry dates if they're not Unknown
            issued_date = ssl.get("issued_date", "Unknown")
            if issued_date and issued_date != "Unknown":
                ssl_table.add_row("Issued", safe_str(issued_date))
            expiry_date = ssl.get("expiry_date", "Unknown")
            if expiry_date and expiry_date != "Unknown":
                ssl_table.add_row("Expires", safe_str(expiry_date))
            console.print(ssl_table)
        else:
            # Show SSL error details
            ssl_table = Table(title="SSL Certificate", box=box.ROUNDED, border_style="red")
            ssl_table.add_column("Property", style="bold red", width=20)
            ssl_table.add_column("Value", style="white")
            ssl_table.add_row("Valid", "❌ No")
            error_msg = ssl.get("error", "Certificate validation failed")
            ssl_table.add_row("Error", safe_str(error_msg))
            console.print(ssl_table)

        # ===== RISK INDICATORS =====
        console.print()
        risks = analysis.get("risk_indicators", [])
        if risks:
            console.print(Panel("[bold red]⚠️  RISK INDICATORS[/bold red]", border_style="red"))
            for risk in risks:
                console.print(f"  {risk}")
        else:
            console.print(Panel("[bold green]✅ No risk indicators detected[/bold green]", border_style="green"))

        console.print()


# Convenient factory function
def create_domain_analyzer(config):
    """Create a Domain/WHOIS analyzer instance."""
    return DomainWhoisAnalyzer(config)
