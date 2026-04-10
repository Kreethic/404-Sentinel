"""
modules/report_saver.py
========================
Report Saving Utility

Handles saving reports from all modules to file in human-readable format.
"""

import os
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

from rich.console import Console

console = Console()


class ReportSaver:
    """Handles saving analysis reports to disk in human-readable format."""
    LINE_WIDTH = 80
    CONTENT_WIDTH = 76
    
    def __init__(self):
        self.reports_dir = self._ensure_reports_dir()
    
    def _ensure_reports_dir(self) -> str:
        """Create reports directory if it doesn't exist."""
        reports_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "reports")
        Path(reports_path).mkdir(parents=True, exist_ok=True)
        return reports_path
    
    def _pad_line(self, content: str) -> str:
        """Pad line to exact width."""
        return content.ljust(self.CONTENT_WIDTH)
    
    def _box_line(self, content: str = "") -> str:
        """Create a box line with content."""
        if content:
            return "│ " + self._pad_line(content)[:-1] + " │"
        return "│" + self._pad_line("") + "│"
    
    def _format_human_readable(self, module_name: str, data: Dict[str, Any], target: Optional[str]) -> str:
        """Format report data into human-readable cybersecurity theme."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        report = []
        report.append("╔" + "═" * self.CONTENT_WIDTH + "╗")
        report.append(self._box_line("404 SENTINEL - THREAT INTELLIGENCE REPORT"))
        report.append("╚" + "═" * self.CONTENT_WIDTH + "╝")
        report.append("")
        
        # Header Info
        title = "REPORT METADATA"
        spaces = self.CONTENT_WIDTH - len(title) - 4
        report.append("┌─ " + title + " " + "─" * spaces + "┐")
        report.append(self._box_line(f"Module          : {module_name.replace('_', ' ').title()}"))
        report.append(self._box_line(f"Target          : {str(target) if target else 'N/A'}"))
        report.append(self._box_line(f"Generated       : {timestamp}"))
        report.append("└" + "─" * self.CONTENT_WIDTH + "┘")
        report.append("")
        
        # Parse different module types
        if module_name == "ip_reputation":
            report.extend(self._format_ip_reputation(data))
        elif module_name == "phishing_detector":
            report.extend(self._format_phishing_detector(data))
        elif module_name == "email_analyzer":
            report.extend(self._format_email_analyzer(data))
        elif module_name == "domain_whois_analyzer":
            report.extend(self._format_domain_analyzer(data))
        elif module_name == "file_hash_analyzer":
            report.extend(self._format_file_analyzer(data))
        elif module_name == "subdomain_enumerator":
            report.extend(self._format_subdomain_analyzer(data))
        elif module_name == "risk_scorer":
            report.extend(self._format_risk_scorer(data))
        elif module_name == "batch_scan":
            report.extend(self._format_batch_scan(data))
        else:
            report.extend(self._format_generic(data))
        
        # Footer
        report.append("")
        report.append("╔" + "═" * self.CONTENT_WIDTH + "╗")
        report.append(self._box_line("END OF REPORT"))
        report.append("╚" + "═" * self.CONTENT_WIDTH + "╝")
        
        return "\n".join(report)
    
    def _format_ip_reputation(self, data: Dict) -> list:
        """Format IP reputation report."""
        lines = []
        title = "IP/DOMAIN REPUTATION ANALYSIS"
        spaces = self.CONTENT_WIDTH - len(title) - 4
        lines.append("┌─ " + title + " " + "─" * spaces + "┐")
        
        target_type = data.get("type", "N/A")
        lines.append(self._box_line(f"Target Type     : {target_type}"))
        
        # AbuseIPDB
        abuse = data.get("abuseipdb") or {}
        if abuse:
            score = abuse.get('abuse_confidence_score', 0)
            if score > 75:
                risk = "[HIGH RISK]"
            elif score > 25:
                risk = "[SUSPICIOUS]"
            else:
                risk = "[CLEAN]"
            lines.append(self._box_line(f"Abuse Score     : {score}/100 {risk}"))
            lines.append(self._box_line(f"Reports         : {abuse.get('total_reports', 0)}"))
            lines.append(self._box_line(f"ISP             : {abuse.get('isp', 'N/A')}"))
            lines.append(self._box_line(f"Country         : {abuse.get('country_code', 'N/A')}"))
        
        # VirusTotal
        vt = data.get("virustotal") or {}
        if vt:
            lines.append(self._box_line(f"VirusTotal      : {vt.get('malicious', 0)}/90 detected"))
        
        # OTX
        otx = data.get("otx") or {}
        if otx:
            lines.append(self._box_line(f"OTX Pulses      : {len(otx.get('pulses', []))}"))
        
        lines.append("└" + "─" * self.CONTENT_WIDTH + "┘")
        return lines
    
    def _format_phishing_detector(self, data: Dict) -> list:
        """Format phishing detector report."""
        lines = []
        title = "PHISHING URL ANALYSIS"
        spaces = self.CONTENT_WIDTH - len(title) - 4
        lines.append("┌─ " + title + " " + "─" * spaces + "┐")
        
        is_phishing = data.get("is_phishing", False)
        phishing_score = data.get("phishing_score", 0)
        
        risk_label = "[CRITICAL PHISHING]" if is_phishing else "[SAFE]"
        lines.append(self._box_line(f"Status          : {risk_label}"))
        lines.append(self._box_line(f"Phishing Score  : {phishing_score}/100"))
        
        categories = data.get("categories", [])
        if categories:
            cat_str = ", ".join(categories[:3])
            lines.append(self._box_line(f"Categories      : {cat_str}"))
        
        # Detections
        detections = []
        
        phishtank = data.get("phishtank", {})
        if phishtank.get("detected"):
            detections.append("PhishTank")
        
        safe_browsing = data.get("safe_browsing", {})
        if safe_browsing.get("is_malicious"):
            detections.append("Google Safe Browsing")
        
        virustotal = data.get("virustotal", {})
        if virustotal.get("malicious", 0) > 0:
            detections.append(f"VirusTotal ({virustotal['malicious']} engines)")
        
        if detections:
            det_str = ", ".join(detections[:2])
            lines.append(self._box_line(f"Detected By     : {det_str}"))
        
        lines.append("└" + "─" * self.CONTENT_WIDTH + "┘")
        return lines
    
    def _format_email_analyzer(self, data: Dict) -> list:
        """Format email analyzer report."""
        lines = []
        title = "EMAIL HEADER ANALYSIS"
        spaces = self.CONTENT_WIDTH - len(title) - 4
        lines.append("┌─ " + title + " " + "─" * spaces + "┐")
        
        spf_status = data.get("spf_status", "UNKNOWN")
        dkim_status = data.get("dkim_status", "UNKNOWN")
        dmarc_status = data.get("dmarc_status", "UNKNOWN")
        
        lines.append(self._box_line(f"SPF Status      : {spf_status}"))
        lines.append(self._box_line(f"DKIM Status     : {dkim_status}"))
        lines.append(self._box_line(f"DMARC Status    : {dmarc_status}"))
        
        from_addr = data.get("from", "N/A")
        lines.append(self._box_line(f"From Address    : {str(from_addr)[:60]}"))
        
        spoofing_risk = data.get("spoofing_risk", "Unknown")
        lines.append(self._box_line(f"Spoofing Risk   : {spoofing_risk}"))
        
        lines.append("└" + "─" * self.CONTENT_WIDTH + "┘")
        return lines
    
    def _format_domain_analyzer(self, data: Dict) -> list:
        """Format domain analyzer report."""
        lines = []
        title = "DOMAIN/WHOIS ANALYSIS"
        spaces = self.CONTENT_WIDTH - len(title) - 4
        lines.append("┌─ " + title + " " + "─" * spaces + "┐")
        
        domain = data.get("domain", "N/A")
        lines.append(self._box_line(f"Domain          : {domain}"))
        
        registrar = data.get("registrar", "N/A")
        lines.append(self._box_line(f"Registrar       : {str(registrar)[:60]}"))
        
        created = data.get("created_date", "N/A")
        lines.append(self._box_line(f"Created Date    : {str(created)[:60]}"))
        
        expires = data.get("expiration_date", "N/A")
        lines.append(self._box_line(f"Expires         : {str(expires)[:60]}"))
        
        lines.append("└" + "─" * self.CONTENT_WIDTH + "┘")
        return lines
    
    def _format_file_analyzer(self, data: Dict) -> list:
        """Format file analyzer report."""
        lines = []
        title = "FILE/HASH ANALYSIS"
        spaces = self.CONTENT_WIDTH - len(title) - 4
        lines.append("┌─ " + title + " " + "─" * spaces + "┐")
        
        if "md5" in data:
            lines.append(self._box_line(f"MD5             : {data.get('md5', 'N/A')}"))
        if "sha1" in data:
            lines.append(self._box_line(f"SHA1            : {data.get('sha1', 'N/A')}"))
        if "sha256" in data:
            lines.append(self._box_line(f"SHA256          : {data.get('sha256', 'N/A')[:60]}"))
        
        vt_results = data.get("virustotal", {})
        if vt_results:
            malicious = vt_results.get("malicious", 0)
            suspicious = vt_results.get("suspicious", 0)
            lines.append(self._box_line(f"VirusTotal      : {malicious} malicious, {suspicious} suspicious"))
        
        lines.append("└" + "─" * self.CONTENT_WIDTH + "┘")
        return lines
    
    def _format_subdomain_analyzer(self, data: Dict) -> list:
        """Format subdomain analyzer report."""
        lines = []
        title = "SUBDOMAIN ENUMERATION"
        spaces = self.CONTENT_WIDTH - len(title) - 4
        lines.append("┌─ " + title + " " + "─" * spaces + "┐")
        
        domain = data.get("domain", "N/A")
        lines.append(self._box_line(f"Domain          : {domain}"))
        
        total = data.get("total_found", 0)
        active = data.get("active_count", 0)
        lines.append(self._box_line(f"Subdomains Found: {total} found, {active} active"))
        
        methods = data.get("methods_used", [])
        if methods:
            methods_str = ", ".join(methods[:2])
            lines.append(self._box_line(f"Methods Used    : {methods_str}"))
        
        lines.append("└" + "─" * self.CONTENT_WIDTH + "┘")
        return lines
    
    def _format_risk_scorer(self, data: Dict) -> list:
        """Format risk scorer report."""
        lines = []
        title = "UNIFIED RISK SCORE REPORT"
        spaces = self.CONTENT_WIDTH - len(title) - 4
        lines.append("┌─ " + title + " " + "─" * spaces + "┐")
        lines.append(self._box_line("Full threat intelligence aggregation"))
        lines.append("└" + "─" * self.CONTENT_WIDTH + "┘")
        return lines
    
    def _format_batch_scan(self, data: Dict) -> list:
        """Format batch scan report."""
        lines = []
        title = "BATCH SCAN SUMMARY"
        spaces = self.CONTENT_WIDTH - len(title) - 4
        lines.append("┌─ " + title + " " + "─" * spaces + "┐")
        
        targets = data.get("targets_analyzed", 0)
        lines.append(self._box_line(f"Targets Scanned : {targets}"))
        
        results = data.get("results", [])
        if results:
            high_risk = sum(1 for r in results if r.get("score", 0) > 60)
            lines.append(self._box_line(f"High Risk Found : {high_risk}"))
        
        lines.append("└" + "─" * self.CONTENT_WIDTH + "┘")
        return lines
    
    def _format_generic(self, data: Dict) -> list:
        """Format generic report."""
        lines = []
        title = "ANALYSIS DATA"
        spaces = self.CONTENT_WIDTH - len(title) - 4
        lines.append("┌─ " + title + " " + "─" * spaces + "┐")
        
        for key, value in list(data.items())[:15]:
            key_str = str(key)[:20]
            val_str = str(value)[:50]
            lines.append(self._box_line(f"{key_str:<20} : {val_str}"))
        
        lines.append("└" + "─" * self.CONTENT_WIDTH + "┘")
        return lines
    
    def save_report(self, module_name: str, data: Dict[str, Any], target: Optional[str] = None) -> str:
        """
        Save a report to file in human-readable format.
        
        Args:
            module_name: Name of the module (e.g., 'ip_reputation', 'phishing_detector')
            data: Report data to save
            target: Target being analyzed (used in filename)
        
        Returns:
            Path to saved file
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Create safer filename from target
        safe_target = target.replace("/", "_").replace("\\", "_").replace(":", "_").replace("?", "_") if target else "report"
        safe_target = safe_target[:50]  # Limit length
        
        filename = f"{module_name}_{safe_target}_{timestamp}.txt"
        filepath = os.path.join(self.reports_dir, filename)
        
        try:
            # Format report
            formatted_report = self._format_human_readable(module_name, data, target)
            
            # Save to file
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(formatted_report)
            
            console.print(f"[green]✓ Report saved to: [bold]{filepath}[/bold][/green]")
            return filepath
        
        except Exception as e:
            console.print(f"[red]✗ Failed to save report: {e}[/red]")
            return ""


# Create global instance
report_saver = ReportSaver()


def save_report(module_name: str, data: Dict[str, Any], target: Optional[str] = None) -> str:
    """Convenience function to save a report."""
    return report_saver.save_report(module_name, data, target)
