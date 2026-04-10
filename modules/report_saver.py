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
    
    def __init__(self):
        self.reports_dir = self._ensure_reports_dir()
    
    def _ensure_reports_dir(self) -> str:
        """Create reports directory if it doesn't exist."""
        reports_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "reports")
        Path(reports_path).mkdir(parents=True, exist_ok=True)
        return reports_path
    
    def _format_human_readable(self, module_name: str, data: Dict[str, Any], target: Optional[str]) -> str:
        """Format report data into human-readable cybersecurity theme."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        report = []
        report.append("╔" + "═" * 78 + "╗")
        report.append("║" + " " * 78 + "║")
        report.append("║" + "404 SENTINEL - THREAT INTELLIGENCE REPORT".center(78) + "║")
        report.append("║" + " " * 78 + "║")
        report.append("╚" + "═" * 78 + "╝")
        report.append("")
        
        # Header Info
        report.append("┌─ REPORT METADATA " + "─" * 60 + "┐")
        report.append(f"│ Module          : {module_name.replace('_', ' ').title():<58} │")
        report.append(f"│ Target          : {str(target)[:58]:<58} │")
        report.append(f"│ Generated       : {timestamp:<58} │")
        report.append("└" + "─" * 77 + "┘")
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
        report.append("┌" + "─" * 77 + "┐")
        report.append("│ End of Report - 404 SENTINEL Threat Intelligence Platform          │")
        report.append("└" + "─" * 77 + "┘")
        
        return "\n".join(report)
    
    def _format_ip_reputation(self, data: Dict) -> list:
        """Format IP reputation report."""
        lines = []
        lines.append("┌─ IP/DOMAIN REPUTATION ANALYSIS " + "─" * 44 + "┐")
        
        target = data.get("target", "N/A")
        target_type = data.get("type", "N/A")
        lines.append(f"│ Target Type     : {target_type:<58} │")
        
        # AbuseIPDB
        abuse = data.get("abuseipdb") or {}
        if abuse:
            lines.append(f"│ Abuse Score     : {str(abuse.get('abuse_confidence_score', 'N/A'))}/100 {'[HIGH RISK]' if abuse.get('abuse_confidence_score', 0) > 75 else '[SUSPICIOUS]' if abuse.get('abuse_confidence_score', 0) > 25 else '[CLEAN]':<33}")
            lines.append(f"│ Reports         : {str(abuse.get('total_reports', 0)):<58} │")
            lines.append(f"│ ISP             : {str(abuse.get('isp', 'N/A'))[:58]:<58} │")
            lines.append(f"│ Country         : {str(abuse.get('country_code', 'N/A')):<58} │")
        
        # VirusTotal
        vt = data.get("virustotal") or {}
        if vt:
            lines.append(f"│ VirusTotal Hits : {str(vt.get('malicious', 0))}/90 engines detected │")
        
        # OTX
        otx = data.get("otx") or {}
        if otx:
            lines.append(f"│ OTX Pulses      : {str(len(otx.get('pulses', []))):<58} │")
        
        lines.append("└" + "─" * 77 + "┘")
        return lines
    
    def _format_phishing_detector(self, data: Dict) -> list:
        """Format phishing detector report."""
        lines = []
        lines.append("┌─ PHISHING URL ANALYSIS " + "─" * 53 + "┐")
        
        is_phishing = data.get("is_phishing", False)
        phishing_score = data.get("phishing_score", 0)
        
        risk_label = "[CRITICAL PHISHING]" if is_phishing else "[SAFE]"
        lines.append(f"│ Status          : {risk_label:<58} │")
        lines.append(f"│ Phishing Score  : {phishing_score}/100                                         │")
        
        categories = data.get("categories", [])
        if categories:
            cat_str = ", ".join(categories[:3])
            lines.append(f"│ Categories      : {cat_str[:58]:<58} │")
        
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
            lines.append(f"│ Detected By     : {det_str[:58]:<58} │")
        
        lines.append("└" + "─" * 77 + "┘")
        return lines
    
    def _format_email_analyzer(self, data: Dict) -> list:
        """Format email analyzer report."""
        lines = []
        lines.append("┌─ EMAIL HEADER ANALYSIS " + "─" * 53 + "┐")
        
        spf_status = data.get("spf_status", "UNKNOWN")
        dkim_status = data.get("dkim_status", "UNKNOWN")
        dmarc_status = data.get("dmarc_status", "UNKNOWN")
        
        lines.append(f"│ SPF Status      : {spf_status:<58} │")
        lines.append(f"│ DKIM Status     : {dkim_status:<58} │")
        lines.append(f"│ DMARC Status    : {dmarc_status:<58} │")
        
        from_addr = data.get("from", "N/A")
        lines.append(f"│ From Address    : {str(from_addr)[:58]:<58} │")
        
        spoofing_risk = data.get("spoofing_risk", "Unknown")
        lines.append(f"│ Spoofing Risk   : {spoofing_risk:<58} │")
        
        lines.append("└" + "─" * 77 + "┘")
        return lines
    
    def _format_domain_analyzer(self, data: Dict) -> list:
        """Format domain analyzer report."""
        lines = []
        lines.append("┌─ DOMAIN/WHOIS ANALYSIS " + "─" * 53 + "┐")
        
        domain = data.get("domain", "N/A")
        lines.append(f"│ Domain          : {domain:<58} │")
        
        registrar = data.get("registrar", "N/A")
        lines.append(f"│ Registrar       : {str(registrar)[:58]:<58} │")
        
        created = data.get("created_date", "N/A")
        lines.append(f"│ Created Date    : {str(created)[:58]:<58} │")
        
        expires = data.get("expiration_date", "N/A")
        lines.append(f"│ Expires         : {str(expires)[:58]:<58} │")
        
        lines.append("└" + "─" * 77 + "┘")
        return lines
    
    def _format_file_analyzer(self, data: Dict) -> list:
        """Format file analyzer report."""
        lines = []
        lines.append("┌─ FILE/HASH ANALYSIS " + "─" * 56 + "┐")
        
        if "md5" in data:
            lines.append(f"│ MD5             : {data.get('md5', 'N/A'):<58} │")
        if "sha1" in data:
            lines.append(f"│ SHA1            : {data.get('sha1', 'N/A'):<58} │")
        if "sha256" in data:
            lines.append(f"│ SHA256          : {data.get('sha256', 'N/A')[:58]:<58} │")
        
        vt_results = data.get("virustotal", {})
        if vt_results:
            malicious = vt_results.get("malicious", 0)
            suspicious = vt_results.get("suspicious", 0)
            lines.append(f"│ VirusTotal      : {malicious} malicious, {suspicious} suspicious     │")
        
        lines.append("└" + "─" * 77 + "┘")
        return lines
    
    def _format_subdomain_analyzer(self, data: Dict) -> list:
        """Format subdomain analyzer report."""
        lines = []
        lines.append("┌─ SUBDOMAIN ENUMERATION " + "─" * 53 + "┐")
        
        domain = data.get("domain", "N/A")
        lines.append(f"│ Domain          : {domain:<58} │")
        
        total = data.get("total_found", 0)
        active = data.get("active_count", 0)
        lines.append(f"│ Subdomains Found: {total} total, {active} active                     │")
        
        methods = data.get("methods_used", [])
        if methods:
            methods_str = ", ".join(methods[:2])
            lines.append(f"│ Methods Used    : {methods_str[:58]:<58} │")
        
        lines.append("└" + "─" * 77 + "┘")
        return lines
    
    def _format_risk_scorer(self, data: Dict) -> list:
        """Format risk scorer report."""
        lines = []
        lines.append("┌─ UNIFIED RISK SCORE REPORT " + "─" * 49 + "┐")
        lines.append("│ (Full threat intelligence aggregation)                                     │")
        lines.append("└" + "─" * 77 + "┘")
        return lines
    
    def _format_batch_scan(self, data: Dict) -> list:
        """Format batch scan report."""
        lines = []
        lines.append("┌─ BATCH SCAN SUMMARY " + "─" * 56 + "┐")
        
        targets = data.get("targets_analyzed", 0)
        lines.append(f"│ Targets Scanned : {targets:<58} │")
        
        results = data.get("results", [])
        if results:
            high_risk = sum(1 for r in results if r.get("score", 0) > 60)
            lines.append(f"│ High Risk Found : {high_risk:<58} │")
        
        lines.append("└" + "─" * 77 + "┘")
        return lines
    
    def _format_generic(self, data: Dict) -> list:
        """Format generic report."""
        lines = []
        lines.append("┌─ ANALYSIS DATA " + "─" * 61 + "┐")
        lines.append("│ Key                              | Value                               │")
        lines.append("├" + "─" * 77 + "┤")
        
        for key, value in list(data.items())[:10]:
            key_str = str(key)[:30]
            val_str = str(value)[:42]
            lines.append(f"│ {key_str:<32} | {val_str:<42} │")
        
        lines.append("└" + "─" * 77 + "┘")
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
