"""
modules/report_saver.py
========================
Report Saving Utility

Handles saving reports from all modules to file in JSON/TXT format.
"""

import os
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

from rich.console import Console

console = Console()


class ReportSaver:
    """Handles saving analysis reports to disk."""
    
    def __init__(self):
        self.reports_dir = self._ensure_reports_dir()
    
    def _ensure_reports_dir(self) -> str:
        """Create reports directory if it doesn't exist."""
        reports_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "reports")
        Path(reports_path).mkdir(parents=True, exist_ok=True)
        return reports_path
    
    def save_report(self, module_name: str, data: Dict[str, Any], target: Optional[str] = None) -> str:
        """
        Save a report to file.
        
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
        
        filename = f"{module_name}_{safe_target}_{timestamp}.json"
        filepath = os.path.join(self.reports_dir, filename)
        
        try:
            # Add metadata
            report = {
                "module": module_name,
                "timestamp": datetime.now().isoformat(),
                "target": target,
                "data": data
            }
            
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            
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
