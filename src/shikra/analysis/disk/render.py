import json
from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime
import logging

from jinja2 import Environment, FileSystemLoader, Template
from ...utils.logger import setup_logger

class DiskReportRenderer:
    """
    Renders disk analysis reports into HTML and PDF formats using Jinja2 templates.
    """
    
    def __init__(self, template_dir: str = "templates"):
        self.logger = setup_logger("DiskReportRenderer")
        self.template_dir = Path(template_dir)
        
        # Set up Jinja2 environment
        self.jinja_env = Environment(
            loader=FileSystemLoader(str(self.template_dir)),
            trim_blocks=True,
            lstrip_blocks=True
        )
        
        # Add custom filters
        self.jinja_env.filters['datetime'] = self._format_datetime
        self.jinja_env.filters['filesize'] = self._format_filesize
        self.jinja_env.filters['risk_color'] = self._get_risk_color
        self.jinja_env.filters['severity_color'] = self._get_severity_color
    
    def render_html_from_file(self, json_file: Path, output_file: Path) -> None:
        """Render HTML report from JSON file."""
        with open(json_file, 'r') as f:
            data = json.load(f)
        
        self.render_html(data, output_file)
    
    def render_html(self, data: Dict[str, Any], output_file: Path) -> None:
        """Render HTML report from data dictionary."""
        try:
            template = self.jinja_env.get_template('disk_report.html.j2')
            rendered = template.render(
                report=data,
                generated_at=datetime.now().isoformat(),
                **self._prepare_template_data(data)
            )
            
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(rendered)
                
            self.logger.info(f"HTML report generated: {output_file}")
            
        except Exception as e:
            self.logger.error(f"Failed to render HTML report: {e}")
            raise
    
    def render_pdf_from_file(self, json_file: Path, output_file: Path) -> None:
        """Render PDF report from JSON file."""
        with open(json_file, 'r') as f:
            data = json.load(f)
        
        self.render_pdf(data, output_file)
    
    def render_pdf(self, data: Dict[str, Any], output_file: Path) -> None:
        """Render PDF report from data dictionary."""
        try:
            # For PDF generation, we'll use weasyprint or similar
            # For now, generate HTML first then convert
            import tempfile
            
            with tempfile.NamedTemporaryFile(suffix='.html', delete=False) as tmp:
                tmp_html = Path(tmp.name)
            
            try:
                self.render_html(data, tmp_html)
                
                # Try to convert HTML to PDF using weasyprint
                try:
                    import weasyprint
                    weasyprint.HTML(filename=str(tmp_html)).write_pdf(str(output_file))
                    self.logger.info(f"PDF report generated: {output_file}")
                except ImportError:
                    self.logger.warning("weasyprint not available, PDF generation skipped")
                    raise RuntimeError("PDF generation requires weasyprint: pip install weasyprint")
                    
            finally:
                # Cleanup temporary file
                if tmp_html.exists():
                    tmp_html.unlink()
                    
        except Exception as e:
            self.logger.error(f"Failed to render PDF report: {e}")
            raise
    
    def _prepare_template_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Prepare additional data for template rendering."""
        
        # Calculate summary statistics
        file_changes = data.get("file_changes", {})
        files_added = file_changes.get("files_added", [])
        files_modified = file_changes.get("files_modified", [])
        files_removed = file_changes.get("files_removed", [])
        
        # Get risk assessment
        risk_assessment = data.get("risk_assessment", {})
        
        # Get ransomware indicators by severity
        indicators = data.get("ransomware_indicators", [])
        indicators_by_severity = {
            "critical": [i for i in indicators if i.get("severity") == "critical"],
            "high": [i for i in indicators if i.get("severity") == "high"],
            "medium": [i for i in indicators if i.get("severity") == "medium"],
            "low": [i for i in indicators if i.get("severity") == "low"]
        }
        
        # Get registry changes
        registry_changes = data.get("registry_changes", {})
        
        # Prepare file hash summary
        file_hashes = data.get("file_hashes", {})
        files_with_vt = sum(1 for h in file_hashes.values() 
                           if isinstance(h, dict) and "virustotal" in h)
        
        return {
            "summary": {
                "total_files_changed": len(files_added) + len(files_modified) + len(files_removed),
                "files_added_count": len(files_added),
                "files_modified_count": len(files_modified),
                "files_removed_count": len(files_removed),
                "registry_changes_detected": registry_changes.get("changes_detected", False),
                "indicators_count": len(indicators),
                "critical_indicators_count": len(indicators_by_severity["critical"]),
                "high_indicators_count": len(indicators_by_severity["high"]),
                "files_with_hashes": len([h for h in file_hashes.values() if isinstance(h, dict)]),
                "files_with_virustotal": files_with_vt,
                "risk_level": risk_assessment.get("risk_level", "UNKNOWN"),
                "risk_score": risk_assessment.get("risk_score", 0)
            },
            "indicators_by_severity": indicators_by_severity,
            "top_suspicious_files": self._get_top_suspicious_files(files_added + files_modified),
            "ransom_notes": self._extract_ransom_notes(indicators),
            "encrypted_files": self._extract_encrypted_files(indicators),
            "registry_summary": self._summarize_registry_changes(registry_changes),
            "vt_results": self._summarize_vt_results(file_hashes)
        }
    
    def _get_top_suspicious_files(self, files: list, limit: int = 10) -> list:
        """Get top suspicious files based on various criteria."""
        suspicious_files = []
        
        for file_info in files:
            if isinstance(file_info, dict):
                suspicion_score = 0
                
                # Check if marked as suspicious
                if file_info.get("is_suspicious", False):
                    suspicion_score += 10
                
                # Check file extension
                ext = file_info.get("extension", "").lower()
                suspicious_extensions = [
                    ".encrypted", ".locked", ".crypto", ".crypt", ".enc"
                ]
                if ext in suspicious_extensions:
                    suspicion_score += 20
                
                # Check file size (very large or very small files)
                size = file_info.get("size", 0)
                if size > 100 * 1024 * 1024:  # > 100MB
                    suspicion_score += 5
                elif size == 0:  # Empty files
                    suspicion_score += 3
                
                if suspicion_score > 0:
                    file_info["suspicion_score"] = suspicion_score
                    suspicious_files.append(file_info)
        
        # Sort by suspicion score and return top files
        suspicious_files.sort(key=lambda x: x.get("suspicion_score", 0), reverse=True)
        return suspicious_files[:limit]
    
    def _extract_ransom_notes(self, indicators: list) -> list:
        """Extract ransom note information from indicators."""
        ransom_notes = []
        
        for indicator in indicators:
            if indicator.get("type") == "ransom_note":
                ransom_notes.append({
                    "file_path": indicator.get("file_path", ""),
                    "content_preview": indicator.get("content_preview", ""),
                    "description": indicator.get("description", "")
                })
        
        return ransom_notes
    
    def _extract_encrypted_files(self, indicators: list) -> list:
        """Extract encrypted file information from indicators."""
        encrypted_files = []
        
        for indicator in indicators:
            if indicator.get("type") == "mass_encryption":
                sample_files = indicator.get("sample_files", [])
                encrypted_files.extend(sample_files)
        
        return encrypted_files
    
    def _summarize_registry_changes(self, registry_changes: dict) -> dict:
        """Summarize registry changes."""
        if not registry_changes.get("changes_detected", False):
            return {"detected": False}
        
        modified_keys = registry_changes.get("modified_keys", [])
        
        return {
            "detected": True,
            "total_keys_modified": len(modified_keys),
            "keys": modified_keys[:10]  # Show first 10
        }
    
    def _summarize_vt_results(self, file_hashes: dict) -> dict:
        """Summarize VirusTotal results."""
        vt_summary = {
            "total_files_checked": 0,
            "malicious_files": 0,
            "suspicious_files": 0,
            "clean_files": 0,
            "detection_details": []
        }
        
        for file_path, hash_data in file_hashes.items():
            if isinstance(hash_data, dict) and "virustotal" in hash_data:
                vt_summary["total_files_checked"] += 1
                vt_result = hash_data["virustotal"]
                
                if isinstance(vt_result, dict):
                    positives = vt_result.get("positives", 0)
                    total = vt_result.get("total", 0)
                    
                    if positives > 0:
                        if positives >= total * 0.3:  # 30% or more detections
                            vt_summary["malicious_files"] += 1
                            detection_type = "malicious"
                        else:
                            vt_summary["suspicious_files"] += 1
                            detection_type = "suspicious"
                        
                        vt_summary["detection_details"].append({
                            "file_path": file_path,
                            "positives": positives,
                            "total": total,
                            "detection_type": detection_type,
                            "scan_date": vt_result.get("scan_date", "")
                        })
                    else:
                        vt_summary["clean_files"] += 1
        
        return vt_summary
    
    def _format_datetime(self, value: str) -> str:
        """Format datetime string for display."""
        try:
            if isinstance(value, str):
                dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
                return dt.strftime('%Y-%m-%d %H:%M:%S UTC')
        except:
            pass
        return str(value)
    
    def _format_filesize(self, size: int) -> str:
        """Format file size in human readable format."""
        if size is None:
            return "Unknown"
        
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} PB"
    
    def _get_risk_color(self, risk_level: str) -> str:
        """Get color class for risk level."""
        color_map = {
            "CRITICAL": "danger",
            "HIGH": "warning", 
            "MEDIUM": "info",
            "LOW": "secondary",
            "MINIMAL": "success",
            "UNKNOWN": "dark"
        }
        return color_map.get(risk_level.upper(), "dark")
    
    def _get_severity_color(self, severity: str) -> str:
        """Get color class for severity level."""
        color_map = {
            "critical": "danger",
            "high": "warning",
            "medium": "info", 
            "low": "secondary"
        }
        return color_map.get(severity.lower(), "dark")
