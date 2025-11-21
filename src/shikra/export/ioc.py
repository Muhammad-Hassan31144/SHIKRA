import yaml
from pathlib import Path
from typing import Dict, Any, List
import logging
from uuid import uuid4

from ..utils.logger import setup_logger
from ..utils.jsonio import load_json

class IOCExporter:
    """
    Exports Indicators of Compromise (IOCs) from a combined report
    into various standard formats like Sigma, YARA, and Suricata.
    """
    def __init__(self):
        self.logger = setup_logger("IOCExporter")

    def export(self, combined_path: Path, output_dir: Path):
        """
        Main export function. Creates the output directory and calls
        individual format exporters.
        """
        self.logger.info(f"Exporting IOCs to directory: {output_dir}")
        combined_report = load_json(combined_path)
        
        output_dir.mkdir(parents=True, exist_ok=True)
        
        self._export_sigma(combined_report, output_dir / "detection_rules.yml")
        self._export_yara(combined_report, output_dir / "file_indicators.yar")
        self._export_suricata(combined_report, output_dir / "network_rules.rules")
        
        self.logger.info("IOC export complete.")

    def _export_sigma(self, report: Dict[str, Any], output_path: Path):
        """Generates Sigma rules from high-confidence indicators."""
        rules = []
        iocs = report.get("summary", {}).get("iocs", {})
        
        # Rule for suspicious file hashes
        if iocs.get("hashes_sha256"):
            rules.append({
                "title": "Suspicious File Hash Detected by RansomKit",
                "id": str(uuid4()),
                "status": "experimental",
                "description": "Detects file hashes associated with a RansomKit analysis.",
                "logsource": {"category": "file_event", "product": "windows"},
                "detection": {
                    "selection": {"Image|endswith": list(iocs["hashes_sha256"])},
                    "condition": "selection"
                },
                "level": "high"
            })

        # Rule for suspicious C2 domains
        if iocs.get("domains"):
            rules.append({
                "title": "Suspicious Domain Queried by RansomKit",
                "id": str(uuid4()),
                "status": "experimental",
                "description": "Detects DNS queries for domains associated with a RansomKit analysis.",
                "logsource": {"category": "dns", "product": "windows"},
                "detection": {
                    "selection": {"query": list(iocs["domains"])},
                    "condition": "selection"
                },
                "level": "high"
            })

        if rules:
            with open(output_path, 'w', encoding='utf-8') as f:
                yaml.dump_all(rules, f, sort_keys=False, default_flow_style=False)
            self.logger.info(f"Generated {len(rules)} Sigma rules at {output_path}")

    def _export_yara(self, report: Dict[str, Any], output_path: Path):
        """Generates a YARA rule from collected string indicators."""
        iocs = report.get("summary", {}).get("iocs", {})
        
        # Collect some strings for a basic YARA rule
        paths = iocs.get("paths", [])
        urls = iocs.get("urls", [])
        
        if not paths and not urls:
            return

        rule_name = f"RansomKit_Indicators_{report['meta']['combined_at'].split('T')[0].replace('-', '')}"
        
        yara_strings = []
        for i, path in enumerate(paths[:5]): # Limit to 5 paths
            yara_strings.append(f'        $path{i} = "{Path(path).name}" nocase wide ascii')
        for i, url in enumerate(urls[:5]): # Limit to 5 urls
            yara_strings.append(f'        $url{i} = "{url}" nocase wide ascii')

        rule = f"""
rule {rule_name}
{{
    meta:
        author = "RansomKit Automated Exporter"
        description = "Automatically generated YARA rule from analysis on {report['meta']['combined_at']}"
        source_procmon = "{report['meta']['sources']['procmon']}"
        risk_score = {report['summary']['risk_score']}

    strings:
{chr(10).join(yara_strings)}

    condition:
        any of them
}}
"""
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(rule)
        self.logger.info(f"Generated YARA rule at {output_path}")

    def _export_suricata(self, report: Dict[str, Any], output_path: Path):
        """Generates Suricata rules for network IOCs."""
        rules = []
        iocs = report.get("summary", {}).get("iocs", {})
        
        # Rule for C2 IP addresses
        if iocs.get("ips"):
            ip_list = f"[{','.join(iocs['ips'][:20])}]" # Limit to 20 IPs
            rules.append(f'alert ip any any -> {ip_list} any (msg:"RansomKit: Potential C2 Communication"; classtype:trojan-activity; sid:{1000000 + abs(hash(ip_list)) % 10000}; rev:1;)')

        # Rule for suspicious domains
        if iocs.get("domains"):
            for i, domain in enumerate(iocs['domains'][:20]):
                rules.append(f'alert dns any any -> any any (msg:"RansomKit: DNS Query for Suspicious Domain {domain}"; dns.query; content:"{domain}"; nocase; classtype:trojan-activity; sid:{1010000 + i}; rev:1;)')

        if rules:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write("\n".join(rules))
            self.logger.info(f"Generated {len(rules)} Suricata rules at {output_path}")
