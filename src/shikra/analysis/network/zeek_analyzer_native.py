"""
Zeek-based network analysis for ransomware detection.
This module provides a native Zeek integration using Zeek's built-in automation capabilities.
"""

import subprocess
import asyncio
import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
import tempfile
from datetime import datetime
import shutil

from ...utils.logger import setup_logger

logger = setup_logger(__name__)


class ZeekAnalyzer:
    """
    Native Zeek Network Security Monitor integration for ransomware analysis.
    Leverages Zeek's event-driven architecture and built-in log generation.
    """
    
    def __init__(self, zeek_path: str = "zeek", scripts_dir: Optional[Path] = None):
        """
        Initialize Zeek analyzer with native automation.
        
        Args:
            zeek_path: Path to zeek binary
            scripts_dir: Directory containing custom Zeek scripts
        """
        self.zeek_path = zeek_path
        self.scripts_dir = scripts_dir or Path(__file__).parent / "zeek_scripts"
        self.output_dir = None
        self.analysis_results = {}
        self._verify_zeek_installation()
        
    def _verify_zeek_installation(self):
        """Verify that Zeek is properly installed and accessible."""
        try:
            result = subprocess.run([self.zeek_path, "--version"], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode != 0:
                raise RuntimeError(f"Zeek not found at {self.zeek_path}")
            logger.info(f"Found Zeek: {result.stdout.strip()}")
        except (subprocess.TimeoutExpired, FileNotFoundError, RuntimeError) as e:
            logger.error(f"Zeek verification failed: {e}")
            # Try alternative common paths
            for alt_path in ["/usr/local/zeek/bin/zeek", "/opt/zeek/bin/zeek", "bro"]:
                if shutil.which(alt_path):
                    self.zeek_path = alt_path
                    logger.info(f"Using alternative Zeek path: {alt_path}")
                    return
            raise RuntimeError("Zeek installation not found. Please install Zeek or specify correct path.")
    
    async def analyze_pcap(self, pcap_path: Path, output_dir: Path, 
                          custom_scripts: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Analyze PCAP file using Zeek's native automation capabilities.
        
        Args:
            pcap_path: Path to PCAP file
            output_dir: Directory for Zeek output logs
            custom_scripts: Additional Zeek scripts to load
            
        Returns:
            Dictionary containing comprehensive analysis results
        """
        self.output_dir = output_dir
        output_dir.mkdir(parents=True, exist_ok=True)
        
        try:
            # Run Zeek with native script loading
            await self._run_zeek_native(pcap_path, output_dir, custom_scripts)
            
            # Parse generated Zeek logs using native log format
            results = await self._parse_native_logs(output_dir)
            
            # Enhance with ransomware-specific analysis
            enhanced_results = await self._enhance_ransomware_analysis(results)
            
            self.analysis_results = enhanced_results
            return enhanced_results
            
        except Exception as e:
            logger.error(f"Native Zeek analysis failed: {e}")
            raise
    
    async def _run_zeek_native(self, pcap_path: Path, output_dir: Path, 
                              custom_scripts: Optional[List[str]] = None):
        """Run Zeek analysis using proper command line options."""
        
        # Create extract_files directory
        extract_dir = output_dir / "extract_files"
        extract_dir.mkdir(parents=True, exist_ok=True)
        
        # Build Zeek command with proper options
        cmd = [
            self.zeek_path,
            "-r", str(pcap_path),          # Read from PCAP file
            "-C",                          # Ignore checksum errors
            "-d", str(output_dir),         # Set output directory (newer Zeek versions)
        ]
        
        # For older Zeek versions, use Log::default_logdir
        if not any("zeek" in self.zeek_path and "4." in self.zeek_path for _ in [""]):  # Simple version check
            cmd.extend(["-e", f"Log::default_logdir=\"{output_dir}\""])
        
        # Load base protocol analyzers using proper @load syntax
        base_scripts = [
            "base/protocols/conn",
            "base/protocols/dns", 
            "base/protocols/http",
            "base/protocols/ssl",
            "base/protocols/ftp",
            "base/protocols/smtp",
            "base/files/hash",
            "base/files/extract",
            "base/frameworks/intel",
            "base/frameworks/notice",
            "base/frameworks/files",
        ]
        
        # Create a temporary script to load all required modules
        temp_script = output_dir / "load_modules.zeek"
        with open(temp_script, 'w') as f:
            for script in base_scripts:
                f.write(f"@load {script}\n")
            
            # Add file extraction configuration
            f.write(f'\nredef FileExtract::prefix = "{output_dir / "extract_files" / "extract-"}";\n')
            f.write("redef FileExtract::default_limit = 50MB;\n")
        
        # Add the temp script to command
        cmd.append(str(temp_script))
        
        # Load our custom ransomware detection script
        ransomware_script = self.scripts_dir / "ransomware-detection.zeek"
        if ransomware_script.exists():
            cmd.append(str(ransomware_script))
        else:
            self.logger.warning(f"Ransomware detection script not found: {ransomware_script}")
        
        # Load additional custom scripts
        if custom_scripts:
            for script in custom_scripts:
                script_path = self.scripts_dir / f"{script}.zeek"
                if script_path.exists():
                    cmd.append(str(script_path))
        
        logger.info(f"Running Zeek analysis: {' '.join(cmd)}")
        
        # Execute Zeek
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=output_dir
        )
        
        stdout, stderr = await process.communicate()
        
        # Clean up temp script
        try:
            temp_script.unlink()
        except:
            pass
        
        if process.returncode != 0:
            error_msg = f"Zeek analysis failed (exit {process.returncode}): {stderr.decode()}"
            logger.error(error_msg)
            logger.error(f"Stdout: {stdout.decode()}")
            raise RuntimeError(error_msg)
        
        logger.info("Zeek analysis completed successfully")
        if stdout:
            logger.debug(f"Zeek output: {stdout.decode()}")
    
    async def _parse_native_logs(self, output_dir: Path) -> Dict[str, Any]:
        """Parse Zeek's native log files generated by the event-driven system."""
        
        results = {
            "connections": [],
            "dns_queries": [],
            "http_requests": [],
            "ssl_certificates": [],
            "files": [],
            "notice_log": [],
            "intel_log": [],
            "ransomware_indicators": [],
            "statistics": {},
            "metadata": {
                "zeek_version": await self._get_zeek_version(),
                "analysis_timestamp": datetime.now().isoformat(),
                "log_files_found": []
            }
        }
        
        # Map of log files to their parsing functions
        log_parsers = {
            "conn.log": ("connections", self._parse_conn_native),
            "dns.log": ("dns_queries", self._parse_dns_native),
            "http.log": ("http_requests", self._parse_http_native),
            "ssl.log": ("ssl_certificates", self._parse_ssl_native),
            "files.log": ("files", self._parse_files_native),
            "notice.log": ("notice_log", self._parse_notice_native),
            "intel.log": ("intel_log", self._parse_intel_native),
            "ransomware.log": ("ransomware_indicators", self._parse_ransomware_native)
        }
        
        # Parse each available log file
        for log_file, (result_key, parser_func) in log_parsers.items():
            log_path = output_dir / log_file
            if log_path.exists():
                results["metadata"]["log_files_found"].append(log_file)
                try:
                    results[result_key] = await parser_func(log_path)
                    logger.info(f"Parsed {log_file}: {len(results[result_key])} records")
                except Exception as e:
                    logger.error(f"Failed to parse {log_file}: {e}")
                    results[result_key] = []
        
        return results
    
    async def _parse_conn_native(self, log_path: Path) -> List[Dict]:
        """Parse Zeek's native connection log format."""
        return await self._parse_zeek_log_native(log_path, {
            'ts': float,
            'uid': str,
            'id.orig_h': str,
            'id.orig_p': int,
            'id.resp_h': str, 
            'id.resp_p': int,
            'proto': str,
            'service': str,
            'duration': float,
            'orig_bytes': int,
            'resp_bytes': int,
            'conn_state': str,
            'local_orig': bool,
            'local_resp': bool,
            'missed_bytes': int,
            'history': str,
            'orig_pkts': int,
            'orig_ip_bytes': int,
            'resp_pkts': int,
            'resp_ip_bytes': int
        })
    
    async def _parse_dns_native(self, log_path: Path) -> List[Dict]:
        """Parse Zeek's native DNS log format."""
        return await self._parse_zeek_log_native(log_path, {
            'ts': float,
            'uid': str,
            'id.orig_h': str,
            'id.orig_p': int,
            'id.resp_h': str,
            'id.resp_p': int,
            'proto': str,
            'trans_id': int,
            'rtt': float,
            'query': str,
            'qclass': int,
            'qclass_name': str,
            'qtype': int,
            'qtype_name': str,
            'rcode': int,
            'rcode_name': str,
            'AA': bool,
            'TC': bool,
            'RD': bool,
            'RA': bool,
            'Z': int,
            'answers': list,
            'TTLs': list,
            'rejected': bool
        })
    
    async def _parse_http_native(self, log_path: Path) -> List[Dict]:
        """Parse Zeek's native HTTP log format."""
        return await self._parse_zeek_log_native(log_path, {
            'ts': float,
            'uid': str,
            'id.orig_h': str,
            'id.orig_p': int,
            'id.resp_h': str,
            'id.resp_p': int,
            'trans_depth': int,
            'method': str,
            'host': str,
            'uri': str,
            'referrer': str,
            'version': str,
            'user_agent': str,
            'origin': str,
            'request_body_len': int,
            'response_body_len': int,
            'status_code': int,
            'status_msg': str,
            'info_code': int,
            'info_msg': str,
            'tags': list,
            'username': str,
            'password': str,
            'proxied': list,
            'orig_fuids': list,
            'orig_filenames': list,
            'orig_mime_types': list,
            'resp_fuids': list,
            'resp_filenames': list,
            'resp_mime_types': list
        })
    
    async def _parse_ssl_native(self, log_path: Path) -> List[Dict]:
        """Parse Zeek's native SSL log format."""
        return await self._parse_zeek_log_native(log_path, {
            'ts': float,
            'uid': str,
            'id.orig_h': str,
            'id.orig_p': int,
            'id.resp_h': str,
            'id.resp_p': int,
            'version': str,
            'cipher': str,
            'curve': str,
            'server_name': str,
            'resumed': bool,
            'last_alert': str,
            'next_protocol': str,
            'established': bool,
            'cert_chain_fuids': list,
            'client_cert_chain_fuids': list,
            'subject': str,
            'issuer': str,
            'client_subject': str,
            'client_issuer': str,
            'validation_status': str
        })
    
    async def _parse_files_native(self, log_path: Path) -> List[Dict]:
        """Parse Zeek's native files log format."""
        return await self._parse_zeek_log_native(log_path, {
            'ts': float,
            'fuid': str,
            'tx_hosts': list,
            'rx_hosts': list,
            'conn_uids': list,
            'source': str,
            'depth': int,
            'analyzers': list,
            'mime_type': str,
            'filename': str,
            'duration': float,
            'local_orig': bool,
            'is_orig': bool,
            'seen_bytes': int,
            'total_bytes': int,
            'missing_bytes': int,
            'overflow_bytes': int,
            'timedout': bool,
            'parent_fuid': str,
            'md5': str,
            'sha1': str,
            'sha256': str,
            'extracted': str
        })
    
    async def _parse_notice_native(self, log_path: Path) -> List[Dict]:
        """Parse Zeek's native notice log format."""
        return await self._parse_zeek_log_native(log_path, {
            'ts': float,
            'uid': str,
            'id.orig_h': str,
            'id.orig_p': int,
            'id.resp_h': str,
            'id.resp_p': int,
            'fuid': str,
            'file_mime_type': str,
            'file_desc': str,
            'proto': str,
            'note': str,
            'msg': str,
            'sub': str,
            'src': str,
            'dst': str,
            'p': int,
            'n': int,
            'peer_descr': str,
            'actions': list,
            'email_dest': list,
            'email_body_sections': list,
            'identifier': str,
            'suppress_for': float,
            'remote_location.country_code': str,
            'remote_location.region': str,
            'remote_location.city': str,
            'remote_location.latitude': float,
            'remote_location.longitude': float
        })
    
    async def _parse_intel_native(self, log_path: Path) -> List[Dict]:
        """Parse Zeek's native intel log format."""
        return await self._parse_zeek_log_native(log_path, {
            'ts': float,
            'uid': str,
            'id.orig_h': str,
            'id.orig_p': int,
            'id.resp_h': str,
            'id.resp_p': int,
            'seen.indicator': str,
            'seen.indicator_type': str,
            'seen.where': str,
            'seen.node': str,
            'matched': list,
            'sources': list,
            'fuid': str,
            'file_mime_type': str,
            'file_desc': str
        })
    
    async def _parse_ransomware_native(self, log_path: Path) -> List[Dict]:
        """Parse our custom ransomware indicators log."""
        return await self._parse_zeek_log_native(log_path, {
            'ts': float,
            'uid': str,
            'id.orig_h': str,
            'id.orig_p': int,
            'id.resp_h': str,
            'id.resp_p': int,
            'indicator_type': str,
            'indicator_value': str,
            'confidence': str,
            'description': str,
            'source_ip': str,
            'dest_ip': str,
            'dest_port': int
        })
    
    async def _parse_zeek_log_native(self, log_path: Path, field_types: Dict[str, type]) -> List[Dict]:
        """
        Native parser for Zeek's TSV log format with proper type conversion.
        
        Args:
            log_path: Path to Zeek log file
            field_types: Dictionary mapping field names to Python types
            
        Returns:
            List of parsed log records
        """
        records = []
        
        try:
            with open(log_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            fields = []
            types = []
            
            # Parse Zeek log header
            for line in lines:
                line = line.strip()
                if line.startswith('#fields'):
                    fields = line.split('\t')[1:]  # Skip '#fields'
                elif line.startswith('#types'):
                    types = line.split('\t')[1:]   # Skip '#types'
                elif line.startswith('#') or not line:
                    continue  # Skip other comments and empty lines
                else:
                    # Parse data line
                    values = line.split('\t')
                    if len(values) == len(fields):
                        record = {}
                        for i, (field, value) in enumerate(zip(fields, values)):
                            if value == '-':
                                record[field] = None
                            else:
                                # Convert based on specified type or Zeek type
                                field_type = field_types.get(field)
                                if field_type:
                                    record[field] = self._convert_value(value, field_type)
                                elif i < len(types):
                                    record[field] = self._convert_zeek_type(value, types[i])
                                else:
                                    record[field] = value
                        records.append(record)
        
        except Exception as e:
            logger.error(f"Failed to parse native Zeek log {log_path}: {e}")
        
        return records
    
    def _convert_value(self, value: str, target_type: type):
        """Convert string value to specified Python type."""
        try:
            if target_type == bool:
                return value in ('T', 'true', '1', 'True')
            elif target_type == int:
                return int(float(value))  # Handle scientific notation
            elif target_type == float:
                return float(value)
            elif target_type == list:
                # Handle Zeek's comma-separated values in parentheses
                if value.startswith('(') and value.endswith(')'):
                    return [item.strip() for item in value[1:-1].split(',') if item.strip()]
                elif ',' in value:
                    return [item.strip() for item in value.split(',') if item.strip()]
                else:
                    return [value] if value else []
            else:
                return str(value)
        except (ValueError, TypeError):
            return value
    
    def _convert_zeek_type(self, value: str, zeek_type: str):
        """Convert value based on Zeek's native type system."""
        type_mapping = {
            'time': float,
            'interval': float,
            'count': int,
            'int': int,
            'double': float,
            'bool': bool,
            'addr': str,
            'port': int,
            'string': str,
            'enum': str,
            'set': list,
            'vector': list,
            'table': dict
        }
        
        # Extract base type from complex types like 'set[string]'
        base_type = zeek_type.split('[')[0]
        target_type = type_mapping.get(base_type, str)
        
        return self._convert_value(value, target_type)
    
    async def _get_zeek_version(self) -> str:
        """Get Zeek version information."""
        try:
            result = subprocess.run([self.zeek_path, "--version"], 
                                  capture_output=True, text=True, timeout=5)
            return result.stdout.strip() if result.returncode == 0 else "unknown"
        except:
            return "unknown"
    
    async def _enhance_ransomware_analysis(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Enhance analysis with ransomware-specific insights using native Zeek data."""
        
        enhanced = results.copy()
        
        # Generate comprehensive statistics
        enhanced["statistics"] = await self._calculate_native_statistics(results)
        
        # Perform risk assessment based on native indicators
        enhanced["risk_assessment"] = await self._assess_native_risk(results)
        
        # Extract key entities and IOCs
        enhanced["key_entities"] = await self._extract_native_entities(results)
        
        # Create detailed timeline from all events
        enhanced["timeline"] = await self._create_native_timeline(results)
        
        # Analyze communication patterns
        enhanced["communication_patterns"] = await self._analyze_communication_patterns(results)
        
        # File analysis summary
        enhanced["file_analysis"] = await self._analyze_extracted_files(results)
        
        return enhanced
    
    async def _calculate_native_statistics(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate comprehensive statistics from native Zeek logs."""
        stats = {
            "total_connections": len(results["connections"]),
            "total_dns_queries": len(results["dns_queries"]),
            "total_http_requests": len(results["http_requests"]),
            "total_ssl_connections": len(results["ssl_certificates"]),
            "total_files": len(results["files"]),
            "total_notices": len(results["notice_log"]),
            "total_intel_hits": len(results["intel_log"]),
            "ransomware_indicators": len(results["ransomware_indicators"]),
            "unique_ips": {
                "internal": set(),
                "external": set()
            },
            "protocols": {},
            "services": {},
            "file_types": {},
            "ssl_versions": {},
            "user_agents": set()
        }
        
        # Analyze connections
        for conn in results["connections"]:
            if conn.get("local_orig"):
                stats["unique_ips"]["internal"].add(conn.get("id.orig_h"))
            if conn.get("local_resp"):
                stats["unique_ips"]["internal"].add(conn.get("id.resp_h"))
            else:
                stats["unique_ips"]["external"].add(conn.get("id.resp_h"))
            
            proto = conn.get("proto", "unknown")
            stats["protocols"][proto] = stats["protocols"].get(proto, 0) + 1
            
            service = conn.get("service", "unknown")
            if service and service != "-":
                stats["services"][service] = stats["services"].get(service, 0) + 1
        
        # Analyze files
        for file_rec in results["files"]:
            mime_type = file_rec.get("mime_type", "unknown")
            stats["file_types"][mime_type] = stats["file_types"].get(mime_type, 0) + 1
        
        # Analyze SSL
        for ssl_rec in results["ssl_certificates"]:
            version = ssl_rec.get("version", "unknown")
            stats["ssl_versions"][version] = stats["ssl_versions"].get(version, 0) + 1
        
        # Analyze HTTP user agents
        for http_rec in results["http_requests"]:
            ua = http_rec.get("user_agent")
            if ua and ua != "-":
                stats["user_agents"].add(ua)
        
        # Convert sets to counts for serialization
        stats["unique_ips"]["internal"] = len(stats["unique_ips"]["internal"])
        stats["unique_ips"]["external"] = len(stats["unique_ips"]["external"])
        stats["unique_user_agents"] = len(stats["user_agents"])
        del stats["user_agents"]  # Remove set for JSON compatibility
        
        return stats
    
    async def _assess_native_risk(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Assess risk using native Zeek indicators and notices."""
        
        risk_score = 0
        risk_factors = []
        
        # Analyze custom ransomware indicators
        indicator_counts = {}
        for indicator in results["ransomware_indicators"]:
            indicator_type = indicator.get("indicator_type", "unknown")
            confidence = indicator.get("confidence", "LOW")
            
            indicator_counts[indicator_type] = indicator_counts.get(indicator_type, 0) + 1
            
            # Scoring based on confidence and type
            if confidence == "HIGH":
                risk_score += 25
            elif confidence == "MEDIUM":
                risk_score += 15
            else:
                risk_score += 5
        
        # Analyze Zeek notices
        notice_types = {}
        for notice in results["notice_log"]:
            note_type = notice.get("note", "unknown")
            notice_types[note_type] = notice_types.get(note_type, 0) + 1
            
            # High-risk notice types
            if "Ransomware" in note_type:
                risk_score += 30
            elif any(keyword in note_type.lower() for keyword in ["malware", "trojan", "suspicious"]):
                risk_score += 20
            else:
                risk_score += 10
        
        # Intel framework hits
        if results["intel_log"]:
            risk_score += len(results["intel_log"]) * 25
            risk_factors.append(f"{len(results['intel_log'])} threat intelligence matches")
        
        # Large file transfers (potential exfiltration)
        large_transfers = 0
        for conn in results["connections"]:
            total_bytes = (conn.get("orig_bytes", 0) or 0) + (conn.get("resp_bytes", 0) or 0)
            if total_bytes > 100 * 1024 * 1024:  # 100MB
                large_transfers += 1
        
        if large_transfers > 0:
            risk_score += large_transfers * 15
            risk_factors.append(f"{large_transfers} large data transfer(s)")
        
        # Build risk factors list
        for indicator_type, count in indicator_counts.items():
            if count > 0:
                risk_factors.append(f"{count} {indicator_type.lower().replace('_', ' ')} indicator(s)")
        
        for notice_type, count in notice_types.items():
            if count > 0:
                risk_factors.append(f"{count} {notice_type} notice(s)")
        
        # Determine risk level
        if risk_score >= 100:
            risk_level = "CRITICAL"
        elif risk_score >= 50:
            risk_level = "HIGH"
        elif risk_score >= 20:
            risk_level = "MEDIUM"
        elif risk_score > 0:
            risk_level = "LOW"
        else:
            risk_level = "MINIMAL"
        
        return {
            "risk_score": risk_score,
            "risk_level": risk_level,
            "risk_factors": risk_factors,
            "indicator_breakdown": indicator_counts,
            "notice_breakdown": notice_types,
            "large_transfers": large_transfers
        }
    
    async def _extract_native_entities(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Extract key entities from native Zeek analysis."""
        
        entities = {
            "suspicious_ips": set(),
            "suspicious_domains": set(),
            "crypto_addresses": set(),
            "malicious_files": set(),
            "c2_servers": set(),
            "tor_nodes": set(),
            "suspicious_certificates": set(),
            "extracted_files": []
        }
        
        # Extract from ransomware indicators
        for indicator in results["ransomware_indicators"]:
            indicator_type = indicator.get("indicator_type", "")
            value = indicator.get("indicator_value", "")
            dest_ip = indicator.get("dest_ip")
            
            if indicator_type == "SUSPICIOUS_DOMAIN":
                entities["suspicious_domains"].add(value)
            elif indicator_type == "CRYPTO_ADDRESS":
                entities["crypto_addresses"].add(value)
            elif indicator_type in ["C2_PATTERN", "BEACONING_PATTERN"]:
                if dest_ip:
                    entities["c2_servers"].add(dest_ip)
            elif indicator_type == "SUSPICIOUS_SSL_DOMAIN":
                entities["suspicious_certificates"].add(value)
        
        # Extract from notices
        for notice in results["notice_log"]:
            src = notice.get("src")
            dst = notice.get("dst")
            note_type = notice.get("note", "")
            
            if "Ransomware" in note_type and src:
                entities["suspicious_ips"].add(src)
            if "TOR" in note_type and dst:
                entities["tor_nodes"].add(dst)
        
        # Extract from files
        for file_rec in results["files"]:
            if file_rec.get("extracted"):
                entities["extracted_files"].append({
                    "filename": file_rec.get("filename", "unknown"),
                    "mime_type": file_rec.get("mime_type", "unknown"),
                    "size": file_rec.get("seen_bytes", 0),
                    "md5": file_rec.get("md5"),
                    "sha1": file_rec.get("sha1"),
                    "sha256": file_rec.get("sha256"),
                    "extracted_path": file_rec.get("extracted")
                })
        
        # Convert sets to lists for JSON serialization
        return {k: list(v) if isinstance(v, set) else v for k, v in entities.items()}
    
    async def _create_native_timeline(self, results: Dict[str, Any]) -> List[Dict]:
        """Create comprehensive timeline from all native Zeek events."""
        
        timeline_events = []
        
        # Add ransomware indicators
        for indicator in results["ransomware_indicators"]:
            timeline_events.append({
                "timestamp": indicator.get("ts", 0),
                "event_type": "RANSOMWARE_INDICATOR",
                "description": indicator.get("description", ""),
                "indicator_type": indicator.get("indicator_type", ""),
                "confidence": indicator.get("confidence", ""),
                "source_ip": indicator.get("source_ip"),
                "dest_ip": indicator.get("dest_ip")
            })
        
        # Add notices
        for notice in results["notice_log"]:
            timeline_events.append({
                "timestamp": notice.get("ts", 0),
                "event_type": "NOTICE",
                "description": notice.get("msg", ""),
                "notice_type": notice.get("note", ""),
                "source_ip": notice.get("src"),
                "dest_ip": notice.get("dst")
            })
        
        # Add intel hits
        for intel in results["intel_log"]:
            timeline_events.append({
                "timestamp": intel.get("ts", 0),
                "event_type": "INTEL_HIT",
                "description": f"Intel match: {intel.get('seen.indicator', '')}",
                "indicator": intel.get("seen.indicator"),
                "indicator_type": intel.get("seen.indicator_type"),
                "source_ip": intel.get("id.orig_h"),
                "dest_ip": intel.get("id.resp_h")
            })
        
        # Sort by timestamp
        timeline_events.sort(key=lambda x: float(x["timestamp"]) if x["timestamp"] else 0)
        
        return timeline_events
    
    async def _analyze_communication_patterns(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze communication patterns for C2 detection."""
        
        patterns = {
            "beaconing_candidates": [],
            "data_exfiltration": [],
            "tor_usage": [],
            "dns_tunneling": []
        }
        
        # Analyze connections for beaconing
        conn_groups = {}
        for conn in results["connections"]:
            key = (conn.get("id.orig_h"), conn.get("id.resp_h"), conn.get("id.resp_p"))
            if key not in conn_groups:
                conn_groups[key] = []
            conn_groups[key].append(conn)
        
        for key, conns in conn_groups.items():
            if len(conns) >= 5:  # Multiple connections to same endpoint
                patterns["beaconing_candidates"].append({
                    "orig_h": key[0],
                    "resp_h": key[1],
                    "resp_p": key[2],
                    "connection_count": len(conns),
                    "total_bytes": sum((c.get("orig_bytes", 0) or 0) + (c.get("resp_bytes", 0) or 0) for c in conns)
                })
        
        return patterns
    
    async def _analyze_extracted_files(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze extracted files for malware indicators."""
        
        file_analysis = {
            "total_extracted": 0,
            "by_type": {},
            "suspicious_files": [],
            "large_files": []
        }
        
        for file_rec in results["files"]:
            if file_rec.get("extracted"):
                file_analysis["total_extracted"] += 1
                
                mime_type = file_rec.get("mime_type", "unknown")
                file_analysis["by_type"][mime_type] = file_analysis["by_type"].get(mime_type, 0) + 1
                
                size = file_rec.get("seen_bytes", 0) or 0
                if size > 10 * 1024 * 1024:  # >10MB
                    file_analysis["large_files"].append({
                        "filename": file_rec.get("filename"),
                        "size": size,
                        "mime_type": mime_type
                    })
                
                # Check for suspicious file types
                if mime_type in ["application/x-dosexec", "application/x-executable", "application/x-msdos-program"]:
                    file_analysis["suspicious_files"].append({
                        "filename": file_rec.get("filename"),
                        "mime_type": mime_type,
                        "hashes": {
                            "md5": file_rec.get("md5"),
                            "sha1": file_rec.get("sha1"),
                            "sha256": file_rec.get("sha256")
                        }
                    })
        
        return file_analysis
    
    def get_summary(self) -> Dict[str, Any]:
        """Get comprehensive analysis summary from native Zeek results."""
        if not self.analysis_results:
            return {"error": "No analysis results available"}
        
        return {
            "metadata": self.analysis_results.get("metadata", {}),
            "statistics": self.analysis_results.get("statistics", {}),
            "risk_assessment": self.analysis_results.get("risk_assessment", {}),
            "key_entities": self.analysis_results.get("key_entities", {}),
            "communication_patterns": self.analysis_results.get("communication_patterns", {}),
            "file_analysis": self.analysis_results.get("file_analysis", {})
        }
    
    def get_detailed_indicators(self) -> List[Dict]:
        """Get detailed ransomware indicators from native analysis."""
        return self.analysis_results.get("ransomware_indicators", [])
    
    def get_zeek_notices(self) -> List[Dict]:
        """Get Zeek's native notice framework alerts."""
        return self.analysis_results.get("notice_log", [])
    
    def get_intel_hits(self) -> List[Dict]:
        """Get threat intelligence matches."""
        return self.analysis_results.get("intel_log", [])
    
    def export_to_json(self, output_path: Path) -> bool:
        """Export native analysis results to JSON file."""
        try:
            with open(output_path, 'w') as f:
                json.dump(self.analysis_results, f, indent=2, default=str)
            return True
        except Exception as e:
            logger.error(f"Failed to export results: {e}")
            return False
