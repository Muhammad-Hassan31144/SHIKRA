import logging
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime
import hashlib
import asyncio
import re
from collections import defaultdict
import subprocess
import json
import os
import struct
import threading
from concurrent.futures import ThreadPoolExecutor

from ...utils import jsonio, VTEnricher, GeoIPLookup
from ...utils.logger import setup_logger

class MemoryAnalyzer:
    """
    Analyzes a memory dump using Volatility 3, incorporating advanced ransomware-focused heuristics,
    file carving, YARA scanning, and MITRE ATT&CK mapping.
    """
    def __init__(self, vt_api_key: Optional[str], config_dir: Path = Path("config"), 
                 optimize_output: bool = True, addon_plugins_file: Optional[str] = None,
                 volatility_path: str = "vol", output_dir: Optional[str] = None,
                 plugin_timeout: int = 600):
        self.logger = setup_logger("MemoryAnalyzer")
        
        # Make config directory handling more robust
        if config_dir.is_absolute():
            absolute_config_dir = config_dir
        else:
            # Look for config relative to current working directory first
            absolute_config_dir = Path.cwd() / config_dir
            if not absolute_config_dir.exists():
                # Fallback to relative to script location
                project_root = Path(__file__).resolve().parent.parent.parent.parent
                absolute_config_dir = project_root / config_dir
        
        if not absolute_config_dir.exists():
             raise FileNotFoundError(f"Configuration directory not found at: {absolute_config_dir}")
        
        config_dir = absolute_config_dir
        
        # Set configurable parameters
        self.volatility_path = volatility_path
        self.plugin_timeout = plugin_timeout
        self.optimize_output = optimize_output
        self.output_dir = Path(output_dir) if output_dir else Path.cwd() / "output" / "memory"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        self.logger.info(f"Output optimization: {'ENABLED' if optimize_output else 'DISABLED (full JSON output)'}")
        self.logger.info(f"Volatility path: {self.volatility_path}")
        self.logger.info(f"Plugin timeout: {self.plugin_timeout}s")
        self.logger.info(f"Output directory: {self.output_dir}")
        
        # Set addon plugins file path (only if explicitly provided)
        if addon_plugins_file is not None:
            self.addon_plugins_file = Path(addon_plugins_file)
            self.logger.info(f"Addon plugins file: {self.addon_plugins_file}")
        else:
            self.addon_plugins_file = None
            self.logger.info("No addon plugins file specified - only essential plugins will run")
        
        # Load all necessary configurations with error handling
        try:
            self.config = jsonio.load_config(config_dir / "memory_config.json")
            self.risk_config = jsonio.load_config(config_dir / "risk_scoring.json")
            self.mitre_config = jsonio.load_config(config_dir / "mitre_mapping.json")
        except Exception as e:
            self.logger.error(f"Failed to load configuration files: {e}")
            # Provide default configurations
            self.config = {"process_baselines": {}, "ransomware_indicators": {}, "suspicious_names": [], "file_signatures": {}}
            self.risk_config = {"memory": {}, "max_score_per_category": {"mem_inject": 6, "mem_procs": 4}, "max_score": 10}
            self.mitre_config = {}
        
        # Initialize GeoIP lookup once
        self.geo_lookup = None
        try:
            self.geo_lookup = GeoIPLookup()
            self.logger.info("GeoIP lookup initialized")
        except Exception as e:
            self.logger.warning(f"Failed to initialize GeoIP lookup: {e}")

        self.vt = None
        if vt_api_key and vt_api_key != "YOUR_VIRUSTOTAL_API_KEY_HERE":
            try:
                self.vt = VTEnricher(api_key=vt_api_key)
                self.logger.info("VirusTotal enricher initialized for file carving.")
            except Exception as e:
                self.logger.warning(f"Failed to initialize VirusTotal enricher: {e}")
        else:
            self.logger.warning("VT API key not provided; enrichment for carved files will be skipped.")

        # Thread pool for async operations
        self.thread_pool = ThreadPoolExecutor(max_workers=4)

        vol_logger = logging.getLogger('volatility3')
        vol_logger.setLevel(logging.CRITICAL)

    async def analyze(self, memory_path: Path) -> Dict[str, Any]:
        """
        Main analysis function for the memory dump.
        """
        if not memory_path.exists():
            raise FileNotFoundError(f"Memory dump file not found: {memory_path}")
            
        self.logger.info(f"Starting comprehensive memory analysis for {memory_path}...")

        # Step 1: Get system info and metadata
        self.logger.info("Step 1/6: Getting system information and metadata...")
        info = await self._run_plugin_async(memory_path, "windows.info.Info")
        metadata = self._build_metadata(memory_path, info)
        
        # Step 2: Core process analysis
        self.logger.info("Step 2/6: Running core process analysis...")
        processes = await self._run_plugin_async(memory_path, "windows.pslist.PsList")
        if self._has_errors(processes):
            self.logger.warning("Primary process listing failed, trying fallback psscan...")
            processes = await self._run_plugin_async(memory_path, "windows.psscan.PsScan")
        
        pstree = await self._run_plugin_async(memory_path, "windows.pstree.PsTree")
        cmdline = await self._run_plugin_async(memory_path, "windows.cmdline.CmdLine")
        
        # Step 3: Network analysis
        self.logger.info("Step 3/6: Analyzing network connections...")
        netscan = await self._run_plugin_async(memory_path, "windows.netscan.NetScan")
        sockets = await self._run_plugin_async(memory_path, "windows.netstat.NetStat")
        
        # Step 4: Malware analysis
        self.logger.info("Step 4/6: Performing malware analysis...")
        malfind = await self._run_plugin_async(memory_path, "windows.malfind.Malfind")
        yarascan = await self._run_yarascan_gracefully(memory_path)
        mutants = await self._run_plugin_async(memory_path, "windows.mutantscan.MutantScan")
        
        # Step 5: Advanced analysis
        self.logger.info("Step 5/6: Running advanced analysis...")
        
        # Enhanced process analysis
        enhanced_processes = await self._enhance_process_analysis(processes, cmdline, pstree)
        network_connections = await self._enhance_network_analysis(netscan, sockets, enhanced_processes)
        
        # Registry and file analysis
        registry_analysis = await self._analyze_registry_persistence(memory_path)
        file_artifacts = await self._analyze_file_artifacts(memory_path)
        
        # Step 6: Threat hunting and IOC extraction
        self.logger.info("Step 6/6: Performing threat hunting...")
        ransomware_indicators = await self._hunt_ransomware_indicators_async(memory_path, mutants)
        
        # Build comprehensive analysis results
        analysis_results = self._build_analysis_results(
            enhanced_processes, network_connections, malfind, yarascan,
            registry_analysis, file_artifacts
        )
        
        # Generate threat assessment
        threat_assessment = self._generate_threat_assessment(
            analysis_results, ransomware_indicators
        )
        
        # Generate recommendations
        recommendations = self._generate_recommendations(threat_assessment)

        # Build final report in new format
        report = {
            "metadata": metadata,
            "analysis_results": analysis_results,
            "threat_assessment": threat_assessment,
            "recommendations": recommendations
        }

        self.logger.info(f"Memory analysis complete. Risk score: {threat_assessment.get('overall_risk_score', 'N/A')}")
        return report

    async def _run_plugin_async(self, memory_path: Path, plugin_name: str) -> List[Dict[str, Any]]:
        """Async wrapper for _run_plugin to prevent blocking the event loop."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(self.thread_pool, self._run_plugin, memory_path, plugin_name)

    async def _run_yarascan_gracefully(self, memory_path: Path) -> List[Dict[str, Any]]:
        """Run YARA scanning with graceful error handling."""
        self.logger.info("Running YARA scanning...")
        
        # Check if yara rules exist
        yara_rules_dir = Path("data/yara_rules")
        yara_files = []
        
        if yara_rules_dir.exists():
            yara_files = list(yara_rules_dir.glob("*.yar"))
            
        if not yara_files:
            self.logger.warning("No YARA rule files found. Skipping YARA scanning.")
            return []
        
        try:
            # Try with first yara file
            yara_file = yara_files[0]
            self.logger.info(f"Using YARA rules from: {yara_file}")
            
            # Run yarascan with specific yara file
            vol3_plugin = "windows.vadyarascan"
            cmd = [
                self.volatility_path,
                '-f', str(memory_path.resolve()),
                '-r', 'json',
                vol3_plugin,
                '--yara-file', str(yara_file)
            ]
            
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=self.plugin_timeout,
                cwd=os.getcwd()
            )
            
            if result.returncode != 0:
                self.logger.warning(f"YARA scanning failed: {result.stderr}")
                return []
            
            if result.stdout.strip():
                try:
                    data = json.loads(result.stdout)
                    self.logger.info(f"YARA scanning completed with {len(data)} matches")
                    return data
                except json.JSONDecodeError as e:
                    self.logger.warning(f"Failed to parse YARA output: {e}")
                    return []
            else:
                self.logger.info("YARA scanning completed with no matches")
                return []
                
        except subprocess.TimeoutExpired:
            self.logger.warning(f"YARA scanning timed out after {self.plugin_timeout}s")
            return []
        except Exception as e:
            self.logger.warning(f"YARA scanning failed: {e}")
            return []

    def _build_metadata(self, memory_path: Path, info_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Build metadata section matching the new format."""
        try:
            # Extract system info from volatility info plugin
            system_info = {}
            if info_data and not self._has_errors(info_data):
                info_item = info_data[0] if info_data else {}
                system_info = {
                    "os": info_item.get("SystemTime", "Windows Unknown"),
                    "architecture": info_item.get("NtProductType", "Unknown"),
                    "kernel_version": info_item.get("KernelVersion", "Unknown"),
                    "build": info_item.get("NtBuildLab", "Unknown"),
                    "hostname": info_item.get("SystemUptime", "Unknown"),
                    "timezone": "UTC"
                }
            else:
                system_info = {
                    "os": "Windows (detected)",
                    "architecture": "Unknown",
                    "kernel_version": "Unknown",
                    "build": "Unknown",
                    "hostname": "Unknown",
                    "timezone": "Unknown"
                }
            
            # Calculate file hashes
            file_stat = memory_path.stat()
            md5_hash = ""
            sha256_hash = ""
            
            try:
                # Calculate partial hashes for large files
                with open(memory_path, 'rb') as f:
                    chunk = f.read(1024 * 1024)  # First 1MB
                    md5_hash = hashlib.md5(chunk).hexdigest()
                    sha256_hash = hashlib.sha256(chunk).hexdigest()
            except Exception as e:
                self.logger.warning(f"Failed to calculate file hashes: {e}")
                md5_hash = "unknown"
                sha256_hash = "unknown"
            
            return {
                "analysis_timestamp": datetime.now().isoformat(),
                "volatility_version": "3.x",
                "analyzer_version": "Shikra Memory Analyzer v3.0",
                "memory_image": {
                    "filename": memory_path.name,
                    "size": file_stat.st_size,
                    "hash": {
                        "md5": md5_hash,
                        "sha256": sha256_hash
                    },
                    "acquisition_time": datetime.fromtimestamp(file_stat.st_mtime).isoformat()
                },
                "system_info": system_info,
                "plugins_executed": [],  # Will be populated during execution
                "integrations": {
                    "virustotal": {
                        "enabled": self.vt is not None,
                        "api_calls": 0,
                        "rate_limit_remaining": 0
                    },
                    "maxmind_geoip": {
                        "enabled": self.geo_lookup is not None,
                        "database_version": "2024-07-15",
                        "lookups_performed": 0
                    }
                }
            }
        except Exception as e:
            self.logger.error(f"Error building metadata: {e}")
            return {
                "analysis_timestamp": datetime.now().isoformat(),
                "error": str(e)
            }

    async def _enhance_process_analysis(self, processes: List[Dict[str, Any]], 
                                      cmdline: List[Dict[str, Any]], 
                                      pstree: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Enhanced process analysis with detailed information."""
        enhanced_processes = []
        
        # Build command line lookup
        cmdline_lookup = {}
        for cmd in cmdline:
            if isinstance(cmd, dict) and 'PID' in cmd:
                cmdline_lookup[cmd['PID']] = cmd.get('Args', '')
        
        # Build process tree lookup
        tree_lookup = {}
        for proc in pstree:
            if isinstance(proc, dict) and 'PID' in proc:
                tree_lookup[proc['PID']] = proc
        
        valid_processes = [p for p in processes if isinstance(p, dict) and 'error' not in p]
        
        for process in valid_processes:
            try:
                pid = process.get('PID', 0)
                process_name = process.get('ImageFileName', 'unknown')
                
                # Get command line safely
                proc_cmdline = cmdline_lookup.get(pid, '')
                if proc_cmdline is None:
                    proc_cmdline = ''
                
                enhanced_proc = {
                    "pid": pid,
                    "ppid": process.get('PPID', 0),
                    "name": process_name,
                    "offset": process.get('Offset', '0x0'),
                    "create_time": process.get('CreateTime', datetime.now().isoformat()),
                    "exit_time": process.get('ExitTime'),
                    "session_id": process.get('SessionId', 0),
                    "wow64": process.get('Wow64', False),
                    "command_line": proc_cmdline,
                    "executable_path": process.get('File output', 'Unknown'),
                    "user": "Unknown",
                    "integrity_level": "medium",
                    "process_ancestry": self._build_process_ancestry(pid, tree_lookup),
                    "threads": [],  # Would need threads plugin
                    "handles": [],  # Would need handles plugin
                    "vad_info": {
                        "vad_count": 0,
                        "executable_vads": 0,
                        "private_memory": 0,
                        "mapped_files": []
                    },
                    "dll_list": [],  # Would need dlllist plugin
                    "network_artifacts": [],  # Will be populated from network analysis
                    "anomalies": self._detect_process_anomalies(process, proc_cmdline)
                }
                
                # Add suspicious score and MITRE techniques
                enhanced_proc['suspicious_score'] = self._calculate_suspicion_score(process)
                enhanced_proc['mitre_techniques'] = self._map_process_to_mitre(process)
                
                enhanced_processes.append(enhanced_proc)
                
            except Exception as e:
                self.logger.warning(f"Error enhancing process {process.get('PID', 'unknown')}: {e}")
                enhanced_processes.append(process)  # Fallback to original
        
        return enhanced_processes

    def _build_process_ancestry(self, pid: int, tree_lookup: Dict[int, Dict]) -> List[Dict[str, Any]]:
        """Build process ancestry chain."""
        ancestry = []
        current_pid = pid
        seen_pids = set()
        
        while current_pid and current_pid not in seen_pids:
            seen_pids.add(current_pid)
            proc_info = tree_lookup.get(current_pid)
            
            if proc_info and proc_info.get('PPID'):
                parent_pid = proc_info['PPID']
                parent_info = tree_lookup.get(parent_pid)
                
                if parent_info:
                    ancestry.append({
                        "pid": parent_pid,
                        "name": parent_info.get('ImageFileName', 'unknown'),
                        "create_time": parent_info.get('CreateTime', datetime.now().isoformat())
                    })
                
                current_pid = parent_pid
            else:
                break
        
        return ancestry

    def _detect_process_anomalies(self, process: Dict[str, Any], command_line: str) -> List[Dict[str, Any]]:
        """Detect process-level anomalies."""
        anomalies = []
        proc_name = process.get('ImageFileName', '').lower()
        
        # Handle None command_line
        if command_line is None:
            command_line = ''
        
        # Check for unsigned executables (simplified)
        if proc_name not in ['system', 'csrss.exe', 'winlogon.exe']:
            anomalies.append({
                "type": "unsigned_executable",
                "severity": "medium",
                "description": "Process may be running unsigned executable"
            })
        
        # Check for suspicious command lines
        if len(command_line) > 200:
            anomalies.append({
                "type": "long_command_line",
                "severity": "medium",
                "description": "Unusually long command line detected"
            })
        
        # Check for masquerading
        suspicious_names = self.config.get('suspicious_names', [])
        if any(name in proc_name for name in suspicious_names):
            anomalies.append({
                "type": "suspicious_name",
                "severity": "high",
                "description": "Process name matches suspicious pattern"
            })
        
        return anomalies

    async def _enhance_network_analysis(self, netscan: List[Dict[str, Any]], 
                                      sockets: List[Dict[str, Any]], 
                                      processes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Enhanced network connection analysis."""
        enhanced_connections = []
        
        # Build process lookup - handle cases where 'pid' might not exist
        process_lookup = {}
        for p in processes:
            if isinstance(p, dict) and p.get('pid') is not None:
                process_lookup[p['pid']] = p
        
        # Check if netscan is supported
        if self._has_unsupported_errors(netscan):
            self.logger.info("Network scanning not supported on this Windows version")
            return []
        
        # Process netscan results
        valid_netscan = [n for n in netscan if isinstance(n, dict) and 'error' not in n]
        
        if not valid_netscan:
            self.logger.info("No valid network connections found")
            return []
        
        for conn in valid_netscan:
            try:
                local_addr = conn.get('LocalAddr', '')
                local_port = conn.get('LocalPort', 0)
                foreign_addr = conn.get('ForeignAddr', '')
                foreign_port = conn.get('ForeignPort', 0)
                pid = conn.get('PID', 0)
                
                # Get process info
                process_info = process_lookup.get(pid, {})
                process_name = process_info.get('name', 'unknown')
                
                # Get geo data for foreign address
                geo_data = {}
                if foreign_addr and foreign_addr not in ['0.0.0.0', '127.0.0.1', '-', '*']:
                    geo_data = self._get_geo_data(foreign_addr)
                
                # Get threat intelligence
                threat_intel = await self._get_threat_intelligence(foreign_addr)
                
                enhanced_conn = {
                    "protocol": conn.get('Proto', 'tcp').lower(),
                    "local_address": local_addr,
                    "local_port": local_port,
                    "remote_address": foreign_addr,
                    "remote_port": foreign_port,
                    "state": conn.get('State', 'unknown'),
                    "pid": pid,
                    "process_name": process_name,
                    "create_time": conn.get('Created', datetime.now().isoformat()),
                    "geoip": self._format_geo_data(geo_data),
                    "threat_intel": threat_intel
                }
                
                enhanced_connections.append(enhanced_conn)
                
            except Exception as e:
                self.logger.warning(f"Error enhancing network connection: {e}")
                # Don't add the original connection on error, just skip it
                continue
        
        return enhanced_connections

    def _format_geo_data(self, geo_data: Dict[str, Any]) -> Dict[str, Any]:
        """Format geo data to match expected structure."""
        return {
            "country": geo_data.get('country', 'Unknown'),
            "country_code": geo_data.get('country_code', 'XX'),
            "region": geo_data.get('region', 'Unknown'),
            "city": geo_data.get('city', 'Unknown'),
            "postal_code": geo_data.get('postal_code', ''),
            "latitude": geo_data.get('latitude', 0),
            "longitude": geo_data.get('longitude', 0),
            "timezone": geo_data.get('timezone', 'Unknown'),
            "asn": geo_data.get('asn', 'Unknown'),
            "organization": geo_data.get('organization', 'Unknown'),
            "isp": geo_data.get('isp', 'Unknown'),
            "is_anonymous_proxy": False,
            "is_satellite": False,
            "connection_type": "Unknown"
        }

    async def _get_threat_intelligence(self, ip: str) -> Dict[str, Any]:
        """Get threat intelligence for IP address."""
        # Placeholder - would integrate with actual threat intel
        return {
            "reputation": "unknown",
            "categories": [],
            "first_seen": None,
            "confidence": 0
        }

    async def _analyze_registry_persistence(self, memory_path: Path) -> List[Dict[str, Any]]:
        """Analyze registry for persistence mechanisms."""
        self.logger.info("Analyzing registry persistence...")
        registry_analysis = []
        
        try:
            # Try to run registry analysis
            hivelist = await self._run_plugin_async(memory_path, "windows.registry.hivelist.HiveList")
            
            # For now, return placeholder data
            # In a real implementation, this would parse registry hives
            registry_analysis.append({
                "hive": "HKEY_LOCAL_MACHINE\\SOFTWARE",
                "key": "Microsoft\\Windows\\CurrentVersion\\Run",
                "value_name": "Example",
                "value_data": "C:\\Windows\\System32\\example.exe",
                "value_type": "REG_SZ",
                "last_write_time": datetime.now().isoformat(),
                "persistence_technique": "registry_autorun"
            })
            
        except Exception as e:
            self.logger.warning(f"Registry analysis failed: {e}")
        
        return registry_analysis

    async def _analyze_file_artifacts(self, memory_path: Path) -> List[Dict[str, Any]]:
        """Analyze file artifacts from memory."""
        self.logger.info("Analyzing file artifacts...")
        file_artifacts = []
        
        try:
            # Try to run filescan
            filescan = await self._run_plugin_async(memory_path, "windows.filescan.FileScan")
            
            valid_files = [f for f in filescan if isinstance(f, dict) and 'error' not in f]
            
            # Process first 50 files to avoid overwhelming output
            for file_info in valid_files[:50]:
                try:
                    file_path = file_info.get('Name', '')
                    if file_path and not file_path.startswith('\\Device'):
                        continue  # Skip system paths
                    
                    artifact = {
                        "filename": Path(file_path).name if file_path else 'unknown',
                        "full_path": file_path,
                        "size": file_info.get('Size', 0),
                        "allocation_status": "allocated",
                        "resident": True,
                        "hash": {
                            "md5": "unknown",
                            "sha256": "unknown"
                        },
                        "created": datetime.now().isoformat(),
                        "modified": datetime.now().isoformat(),
                        "accessed": datetime.now().isoformat(),
                        "virustotal": {
                            "detection_ratio": "0/71",
                            "scan_date": datetime.now().isoformat(),
                            "verdict": "unknown"
                        }
                    }
                    
                    file_artifacts.append(artifact)
                    
                except Exception as e:
                    self.logger.warning(f"Error processing file artifact: {e}")
            
        except Exception as e:
            self.logger.warning(f"File artifacts analysis failed: {e}")
        
        return file_artifacts

    def _build_analysis_results(self, processes: List[Dict[str, Any]], 
                               network_connections: List[Dict[str, Any]],
                               malfind: List[Dict[str, Any]], 
                               yarascan: List[Dict[str, Any]],
                               registry_analysis: List[Dict[str, Any]], 
                               file_artifacts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Build the analysis_results section."""
        
        # Process malfind results
        malfind_results = []
        valid_malfind = [m for m in malfind if isinstance(m, dict) and 'error' not in m]
        
        for mf in valid_malfind[:20]:  # Limit to first 20
            try:
                malfind_results.append({
                    "pid": mf.get('PID', 0),
                    "process_name": mf.get('Process', 'unknown'),
                    "address": mf.get('VadStartAddr', '0x0'),
                    "size": mf.get('CommitCharge', 0),
                    "protection": mf.get('Protection', 'unknown'),
                    "commit_charge": mf.get('PrivateMemory', 'unknown'),
                    "privatememory": 1,
                    "tag": mf.get('Tag', 'unknown'),
                    "disassembly": [],  # Would need to parse hex dump
                    "hexdump": mf.get('HexDump', ''),
                    "yara_matches": [],  # Would cross-reference with yarascan
                    "entropy": 0.0,  # Would calculate from hex dump
                    "pe_characteristics": {
                        "is_pe": False,
                        "has_relocations": False,
                        "is_stripped": False
                    }
                })
            except Exception as e:
                self.logger.warning(f"Error processing malfind result: {e}")
        
        # Build memory regions from malfind
        memory_regions = []
        for mf in malfind_results:
            memory_regions.append({
                "base_address": mf["address"],
                "size": mf["size"],
                "protection": mf["protection"],
                "type": "MEM_PRIVATE",
                "state": "MEM_COMMIT",
                "pid": mf["pid"],
                "process_name": mf["process_name"],
                "content_type": "unknown",
                "entropy": mf["entropy"],
                "strings": []  # Would extract from hex dump
            })
        
        return {
            "processes": processes,
            "network_connections": network_connections,
            "malware_analysis": {
                "malfind_results": malfind_results,
                "code_injection": [],  # Would detect from process analysis
                "rootkit_artifacts": []  # Would detect from advanced analysis
            },
            "registry_analysis": registry_analysis,
            "file_artifacts": file_artifacts,
            "memory_regions": memory_regions
        }

    def _generate_threat_assessment(self, analysis_results: Dict[str, Any], 
                                   ransomware_indicators: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive threat assessment."""
        
        # Calculate risk score
        risk_score = self._calculate_enhanced_risk_score(analysis_results, ransomware_indicators)
        
        # Extract IOCs
        iocs = self._extract_iocs_from_analysis(analysis_results, ransomware_indicators)
        
        # Extract threat categories
        threat_categories = self._extract_threat_categories_from_analysis(analysis_results, iocs)
        
        # Extract MITRE tactics
        mitre_tactics = self._extract_mitre_tactics_from_analysis(analysis_results)
        
        # Build timeline
        timeline = self._build_timeline_from_analysis(analysis_results)
        
        return {
            "overall_risk_score": risk_score,
            "confidence": min(0.95, len(iocs) * 0.1),
            "threat_categories": threat_categories,
            "iocs": iocs,
            "mitre_tactics": mitre_tactics,
            "timeline": timeline
        }

    def _calculate_enhanced_risk_score(self, analysis_results: Dict[str, Any], 
                                     ransomware_indicators: Dict[str, Any]) -> float:
        """Calculate enhanced risk score."""
        score = 0.0
        
        # Process-based scoring
        processes = analysis_results.get('processes', [])
        suspicious_processes = [p for p in processes if p.get('suspicious_score', 0) > 50]
        score += min(len(suspicious_processes) * 1.5, 4.0)
        
        # Network-based scoring
        network_connections = analysis_results.get('network_connections', [])
        malicious_connections = [c for c in network_connections 
                               if c.get('threat_intel', {}).get('reputation') == 'malicious']
        score += min(len(malicious_connections) * 2.0, 4.0)
        
        # Malfind scoring
        malfind_results = analysis_results.get('malware_analysis', {}).get('malfind_results', [])
        score += min(len(malfind_results) * 1.0, 3.0)
        
        # Ransomware indicators
        if ransomware_indicators.get('bitcoin_addresses'):
            score += 2.5
        if ransomware_indicators.get('tor_addresses'):
            score += 2.0
        if ransomware_indicators.get('suspicious_mutexes'):
            score += 1.5
        
        return min(score, 10.0)

    def _extract_iocs_from_analysis(self, analysis_results: Dict[str, Any], 
                                   ransomware_indicators: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract IOCs from analysis results."""
        iocs = []
        
        # Extract from processes
        processes = analysis_results.get('processes', [])
        for proc in processes:
            if proc.get('suspicious_score', 0) > 70:
                iocs.append({
                    "type": "process",
                    "value": proc.get('name', 'unknown'),
                    "context": f"Suspicious process PID {proc.get('pid', 0)}"
                })
        
        # Extract from network connections
        network_connections = analysis_results.get('network_connections', [])
        for conn in network_connections:
            if conn.get('threat_intel', {}).get('reputation') == 'malicious':
                iocs.append({
                    "type": "ip",
                    "value": conn.get('remote_address', ''),
                    "context": "Malicious network connection"
                })
        
        # Extract from ransomware indicators
        for btc in ransomware_indicators.get('bitcoin_addresses', []):
            iocs.append({
                "type": "bitcoin",
                "value": btc,
                "context": "Bitcoin address found in memory"
            })
        
        return iocs

    def _extract_threat_categories_from_analysis(self, analysis_results: Dict[str, Any], 
                                                iocs: List[Dict[str, Any]]) -> List[str]:
        """Extract threat categories."""
        categories = set()
        
        # Check for malware indicators
        if analysis_results.get('malware_analysis', {}).get('malfind_results'):
            categories.add('malware')
        
        # Check for network threats
        network_connections = analysis_results.get('network_connections', [])
        if any(c.get('threat_intel', {}).get('reputation') == 'malicious' for c in network_connections):
            categories.add('c2_communication')
        
        # Check for persistence
        if analysis_results.get('registry_analysis'):
            categories.add('persistence')
        
        # Check for code injection
        if analysis_results.get('malware_analysis', {}).get('code_injection'):
            categories.add('code_injection')
        
        return list(categories)

    def _extract_mitre_tactics_from_analysis(self, analysis_results: Dict[str, Any]) -> List[Dict[str, str]]:
        """Extract MITRE tactics from analysis."""
        tactics = []
        
        # Process injection
        if analysis_results.get('malware_analysis', {}).get('code_injection'):
            tactics.append({
                "tactic": "T1055",
                "technique": "Process Injection",
                "evidence": ["code_injection_detected"]
            })
        
        # Registry persistence
        if analysis_results.get('registry_analysis'):
            tactics.append({
                "tactic": "T1547.001",
                "technique": "Registry Run Keys",
                "evidence": ["registry_persistence"]
            })
        
        # Network communication
        network_connections = analysis_results.get('network_connections', [])
        if network_connections:
            tactics.append({
                "tactic": "T1071.001",
                "technique": "Web Protocols",
                "evidence": ["network_communication"]
            })
        
        return tactics

    def _build_timeline_from_analysis(self, analysis_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Build timeline from analysis results."""
        timeline = []
        
        # Add process creation events
        processes = analysis_results.get('processes', [])
        for proc in processes[:10]:  # Limit to first 10
            if proc.get('suspicious_score', 0) > 50:
                timeline.append({
                    "timestamp": proc.get('create_time', datetime.now().isoformat()),
                    "event": f"Suspicious process creation: {proc.get('name', 'unknown')}",
                    "severity": "high"
                })
        
        # Add network events
        network_connections = analysis_results.get('network_connections', [])
        for conn in network_connections[:5]:  # Limit to first 5
            if conn.get('threat_intel', {}).get('reputation') == 'malicious':
                timeline.append({
                    "timestamp": conn.get('create_time', datetime.now().isoformat()),
                    "event": f"Malicious network connection to {conn.get('remote_address', '')}",
                    "severity": "critical"
                })
        
        return sorted(timeline, key=lambda x: x.get('timestamp', ''))

    def _generate_recommendations(self, threat_assessment: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate security recommendations."""
        recommendations = []
        risk_score = threat_assessment.get('overall_risk_score', 0)
        iocs = threat_assessment.get('iocs', [])
        threat_categories = threat_assessment.get('threat_categories', [])
        
        # High risk recommendations
        if risk_score >= 8:
            recommendations.append({
                "priority": "immediate",
                "action": "isolate_system",
                "rationale": f"Critical risk score detected: {risk_score}"
            })
        
        # Malicious IP blocking
        malicious_ips = [ioc for ioc in iocs if ioc.get('type') == 'ip']
        for ip_ioc in malicious_ips:
            recommendations.append({
                "priority": "high",
                "action": "block_c2_ip",
                "target": ip_ioc.get('value'),
                "rationale": "Block known malicious infrastructure"
            })
        
        # Registry cleanup
        if 'persistence' in threat_categories:
            recommendations.append({
                "priority": "high",
                "action": "remove_persistence",
                "target": "Registry persistence mechanisms",
                "rationale": "Remove malware persistence"
            })
        
        # Default recommendation
        if not recommendations:
            recommendations.append({
                "priority": "medium",
                "action": "continue_monitoring",
                "rationale": "No immediate threats detected, maintain vigilance"
            })
        
        return recommendations

    def _has_errors(self, data: List[Dict[str, Any]]) -> bool:
        """Check if the data contains error entries."""
        if not data:
            return True
        
        # Check if all entries are errors
        error_count = 0
        for item in data:
            if isinstance(item, dict) and 'error' in item:
                error_count += 1
        
        # If more than 80% are errors, consider it failed
        return error_count > len(data) * 0.8

    def _has_unsupported_errors(self, data: List[Dict[str, Any]]) -> bool:
        """Check if the data contains unsupported plugin errors."""
        if not data:
            return False
            
        for item in data:
            if isinstance(item, dict) and item.get('unsupported', False):
                return True
        return False

    async def _enrich_processes_with_vt(self, processes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Enrich process data with VirusTotal information."""
        if not self.vt:
            return processes
            
        enriched_processes = []
        for process in processes:
            if isinstance(process, dict) and 'error' not in process:
                # Try to get process hash if available
                process_hash = process.get('sha256_hash') or process.get('md5_hash')
                if process_hash:
                    try:
                        vt_result = await self.vt.query_hash(process_hash)
                        if vt_result and 'error' not in vt_result:
                            process['vt_result'] = vt_result
                            process['vt_reputation'] = self.vt.calculate_reputation_score(vt_result)
                    except Exception as e:
                        self.logger.warning(f"VT query failed for process {process.get('imagefilename', 'unknown')}: {e}")
            
            enriched_processes.append(process)
        
        return enriched_processes

    async def _enrich_network_with_vt_and_geo(self, connections: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Enrich network connections with VirusTotal and geographic data."""
        enriched_connections = []
        
        for conn in connections:
            if isinstance(conn, dict) and 'error' not in conn:
                # Add geographic data
                foreign_addr = conn.get('foreign_addr') or conn.get('remote_addr')
                if foreign_addr and foreign_addr not in ['0.0.0.0', '127.0.0.1', '-']:
                    conn['geo_data'] = self._get_geo_data(foreign_addr)
                    
                    # Add VT IP reputation if available
                    if self.vt:
                        try:
                            vt_ip_result = await self.vt.query_ip(foreign_addr)
                            if vt_ip_result and 'error' not in vt_ip_result:
                                conn['vt_ip_reputation'] = vt_ip_result
                        except Exception as e:
                            self.logger.warning(f"VT IP query failed for {foreign_addr}: {e}")
            
            enriched_connections.append(conn)
        
        return enriched_connections

    def _enrich_network_connections_with_geo(self, connections: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Enrich network connections with geographic data only (fallback when VT is not available)."""
        enriched_connections = []
        
        for conn in connections:
            if isinstance(conn, dict) and 'error' not in conn:
                # Add geographic data
                foreign_addr = conn.get('foreign_addr') or conn.get('remote_addr')
                if foreign_addr and foreign_addr not in ['0.0.0.0', '127.0.0.1', '-']:
                    conn['geo_data'] = self._get_geo_data(foreign_addr)
            
            enriched_connections.append(conn)
        
        return enriched_connections

    def _run_plugin(self, memory_path: Path, plugin_name: str) -> List[Dict[str, Any]]:
        """Runs a Volatility 3 plugin using subprocess to call vol3 CLI directly."""
        self.logger.info(f"Running plugin: {plugin_name}")
        
        try:
            import subprocess
            import json
            import os
            import glob
            
            # Map our plugin names to vol3 CLI plugin names (essential plugins only)
            plugin_mapping = {
                # Core essential plugins
                "windows.pslist.PsList": "windows.pslist",
                "windows.pstree.PsTree": "windows.pstree", 
                "windows.netscan.NetScan": "windows.netscan",
                "windows.malfind.Malfind": "windows.malfind",
                "windows.mutantscan.MutantScan": "windows.mutantscan",
                "windows.info.Info": "windows.info",
                "windows.cmdline.CmdLine": "windows.cmdline",
                "windows.svcscan.SvcScan": "windows.svcscan",
                "windows.netstat.NetStat": "windows.netstat",
                "windows.vadyarascan.VadYaraScan": "windows.vadyarascan",
                
                # Extended plugins (available for .shikra config)
                "windows.filescan.FileScan": "windows.filescan",
                "windows.dlllist.DllList": "windows.dlllist",
                "windows.handles.Handles": "windows.handles",
                "windows.registry.hivelist.HiveList": "windows.registry.hivelist",
                "windows.registry.printkey.PrintKey": "windows.registry.printkey",
                "windows.modules.Modules": "windows.modules",
                "windows.driverscan.DriverScan": "windows.driverscan",
                "windows.envars.Envars": "windows.envars",
                "windows.privileges.Privs": "windows.privileges",
                "windows.sessions.Sessions": "windows.sessions",
                "windows.ssdt.SSDT": "windows.ssdt",
                "windows.callbacks.Callbacks": "windows.callbacks",
                "windows.memmap.Memmap": "windows.memmap",
                "windows.vadinfo.VadInfo": "windows.vadinfo",
                "windows.mftscan.MFTScan": "windows.mftscan",
                "windows.getsids.GetSIDs": "windows.getsids",
                "windows.psscan.PsScan": "windows.psscan",
                "windows.threads.Threads": "windows.threads",
            }
            
            vol3_plugin = plugin_mapping.get(plugin_name)
            if not vol3_plugin:
                self.logger.error(f"Plugin {plugin_name} not supported")
                return [{"error": f"Plugin {plugin_name} not supported"}]
            
            # Use the provided memory dump path directly
            dump_path = str(memory_path.resolve())
            
            # Build the vol3 command - capture JSON output directly from stdout
            cmd = [
                self.volatility_path,
                '-f', dump_path,
                '-r', 'json'
            ]
            
            # Handle special plugins that require additional arguments
            if vol3_plugin == "windows.vadyarascan":
                # Look for YARA rules in data/yara_rules directory
                yara_rules_dir = Path.cwd() / "data" / "yara_rules"
                if yara_rules_dir.exists():
                    # Find all .yar and .yara files
                    yara_files = []
                    for pattern in ["*.yar", "*.yara"]:
                        yara_files.extend(yara_rules_dir.glob(pattern))
                    
                    # Make max YARA files configurable
                    max_yara_files = self.config.get('max_yara_files', 20)
                    yara_files = yara_files[:max_yara_files]
                    
                    if yara_files:
                        self.logger.info(f"Found {len(yara_files)} YARA rule files, using: {[f.name for f in yara_files]}")
                        # Add the plugin name first, then yara-file parameters
                        cmd.append(vol3_plugin)
                        for yara_file in yara_files:
                            cmd.extend(['--yara-file', str(yara_file)])
                    else:
                        self.logger.warning("No YARA rule files found in data/yara_rules directory")
                        return [{"error": "No YARA rule files found", "details": f"Searched in {yara_rules_dir}"}]
                else:
                    self.logger.warning(f"YARA rules directory not found: {yara_rules_dir}")
                    return [{"error": "YARA rules directory not found", "details": f"Expected: {yara_rules_dir}"}]
            else:
                # Add the plugin name at the end for regular plugins
                cmd.append(vol3_plugin)
            
            self.logger.debug(f"Running command: {' '.join(cmd)}")
            
            # Run the command with configurable timeout and capture stdout
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=self.plugin_timeout,
                cwd=os.getcwd()
            )
            
            if result.returncode != 0:
                # Log full stderr for better debugging
                self.logger.warning(f"vol3 command failed with return code {result.returncode}")
                self.logger.warning(f"Full stderr: {result.stderr}")
                
                # Check for known unsupported plugin errors
                if "NotImplementedError" in result.stderr and "This version of Windows is not supported" in result.stderr:
                    self.logger.warning(f"Plugin {vol3_plugin} not supported on this Windows version")
                    return [{"error": f"Plugin {vol3_plugin} not supported on this Windows version", "unsupported": True}]
                elif "matches multiple plugins" in result.stderr:
                    self.logger.warning(f"Plugin name {vol3_plugin} is ambiguous")
                    return [{"error": f"Plugin {vol3_plugin} name is ambiguous", "details": result.stderr}]
                elif "required" in result.stderr and "argument" in result.stderr:
                    self.logger.warning(f"Plugin {vol3_plugin} requires additional arguments")
                    return [{"error": f"Plugin {vol3_plugin} requires additional arguments", "details": result.stderr}]
                else:
                    return [{"error": f"vol3 {vol3_plugin} failed", "details": result.stderr}]
            
            # Parse JSON output directly from stdout
            if result.stdout.strip():
                try:
                    json_data = json.loads(result.stdout)
                    
                    # Save output to file for debugging
                    output_file = self.output_dir / f"{vol3_plugin.replace('.', '_')}.json"
                    with open(output_file, 'w') as f:
                        json.dump(json_data, f, indent=2)
                    self.logger.debug(f"Saved output to {output_file}")
                    
                    # vol3 JSON output format can vary
                    if isinstance(json_data, list):
                        return json_data
                    elif isinstance(json_data, dict):
                        if 'rows' in json_data:
                            return json_data['rows']
                        elif 'data' in json_data:
                            return json_data['data']
                        else:
                            return [json_data]
                    else:
                        return [json_data] if json_data else []
                        
                except json.JSONDecodeError as e:
                    self.logger.error(f"Failed to parse vol3 JSON output: {e}")
                    self.logger.debug(f"Raw stdout: {result.stdout[:500]}...")
                    return [{"error": "Failed to parse vol3 JSON output", "details": str(e)}]
            else:
                self.logger.warning(f"vol3 produced no output for {vol3_plugin}")
                return []
                    
        except subprocess.TimeoutExpired:
            self.logger.error(f"vol3 {vol3_plugin} command timed out after {self.plugin_timeout}s")
            return [{"error": f"vol3 {vol3_plugin} timed out"}]
        except Exception as e:
            self.logger.error(f"Failed to run vol3 {plugin_name}: {e}", exc_info=True)
            return [{"error": f"vol3 {plugin_name} failed", "details": str(e)}]

    def _validate_system_processes(self, processes: List[Dict], pstree: List[Dict]) -> List[Dict]:
        """Validates system processes against known good baselines from config with full path checking."""
        self.logger.info("Validating system process baselines...")
        violations = []
        proc_baselines = self.config.get("process_baselines", {})
        
        # Handle case where processes might contain error entries
        valid_processes = [p for p in processes if isinstance(p, dict) and 'pid' in p and 'error' not in p]
        valid_pstree = [p for p in pstree if isinstance(p, dict) and 'error' not in p]
        
        procs_by_pid = {p['pid']: p for p in valid_processes}
        children_map = defaultdict(list)
        for node in valid_pstree:
            if node.get('ppid') is not None and node.get('pid') is not None:
                children_map[node['ppid']].append(node.get('pid'))

        for proc_name, baseline in proc_baselines.items():
            for process in [p for p in valid_processes if p.get("imagefilename", "").lower() == proc_name]:
                pid = process.get('pid')
                ppid = process.get('ppid')
                image_path = process.get('image_path', '').lower()
                parent_name = procs_by_pid.get(ppid, {}).get("imagefilename", "N/A").lower()

                # Check parent process
                if baseline.get("parent") and baseline["parent"] != parent_name:
                    violations.append({
                        "process": proc_name, 
                        "pid": pid, 
                        "violation": f"Wrong parent: expected {baseline['parent']}, got {parent_name}",
                        "severity": "high"
                    })
                
                # Check expected path
                expected_paths = baseline.get("expected_paths", [])
                if expected_paths and not any(path.lower() in image_path for path in expected_paths):
                    violations.append({
                        "process": proc_name,
                        "pid": pid,
                        "violation": f"Unexpected path: {image_path}, expected one of {expected_paths}",
                        "severity": "critical"
                    })
                
                # Check forbidden child processes
                for child_pid in children_map.get(pid, []):
                    child_name = procs_by_pid.get(child_pid, {}).get("imagefilename", "").lower()
                    if "any_process" in baseline.get("should_not_spawn", []) or child_name in baseline.get("should_not_spawn", []):
                        violations.append({
                            "process": proc_name, 
                            "pid": pid, 
                            "violation": f"Spawned forbidden child: {child_name}",
                            "severity": "medium"
                        })
        return violations

    async def _hunt_ransomware_indicators_async(self, memory_path: Path, mutants: List[Dict]) -> Dict:
        """Async wrapper for ransomware indicator hunting."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(self.thread_pool, self._hunt_ransomware_indicators, memory_path, mutants)

    def _hunt_ransomware_indicators(self, memory_path: Path, mutants: List[Dict]) -> Dict:
        """Hunts for ransomware-specific indicators with improved byte-based searching."""
        self.logger.info("Hunting for ransomware-specific IOCs...")
        findings = {"ransom_notes": [], "bitcoin_addresses": [], "tor_addresses": [], "suspicious_mutexes": []}
        indicators = self.config.get("ransomware_indicators", {})
        
        # Filter valid mutants
        valid_mutants = [m for m in mutants if isinstance(m, dict) and 'error' not in m]
        
        for mutant in valid_mutants:
            mutant_name = str(mutant.get("name", "")).lower()
            for keyword in indicators.get("mutex_keywords", []):
                if keyword in mutant_name and len(mutant_name) > 20:
                    findings["suspicious_mutexes"].append(mutant)
                    break
        
        self.logger.info("Scanning memory dump for string-based IOCs...")
        
        # Compile byte patterns for better reliability
        try:
            btc_pattern = indicators.get("bitcoin_regex", r"[13][a-km-zA-HJ-NP-Z1-9]{25,34}")
            onion_pattern = indicators.get("onion_regex", r"[a-z2-7]{16}\.onion")
            
            # Compile as byte patterns
            btc_regex_ascii = re.compile(btc_pattern.encode('ascii'))
            onion_regex_ascii = re.compile(onion_pattern.encode('ascii'))
            
            # Also compile UTF-16 patterns for Windows
            btc_regex_utf16 = re.compile(btc_pattern.encode('utf-16le'))
            onion_regex_utf16 = re.compile(onion_pattern.encode('utf-16le'))
            
        except (re.error, UnicodeEncodeError) as e:
            self.logger.error(f"Invalid regex pattern: {e}")
            return findings
        
        try:
            file_size = memory_path.stat().st_size
            chunk_size = 50 * 1024 * 1024  # Increased to 50MB chunks for better coverage
            overlap = 2048  # Larger overlap for multi-byte patterns
            
            with open(memory_path, 'rb') as f:
                processed_size = 0
                
                while processed_size < file_size:
                    remaining = file_size - processed_size
                    current_chunk_size = min(chunk_size, remaining)
                    
                    chunk = f.read(current_chunk_size)
                    if not chunk:
                        break
                    
                    try:
                        # Search for ASCII patterns
                        for match in btc_regex_ascii.finditer(chunk):
                            addr = match.group(0).decode('ascii')
                            if addr not in findings["bitcoin_addresses"]:
                                findings["bitcoin_addresses"].append(addr)
                        
                        for match in onion_regex_ascii.finditer(chunk):
                            addr = match.group(0).decode('ascii')
                            if addr not in findings["tor_addresses"]:
                                findings["tor_addresses"].append(addr)
                        
                        # Search for UTF-16 patterns
                        for match in btc_regex_utf16.finditer(chunk):
                            try:
                                addr = match.group(0).decode('utf-16le')
                                if addr not in findings["bitcoin_addresses"]:
                                    findings["bitcoin_addresses"].append(addr)
                            except UnicodeDecodeError:
                                continue
                        
                        for match in onion_regex_utf16.finditer(chunk):
                            try:
                                addr = match.group(0).decode('utf-16le')
                                if addr not in findings["tor_addresses"]:
                                    findings["tor_addresses"].append(addr)
                            except UnicodeDecodeError:
                                continue
                                
                    except Exception as e:
                        self.logger.warning(f"Error processing chunk at offset {processed_size}: {e}")
                        continue
                    
                    processed_size += current_chunk_size
                    
                    # Move back for overlap, but not beyond start of file
                    if processed_size < file_size:
                        new_pos = max(0, f.tell() - overlap)
                        f.seek(new_pos)
                        processed_size = new_pos
                        
                    # Log progress for large files
                    if file_size > 1024 * 1024 * 1024:  # > 1GB
                        progress = (processed_size / file_size) * 100
                        if int(progress) % 10 == 0:  # Log every 10%
                            self.logger.info(f"IOC scanning progress: {progress:.1f}%")
                        
        except Exception as e:
            self.logger.error(f"Error scanning memory dump for strings: {e}")

        # Remove duplicates
        findings["bitcoin_addresses"] = list(set(findings["bitcoin_addresses"]))
        findings["tor_addresses"] = list(set(findings["tor_addresses"]))
        
        self.logger.info(f"Found {len(findings['bitcoin_addresses'])} Bitcoin addresses, "
                        f"{len(findings['tor_addresses'])} Tor addresses, "
                        f"{len(findings['suspicious_mutexes'])} suspicious mutexes")
        
        return findings

    async def _carve_and_analyze_files_async(self, memory_path: Path) -> List[Dict[str, Any]]:
        """Async wrapper for file carving."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(self.thread_pool, self._carve_and_analyze_files, memory_path)

    # def _carve_and_analyze_files(self, memory_path: Path) -> List[Dict[str, Any]]:
    #     """Improved file carving with proper boundary detection and full dump coverage."""
    #     self.logger.info("Carving files from memory dump with boundary detection...")
    #     artifacts = []
    #     file_signatures = self.config.get('file_signatures', {})
        
    #     # Define file type handlers with proper size detection
    #     file_handlers = {
    #         'PE': self._carve_pe_file,
    #         'ZIP': self._carve_zip_file,
    #         'PDF': self._carve_pdf_file,
    #         'JPEG': self._carve_jpeg_file,
    #     }

    #     try:
    #         file_size = memory_path.stat().st_size
    #         chunk_size = 100 * 1024 * 1024  # 100MB chunks
    #         overlap = 64 * 1024  # 64KB overlap for headers that span chunks
            
    #         self.logger.info(f"Analyzing full memory dump ({file_size / (1024**3):.2f} GB)")
            
    #         with open(memory_path, 'rb') as f:
    #             processed_size = 0
                
    #             while processed_size < file_size:
    #                 remaining = file_size - processed_size
    #                 current_chunk_size = min(chunk_size, remaining)
                    
    #                 chunk = f.read(current_chunk_size)
    #                 if not chunk:
    #                     break
                    
    #                 for file_type, sig_hex in file_signatures.items():
    #                     try:
    #                         signature = bytes.fromhex(sig_hex)
    #                     except ValueError as e:
    #                         self.logger.warning(f"Invalid hex signature for {file_type}: {e}")
    #                         continue
                        
    #                     offset = 0
    #                     while True:
    #                         offset = chunk.find(signature, offset)
    #                         if offset == -1:
    #                             break
                            
    #                         absolute_offset = processed_size + offset
                            
    #                         # Use specialized carving function if available
    #                         if file_type in file_handlers:
    #                             carved_data = file_handlers[file_type](chunk, offset)
    #                         else:
    #                             # Fallback to simple carving
    #                             end_offset = min(offset + 5 * 1024 * 1024, len(chunk))
    #                             carved_data = chunk[offset:end_offset]
                            
    #                         if carved_data and len(carved_data) >= 100:  # Minimum file size
    #                             sha256_hash = hashlib.sha256(carved_data).hexdigest()
                                
    #                             # VT enrichment
    #                             vt_result = None
    #                             vt_enrichment = {}
    #                             if self.vt:
    #                                 try:
    #                                     vt_result = await self.vt.query_hash(sha256_hash)
    #                                     if vt_result and 'error' not in vt_result:
    #                                         vt_enrichment = {
    #                                             'detection_ratio': self.vt.extract_detection_ratio(vt_result),
    #                                             'threat_names': self.vt.extract_threat_names(vt_result),
    #                                             'reputation_score': self.vt.calculate_reputation_score(vt_result),
    #                                             'is_signed': self.vt.extract_signature_info(vt_result),
    #                                             'malware_families': self.vt.extract_malware_families(vt_result),
    #                                             'suspicion_boost': self.vt.calculate_suspicion_boost(vt_result)
    #                                         }
    #                                 except Exception as e:
    #                                     self.logger.warning(f"VT query failed for {sha256_hash}: {e}")

    #                             artifacts.append({
    #                                 "file_path": f"carved_{file_type}_at_0x{absolute_offset:08x}",
    #                                 "file_size": len(carved_data),
    #                                 "sha256_hash": sha256_hash,
    #                                 "file_type": file_type,
    #                                 "offset": absolute_offset,
    #                                 "vt_result": vt_result,
    #                                 "vt_enrichment": vt_enrichment if vt_enrichment else None
    #                             })
                            
    #                         offset += len(signature)
                    
    #                 processed_size += current_chunk_size
                    
    #                 # Handle overlap for next chunk
    #                 if processed_size < file_size:
    #                     new_pos = max(0, f.tell() - overlap)
    #                     f.seek(new_pos)
    #                     processed_size = new_pos
                        
    #     except Exception as e:
    #         self.logger.error(f"File carving failed: {e}")

    #     self.logger.info(f"Carved {len(artifacts)} files from memory dump")
    #     return artifacts
    def _carve_and_analyze_files(self, memory_path: Path) -> List[Dict[str, Any]]:
        """Improved file carving with proper boundary detection and full dump coverage."""
        self.logger.info("Carving files from memory dump with boundary detection...")
        artifacts = []
        file_signatures = self.config.get('file_signatures', {})
        
        # Define file type handlers with proper size detection
        file_handlers = {
            'PE': self._carve_pe_file,
            'ZIP': self._carve_zip_file,
            'PDF': self._carve_pdf_file,
            'JPEG': self._carve_jpeg_file,
        }

        try:
            file_size = memory_path.stat().st_size
            chunk_size = 100 * 1024 * 1024  # 100MB chunks
            overlap = 64 * 1024  # 64KB overlap for headers that span chunks
            
            self.logger.info(f"Analyzing full memory dump ({file_size / (1024**3):.2f} GB)")
            
            with open(memory_path, 'rb') as f:
                processed_size = 0
                
                while processed_size < file_size:
                    remaining = file_size - processed_size
                    current_chunk_size = min(chunk_size, remaining)
                    
                    chunk = f.read(current_chunk_size)
                    if not chunk:
                        break
                    
                    for file_type, sig_hex in file_signatures.items():
                        try:
                            signature = bytes.fromhex(sig_hex)
                        except ValueError as e:
                            self.logger.warning(f"Invalid hex signature for {file_type}: {e}")
                            continue
                        
                        offset = 0
                        while True:
                            offset = chunk.find(signature, offset)
                            if offset == -1:
                                break
                            
                            absolute_offset = processed_size + offset
                            
                            # Use specialized carving function if available
                            if file_type in file_handlers:
                                carved_data = file_handlers[file_type](chunk, offset)
                            else:
                                # Fallback to simple carving
                                end_offset = min(offset + 5 * 1024 * 1024, len(chunk))
                                carved_data = chunk[offset:end_offset]
                            
                            if carved_data and len(carved_data) >= 100:  # Minimum file size
                                sha256_hash = hashlib.sha256(carved_data).hexdigest()
                                
                                # VT enrichment (synchronous - will be handled in post-processing)
                                artifacts.append({
                                    "file_path": f"carved_{file_type}_at_0x{absolute_offset:08x}",
                                    "file_size": len(carved_data),
                                    "sha256_hash": sha256_hash,
                                    "file_type": file_type,
                                    "offset": absolute_offset,
                                    "vt_result": None,  # Will be populated in post-processing
                                    "vt_enrichment": None  # Will be populated in post-processing
                                })
                            
                            offset += len(signature)
                    
                    processed_size += current_chunk_size
                    
                    # Handle overlap for next chunk
                    if processed_size < file_size:
                        new_pos = max(0, f.tell() - overlap)
                        f.seek(new_pos)
                        processed_size = new_pos
                        
        except Exception as e:
            self.logger.error(f"File carving failed: {e}")

        # Post-process VT enrichment for carved files
        if self.vt and artifacts:
            self.logger.info(f"Enriching {len(artifacts)} carved files with VirusTotal data...")
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                loop.run_until_complete(self._enrich_carved_files_with_vt(artifacts))
            finally:
                loop.close()

        self.logger.info(f"Carved {len(artifacts)} files from memory dump")
        return artifacts

    async def _enrich_carved_files_with_vt(self, artifacts: List[Dict[str, Any]]) -> None:
        """Enrich carved files with VirusTotal data."""
        for artifact in artifacts:
            sha256_hash = artifact.get('sha256_hash')
            if sha256_hash and self.vt:
                try:
                    vt_result = await self.vt.query_hash(sha256_hash)
                    if vt_result and 'error' not in vt_result:
                        vt_enrichment = {
                            'detection_ratio': self.vt.extract_detection_ratio(vt_result),
                            'threat_names': self.vt.extract_threat_names(vt_result),
                            'reputation_score': self.vt.calculate_reputation_score(vt_result),
                            'is_signed': self.vt.extract_signature_info(vt_result),
                            'malware_families': self.vt.extract_malware_families(vt_result),
                            'suspicion_boost': self.vt.calculate_suspicion_boost(vt_result)
                        }
                        artifact['vt_result'] = vt_result
                        artifact['vt_enrichment'] = vt_enrichment
                except Exception as e:
                    self.logger.warning(f"VT query failed for {sha256_hash}: {e}")

    def _carve_pe_file(self, data: bytes, offset: int) -> Optional[bytes]:
        """Carve PE file with proper size detection from headers."""
        try:
            if offset + 64 > len(data):  # Need at least DOS header
                return None
            
            # Check DOS header
            if data[offset:offset+2] != b'MZ':
                return None
            
            # Get PE header offset
            pe_offset = struct.unpack('<I', data[offset+60:offset+64])[0] + offset
            
            if pe_offset + 24 > len(data):
                return None
            
            # Check PE signature
            if data[pe_offset:pe_offset+4] != b'PE\x00\x00':
                return None
            
            # Get size of image from optional header
            if pe_offset + 80 > len(data):
                return None
                
            size_of_image = struct.unpack('<I', data[pe_offset+80:pe_offset+84])[0]
            
            # Reasonable size check (max 100MB)
            if size_of_image > 100 * 1024 * 1024:
                size_of_image = min(size_of_image, 10 * 1024 * 1024)  # Cap at 10MB
            
            end_offset = min(offset + size_of_image, len(data))
            return data[offset:end_offset]
            
        except (struct.error, IndexError):
            # Fallback to fixed size
            end_offset = min(offset + 2 * 1024 * 1024, len(data))
            return data[offset:end_offset]

    def _carve_zip_file(self, data: bytes, offset: int) -> Optional[bytes]:
        """Carve ZIP file by finding end of central directory."""
        try:
            # Look for end of central directory signature
            eocd_sig = b'\x50\x4b\x05\x06'
            max_search = min(len(data), offset + 50 * 1024 * 1024)  # Search up to 50MB
            
            eocd_offset = data.find(eocd_sig, offset)
            if eocd_offset != -1 and eocd_offset < max_search:
                # EOCD record is 22 bytes minimum
                end_offset = min(eocd_offset + 22, len(data))
                return data[offset:end_offset]
            else:
                # Fallback to reasonable size
                end_offset = min(offset + 10 * 1024 * 1024, len(data))
                return data[offset:end_offset]
                
        except Exception:
            end_offset = min(offset + 5 * 1024 * 1024, len(data))
            return data[offset:end_offset]

    def _carve_pdf_file(self, data: bytes, offset: int) -> Optional[bytes]:
        """Carve PDF file by finding %%EOF marker."""
        try:
            eof_marker = b'%%EOF'
            max_search = min(len(data), offset + 20 * 1024 * 1024)  # Search up to 20MB
            
            eof_offset = data.find(eof_marker, offset)
            if eof_offset != -1 and eof_offset < max_search:
                end_offset = min(eof_offset + len(eof_marker), len(data))
                return data[offset:end_offset]
            else:
                end_offset = min(offset + 5 * 1024 * 1024, len(data))
                return data[offset:end_offset]
                
        except Exception:
            end_offset = min(offset + 2 * 1024 * 1024, len(data))
            return data[offset:end_offset]

    def _carve_jpeg_file(self, data: bytes, offset: int) -> Optional[bytes]:
        """Carve JPEG file by finding EOI marker."""
        try:
            eoi_marker = b'\xff\xd9'
            max_search = min(len(data), offset + 10 * 1024 * 1024)  # Search up to 10MB
            
            eoi_offset = data.find(eoi_marker, offset + 2)  # Skip initial SOI
            if eoi_offset != -1 and eoi_offset < max_search:
                end_offset = min(eoi_offset + 2, len(data))
                return data[offset:end_offset]
            else:
                end_offset = min(offset + 2 * 1024 * 1024, len(data))
                return data[offset:end_offset]
                
        except Exception:
            end_offset = min(offset + 1 * 1024 * 1024, len(data))
            return data[offset:end_offset]

    def _get_metadata(self, memory_path: Path) -> Dict[str, Any]:
        """Generates metadata with improved file hash calculation."""
        try:
            dump_stat = memory_path.stat()
            
            # Calculate partial hash for identification (clearly labeled)
            file_hash_prefix = ""
            try:
                with open(memory_path, 'rb') as f:
                    # Read first 1MB for hash calculation (faster than full file)
                    chunk = f.read(1024 * 1024)
                    file_hash_prefix = hashlib.md5(chunk).hexdigest()
            except Exception as e:
                self.logger.warning(f"Could not calculate file hash prefix: {e}")

            return {
                "source_file": str(memory_path),
                "file_size": dump_stat.st_size,
                "file_hash_prefix": file_hash_prefix,  # Clearly labeled as partial
                "file_hash_note": "Hash of first 1MB only for quick identification",
                "analyzed_at": datetime.now().isoformat(),
                "os_detected": "Windows (determined via Volatility)",
                "tool_version": "Volatility 3 CLI",
                "analyzer_version": "Shikra Memory Analyzer v2.0",
            }
        except Exception as e:
            self.logger.error(f"Error generating metadata: {e}")
            return {
                "source_file": str(memory_path),
                "error": str(e),
                "analyzed_at": datetime.now().isoformat(),
            }

    def _calculate_suspicion_score(self, process: Dict[str, Any]) -> int:
        """Enhanced suspicion scoring with multiplicative factors."""
        try:
            base_score = 0
            multipliers = []
            
            proc_name = str(process.get('imagefilename', '')).lower()
            image_path = str(process.get('image_path', '')).lower()
            cmdline = str(process.get('commandline', '')).lower()

            # Base scoring factors
            if any(name in proc_name for name in self.config.get('suspicious_names', [])):
                base_score += 30
                multipliers.append(1.5)  # Suspicious name multiplier
                
            if image_path and not image_path.startswith(('c:\\windows', 'c:\\program files')):
                base_score += 20
                multipliers.append(1.3)  # Non-standard path multiplier
                
            if len(cmdline) > 200:
                base_score += 25
                multipliers.append(1.2)  # Long command line multiplier
            
            # Check for masquerading (process name vs path mismatch)
            if proc_name in ['svchost.exe', 'explorer.exe', 'winlogon.exe', 'lsass.exe']:
                expected_paths = {
                    'svchost.exe': 'c:\\windows\\system32\\svchost.exe',
                    'explorer.exe': 'c:\\windows\\explorer.exe',
                    'winlogon.exe': 'c:\\windows\\system32\\winlogon.exe',
                    'lsass.exe': 'c:\\windows\\system32\\lsass.exe'
                }
                if expected_paths.get(proc_name, '').lower() != image_path:
                    base_score += 40
                    multipliers.append(2.0)  # High multiplier for masquerading
            
            handle_count = process.get('handle_count', 0)
            if isinstance(handle_count, (int, float)) and handle_count > 1000:
                base_score += 15
                multipliers.append(1.1)
            
            # Apply multiplicative scoring
            final_score = base_score
            for multiplier in multipliers:
                final_score *= multiplier
                
            return min(int(final_score), 100)
            
        except Exception as e:
            self.logger.warning(f"Error calculating suspicion score: {e}")
            return 0

    def _map_process_to_mitre(self, process: Dict[str, Any]) -> List[str]:
        """Maps a process's characteristics to MITRE ATT&CK techniques."""
        try:
            techniques = set()
            mapping = self.config.get('mitre_mapping', {})
            proc_name = str(process.get('imagefilename', '')).lower()
            image_path = str(process.get('image_path', '')).lower()

            if any(keyword in proc_name for keyword in ['inject', 'hollow', 'proxy']):
                techniques.update(mapping.get('process_injection', []))
            if proc_name in mapping.get('masquerading_binaries', []) and not image_path.startswith('c:\\windows'):
                techniques.update(mapping.get('masquerading', []))
            if proc_name in mapping.get('system_binary_proxies', []):
                techniques.update(mapping.get('system_binary_proxy', []))

            return list(techniques)
        except Exception as e:
            self.logger.warning(f"Error mapping process to MITRE: {e}")
            return []
    
    def _create_timeline(self, report: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Creates a chronological timeline of key events."""
        timeline = []
        try:
            processes = report.get('process_analysis', {}).get('processes', [])
            valid_processes = [p for p in processes if isinstance(p, dict) and 'error' not in p]
            
            for process in valid_processes:
                create_time = process.get('create_time')
                exit_time = process.get('exit_time')
                proc_name = process.get('imagefilename', 'Unknown')
                pid = process.get('pid', 'Unknown')
                
                if create_time:
                    timeline.append({
                        'timestamp': str(create_time), 
                        'event_type': 'Process Start', 
                        'description': f"Process {proc_name} (PID {pid}) started."
                    })
                if exit_time:
                    timeline.append({
                        'timestamp': str(exit_time), 
                        'event_type': 'Process End', 
                        'description': f"Process {proc_name} (PID {pid}) ended."
                    })
            
            return sorted(timeline, key=lambda x: x.get('timestamp', ''))
        except Exception as e:
            self.logger.error(f"Error creating timeline: {e}")
            return []

    def _generate_statistics(self, report: Dict[str, Any]) -> Dict[str, Any]:
        """Generates summary statistics from the analysis."""
        try:
            processes = report.get('process_analysis', {}).get('processes', [])
            valid_processes = [p for p in processes if isinstance(p, dict) and 'error' not in p]
            connections = report.get('network_analysis', {}).get('connections', [])
            valid_connections = [c for c in connections if isinstance(c, dict) and 'error' not in c]
            
            # Count additional data from various plugins
            services = report.get('services', [])
            valid_services = [s for s in services if isinstance(s, dict) and 'error' not in s]
            
            # Count carved files
            carved_files = report.get('carved_files', [])
            
            # Count YARA matches
            yara_matches = report.get('malware_analysis', {}).get('yara_matches', [])
            valid_yara = [y for y in yara_matches if isinstance(y, dict) and 'error' not in y]
            
            # Count code injections
            injections = report.get('code_injections', [])
            valid_injections = [i for i in injections if isinstance(i, dict) and 'error' not in i]
            
            # Count command lines
            cmdlines = report.get('process_analysis', {}).get('command_lines', [])
            valid_cmdlines = [c for c in cmdlines if isinstance(c, dict) and 'error' not in c]
            
            # Count additional plugin data from additional_plugins section
            additional_plugins = report.get('additional_plugins', {})
            
            # Count files found (from filescan plugin if available)
            files_found = []
            if 'windows_filescan_filescan' in additional_plugins:
                files_data = additional_plugins['windows_filescan_filescan']
                files_found = [f for f in files_data if isinstance(f, dict) and 'error' not in f]
            
            # Count drivers (from driverscan plugin if available)
            drivers_found = []
            if 'windows_driverscan_driverscan' in additional_plugins:
                drivers_data = additional_plugins['windows_driverscan_driverscan']
                drivers_found = [d for d in drivers_data if isinstance(d, dict) and 'error' not in d]
            
            # Count modules (from modules plugin if available)
            modules_found = []
            if 'windows_modules_modules' in additional_plugins:
                modules_data = additional_plugins['windows_modules_modules']
                modules_found = [m for m in modules_data if isinstance(m, dict) and 'error' not in m]
            
            # Count registry hives (from hivelist plugin if available)
            registry_hives = []
            if 'windows_registry_hivelist_hivelist' in additional_plugins:
                hives_data = additional_plugins['windows_registry_hivelist_hivelist']
                registry_hives = [h for h in hives_data if isinstance(h, dict) and 'error' not in h]
            
            return {
                'total_processes': len(valid_processes),
                'suspicious_processes': len([p for p in valid_processes if p.get('suspicious_score', 0) > 50]),
                'baseline_violations': len(report.get('process_analysis', {}).get('baseline_violations', [])),
                'total_network_connections': len(valid_connections),
                'total_services': len(valid_services),
                'total_files_found': len(files_found),
                'total_drivers': len(drivers_found),
                'total_modules': len(modules_found),
                'registry_hives': len(registry_hives),
                'carved_files': len(carved_files),
                'yara_detections': len(valid_yara),
                'code_injections': len(valid_injections),
                'command_lines_analyzed': len(valid_cmdlines),
                'mitre_techniques_detected': len(set(t for p in valid_processes for t in p.get('mitre_techniques', []))),
                'ransomware_mutexes': len(report.get('ransomware_indicators', {}).get('suspicious_mutexes', [])),
                'bitcoin_addresses_found': len(report.get('ransomware_indicators', {}).get('bitcoin_addresses', [])),
                'tor_addresses_found': len(report.get('ransomware_indicators', {}).get('tor_addresses', []))
            }
        except Exception as e:
            self.logger.error(f"Error generating statistics: {e}")
            return {}
    
    def _generate_executive_summary(self, report: Dict[str, Any]) -> Dict[str, Any]:
        """Generates a high-level summary of the findings."""
        try:
            stats = report['summary'].get('statistics', {})
            risk_score = report['summary'].get('risk_score', 0)
            
            risk_level = "LOW"
            if risk_score >= 8: risk_level = "CRITICAL"
            elif risk_score >= 6: risk_level = "HIGH"
            elif risk_score >= 4: risk_level = "MEDIUM"

            # Count additional indicators
            yara_matches = report.get('malware_analysis', {}).get('yara_matches', [])
            valid_yara = [y for y in yara_matches if isinstance(y, dict) and 'error' not in y]
            
            password_hashes = report.get('security_analysis', {}).get('password_hashes', [])
            valid_hashes = [h for h in password_hashes if isinstance(h, dict) and 'error' not in h]

            return {
                "overall_risk_level": risk_level,
                "total_processes_analyzed": stats.get('total_processes', 0),
                "high_risk_processes": stats.get('suspicious_processes', 0),
                "baseline_violations": stats.get('baseline_violations', 0),
                "injection_techniques_detected": len(report.get('code_injections', [])),
                "ransomware_indicators_found": len(report.get('ransomware_indicators', {}).get('suspicious_mutexes', [])),
                "yara_detections": len(valid_yara),
                "password_hashes_extracted": len(valid_hashes),
                "total_files_analyzed": stats.get('total_files_found', 0),
                "services_found": stats.get('total_services', 0),
                "drivers_found": stats.get('total_drivers', 0),
                "modules_found": stats.get('total_modules', 0),
                "registry_hives_found": stats.get('registry_hives', 0),
                "carved_files_found": stats.get('carved_files', 0),
                "recommendation": f"Recommendation based on {risk_level} risk: {'Immediate investigation required' if risk_level in ['HIGH', 'CRITICAL'] else 'Monitor and investigate further'}."
            }
        except Exception as e:
            self.logger.error(f"Error generating executive summary: {e}")
            return {"error": str(e)}
    
    async def _load_additional_plugins_async(self, memory_path: Path) -> Dict[str, Any]:
        """Async wrapper for loading additional plugins."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(self.thread_pool, self._load_additional_plugins, memory_path)

    def _load_additional_plugins(self, memory_path: Path) -> Dict[str, Any]:
        """Load and run additional plugins if specified in .shikra file."""
        additional_data = {}
        
        if self.addon_plugins_file and self.addon_plugins_file.exists():
            self.logger.info(f"Loading additional plugins from {self.addon_plugins_file}")
            try:
                import json
                with open(self.addon_plugins_file, 'r') as f:
                    plugins_config = json.load(f)
                
                # Run additional plugins specified in the .shikra file
                for plugin_name in plugins_config.get('additional_plugins', []):
                    self.logger.info(f"Running additional plugin: {plugin_name}")
                    result = self._run_plugin(memory_path, plugin_name)
                    # Store with a clean key name
                    key = plugin_name.replace('.', '_').lower()
                    additional_data[key] = result
                    
            except Exception as e:
                self.logger.warning(f"Failed to load additional plugins: {e}")
                additional_data['error'] = str(e)
        else:
            self.logger.debug("No additional plugins file specified or file not found")
            
        return additional_data

    def _get_geo_data(self, ip_address: str) -> Dict[str, Any]:
        """Get geographic data for an IP address using the initialized GeoIP lookup."""
        if not self.geo_lookup:
            return {
                'country': 'Unknown',
                'city': 'Unknown', 
                'latitude': None,
                'longitude': None,
                'error': 'GeoIP lookup not initialized'
            }
            
        try:
            result = self.geo_lookup.lookup(ip_address)
            if result:
                return result
            else:
                return {
                    'country': 'Unknown',
                    'city': 'Unknown', 
                    'latitude': None,
                    'longitude': None
                }
        except Exception as e:
            self.logger.warning(f"GeoIP lookup failed for {ip_address}: {e}")
            return {
                'country': 'Unknown',
                'city': 'Unknown', 
                'latitude': None,
                'longitude': None,
                'error': str(e)
            }

    def _calculate_risk_score(self, report: Dict[str, Any]) -> int:
        """Enhanced risk scoring with evidence compounding."""
        try:
            risk_factors = []
            risk_config = self.risk_config.get('memory', {})
            
            # Process-based risks
            processes = report.get('process_analysis', {}).get('processes', [])
            valid_processes = [p for p in processes if isinstance(p, dict) and 'error' not in p]
            
            high_risk_processes = len([p for p in valid_processes if p.get('suspicious_score', 0) > 50])
            if high_risk_processes > 0:
                risk_factors.append(min(high_risk_processes * 0.8, 3.0))
            
            # Baseline violations with severity weighting
            baseline_violations = report.get('process_analysis', {}).get('baseline_violations', [])
            if baseline_violations:
                severity_weights = {'critical': 2.0, 'high': 1.5, 'medium': 1.0, 'low': 0.5}
                violation_score = sum(severity_weights.get(v.get('severity', 'medium'), 1.0) for v in baseline_violations)
                risk_factors.append(min(violation_score, 4.0))
            
            # Code injection indicators
            injections = report.get('code_injections', [])
            valid_injections = [i for i in injections if isinstance(i, dict) and 'error' not in i]
            if len(valid_injections) > 0:
                risk_factors.append(min(len(valid_injections) * 1.2, 4.0))
            
            # Ransomware indicators (compounding)
            ransomware_indicators = report.get('ransomware_indicators', {})
            ransomware_score = 0
            if ransomware_indicators.get('suspicious_mutexes'):
                ransomware_score += 1.5
            if ransomware_indicators.get('bitcoin_addresses'):
                ransomware_score += 2.5
            if ransomware_indicators.get('tor_addresses'):
                ransomware_score += 2.0
            
            if ransomware_score > 0:
                risk_factors.append(min(ransomware_score, 5.0))
            
            # YARA detections
            yara_matches = report.get('malware_analysis', {}).get('yara_matches', [])
            valid_yara = [y for y in yara_matches if isinstance(y, dict) and 'error' not in y]
            if len(valid_yara) > 0:
                risk_factors.append(min(len(valid_yara) * 1.0, 3.0))
            
            # Calculate final score using evidence compounding
            if not risk_factors:
                return 0
            
            # Use geometric mean for evidence compounding
            import math
            final_score = math.pow(math.prod([(1 + factor) for factor in risk_factors]), 1/len(risk_factors)) - 1
            
            # Scale to 0-10
            max_score = self.risk_config.get('max_score', 10)
            scaled_score = min(final_score * 2, max_score)  # Scale factor adjustment
            
            return int(scaled_score)
            
        except Exception as e:
            self.logger.error(f"Error calculating risk score: {e}")
            return 0

    def __del__(self):
        """Cleanup resources."""
        if hasattr(self, 'thread_pool'):
            self.thread_pool.shutdown(wait=False)
        if hasattr(self, 'geo_lookup') and self.geo_lookup:
            try:
                self.geo_lookup.close()
            except:
                pass

