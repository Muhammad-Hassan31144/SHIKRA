import pandas as pd
from pathlib import Path
import re
from typing import Dict, List, Any, Optional, Iterator, Set, Tuple
from datetime import datetime, timezone
import pefile
import hashlib
import asyncio
import logging
from collections import defaultdict, Counter
import tempfile
import json
import uuid
import ipaddress

from ...utils import GeoIPLookup, VTEnricher, YaraScanner, jsonio
from ...utils.logger import setup_logger

class ProcmonAnalyzer:
    """
    Analyzes a Procmon CSV log to identify suspicious activities, enrich data,
    and generate a structured JSON report in the new standardized format.
    Uses chunked processing for large files and configuration-driven analysis.
    """
    def __init__(self, vt_api_key: Optional[str], config_dir: Path = Path("config"), 
                 chunk_size: int = 10000, disk_image_path: Optional[Path] = None):
        self.logger = setup_logger("ProcmonAnalyzer")
        
        # Make config directory handling more robust
        if config_dir.is_absolute():
            absolute_config_dir = config_dir
        else:
            # Look for config relative to current working directory first
            absolute_config_dir = Path.cwd() / config_dir
            if not absolute_config_dir.exists():
                # Try relative to this file's directory
                absolute_config_dir = Path(__file__).parent.parent.parent.parent / config_dir
        
        if not absolute_config_dir.exists():
            raise FileNotFoundError(f"Config directory not found: {absolute_config_dir}")

        # Load configurations
        self.config = jsonio.load_config(absolute_config_dir / "procmon_config.json")
        self.mitre_config = jsonio.load_config(absolute_config_dir / "mitre_mapping.json")
        self.risk_config = jsonio.load_config(absolute_config_dir / "risk_scoring.json")
        
        # Load granular configurations if enabled
        self.behavioral_filters = None
        self.malware_patterns = None
        self.noise_filters = None
        
        if self.config.get('general', {}).get('use_granular_configs', False):
            granular_path = absolute_config_dir / "procmon"
            try:
                self.behavioral_filters = jsonio.load_config(granular_path / "behavioral_filters.json")
                self.malware_patterns = jsonio.load_config(granular_path / "malware_patterns.json") 
                self.noise_filters = jsonio.load_config(granular_path / "noise_filters.json")
                self.logger.info("Loaded granular procmon configurations")
            except FileNotFoundError as e:
                self.logger.warning(f"Could not load granular configs: {e}")
            except Exception as e:
                self.logger.error(f"Error loading granular configs: {e}")

        # Processing parameters
        self.chunk_size = chunk_size
        self.disk_image_path = disk_image_path
        
        # Initialize external services using config
        self.vt = None
        if vt_api_key and vt_api_key != "YOUR_VIRUSTOTAL_API_KEY_HERE":
            try:
                self.vt = VTEnricher(vt_api_key)
                self.logger.info("VirusTotal enrichment enabled")
            except Exception as e:
                self.logger.warning(f"Failed to initialize VirusTotal: {e}")
        else:
            self.logger.info("VirusTotal enrichment disabled")

        self.yara = YaraScanner()
        
        # Regex patterns for robust parsing
        self._compile_patterns()
        
        # New data structures for the updated format
        self.events = []  # All parsed events with full detail
        self.process_tree = {"root_processes": [], "orphaned_processes": [], "pid_reuse_detected": []}
        self.process_map = {}  # PID -> process info for tree building
        self.network_connections = defaultdict(list)  # Remote IP -> connection list
        self.file_operations = defaultdict(list)  # File path -> operation list
        self.process_operations = defaultdict(list)  # Process name -> operation list
        self.alerts = []
        
        # Analysis metadata
        self.analysis_start_time = None
        self.analysis_end_time = None
        self.host_info = {}
        self.event_type_counts = {"process": 0, "file": 0, "registry": 0, "network": 0}
        self.total_events_processed = 0
        
    def _compile_patterns(self):
        """Compile regex patterns from configuration for robust data parsing."""
        # Network detail parsing patterns
        self.network_patterns = [
            re.compile(r'(\d+\.\d+\.\d+\.\d+):(\d+)\s*->\s*(\d+\.\d+\.\d+\.\d+):(\d+)'),  # IP:Port -> IP:Port
            re.compile(r'([^:]+):(\d+)\s*->\s*([^:]+):(\d+)'),  # Host:Port -> Host:Port
            re.compile(r'(\S+)\s*->\s*(\S+)'),  # Generic source -> destination
        ]
        
        # Compile registry patterns from config
        registry_patterns = self.config.get('detection_patterns', {}).get('suspicious_registry_key_regex', [])
        self.registry_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in registry_patterns]
        
        # Compile command line patterns from config  
        cmdline_patterns = self.config.get('detection_patterns', {}).get('suspicious_cmdline_regex', [])
        self.cmdline_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in cmdline_patterns]
        
        # Compile file path patterns from config
        file_path_patterns = self.config.get('detection_patterns', {}).get('suspicious_file_path_regex', [])
        self.file_path_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in file_path_patterns]
        
        # Get suspicious process names from config
        self.suspicious_process_names = [name.lower() for name in 
                                       self.config.get('detection_patterns', {}).get('suspicious_process_names', [])]
        
        # Get high risk countries from config
        self.high_risk_countries = self.config.get('general', {}).get('high_risk_countries', [])
        
        # Enhance patterns with granular configurations if available
        if self.malware_patterns:
            # Add malware-specific patterns
            malware_process_names = self.malware_patterns.get('suspicious_processes', {}).get('ransomware_process_names', [])
            self.suspicious_process_names.extend([name.lower() for name in malware_process_names])
            
            # Add suspicious name patterns
            name_patterns = self.malware_patterns.get('suspicious_processes', {}).get('suspicious_name_patterns', [])
            for pattern in name_patterns:
                try:
                    self.cmdline_patterns.append(re.compile(pattern, re.IGNORECASE))
                except re.error as e:
                    self.logger.warning(f"Invalid regex pattern in malware_patterns: {pattern} - {e}")
            
            # Add ransomware file extensions
            ransomware_extensions = self.malware_patterns.get('file_extensions', {}).get('ransomware_extensions', [])
            ransomware_pattern = r'\\.*\.(' + '|'.join([ext.lstrip('.') for ext in ransomware_extensions]) + r')$'
            try:
                self.file_path_patterns.append(re.compile(ransomware_pattern, re.IGNORECASE))
            except re.error as e:
                self.logger.warning(f"Invalid ransomware extension pattern: {e}")
        
        # Prepare filtering patterns from behavioral and noise filters
        self.always_filter_processes = set()
        self.conditionally_filter_processes = set() 
        
        if self.behavioral_filters:
            # Load system processes to filter
            always_filter = self.behavioral_filters.get('system_processes_filter', {}).get('always_filter', [])
            self.always_filter_processes.update([proc.lower() for proc in always_filter])
            
            conditionally_filter = self.behavioral_filters.get('system_processes_filter', {}).get('conditionally_filter', [])
            self.conditionally_filter_processes.update([proc.lower() for proc in conditionally_filter])
        
        if self.noise_filters:
            # Load noise filtering patterns
            noise_processes = self.noise_filters.get('system_noise_patterns', {}).get('windows_system_processes', {}).get('always_filter', [])
            self.always_filter_processes.update([proc.lower().replace('\\\\', '') for proc in noise_processes])

    async def analyze(self, csv_path: Path) -> Dict[str, Any]:
        """
        Main analysis function that produces the new standardized JSON format.
        Processes CSV in chunks for large files and generates comprehensive analysis.
        """
        self.logger.info(f"Starting analysis of {csv_path} with new format")
        
        # Initialize analysis metadata
        self.analysis_start_time = datetime.now(timezone.utc)
        self._reset_data_structures()
        
        # Extract host info from CSV metadata if available
        self._extract_host_info(csv_path)
        
        # Process CSV in chunks to build events and relationships
        total_events = await self._process_csv_for_events(csv_path)
        self.total_events_processed = total_events
        
        # Enrich events with external data
        await self._enrich_events()
        
        # Build process tree from events
        self._build_process_tree()
        
        # Generate aggregations
        aggregations = self._generate_aggregations()
        
        # Generate alerts
        self._generate_alerts()
        
        # Set analysis end time
        self.analysis_end_time = datetime.now(timezone.utc)
        
        # Build final report in new format
        report = {
            "metadata": self._build_metadata(),
            "events": self.events,
            "process_tree": self.process_tree,
            "aggregations": aggregations,
            "alerts": self.alerts
        }
        
        # Calculate risk scores and MITRE mappings for aggregations
        self._enhance_aggregations_with_analysis(report)
        
        self.logger.info(f"Analysis complete. Processed {total_events} events, generated {len(self.events)} detailed events, {len(self.alerts)} alerts")
        return report

    def _reset_data_structures(self):
        """Reset all data structures for a fresh analysis."""
        self.events = []
        self.process_tree = {"root_processes": [], "orphaned_processes": [], "pid_reuse_detected": []}
        self.process_map = {}
        self.network_connections = defaultdict(list)
        self.file_operations = defaultdict(list)
        self.process_operations = defaultdict(list)
        self.alerts = []
        self.event_type_counts = {"process": 0, "file": 0, "registry": 0, "network": 0}
        self.total_events_processed = 0

    def _extract_host_info(self, csv_path: Path):
        """Extract host information from CSV header or filename if available."""
        # Try to extract from filename or use defaults
        filename = csv_path.stem
        self.host_info = {
            "hostname": filename if filename else "UNKNOWN",
            "os_version": "Windows (version unknown)",
            "architecture": "x64"
        }
        
        # TODO: Could be enhanced to parse actual CSV header if it contains host info

    async def _process_csv_for_events(self, csv_path: Path) -> int:
        """Process CSV file to create detailed events in the new format."""
        self.logger.info(f"Processing CSV to generate detailed events...")
        
        total_events = 0
        chunk_count = 0
        
        try:
            # Common timestamp formats to try
            timestamp_formats = [
                '%m/%d/%Y %I:%M:%S.%f %p',  # MM/dd/yyyy HH:mm:ss.fff AM/PM
                '%Y-%m-%d %H:%M:%S.%f',     # yyyy-MM-dd HH:mm:ss.fff
                '%m/%d/%Y %H:%M:%S.%f',     # MM/dd/yyyy HH:mm:ss.fff
                '%Y-%m-%d %H:%M:%S',        # yyyy-MM-dd HH:mm:ss
                '%m/%d/%Y %H:%M:%S',        # MM/dd/yyyy HH:mm:ss
            ]
            
            for chunk in pd.read_csv(csv_path, chunksize=self.chunk_size):
                chunk_count += 1
                self.logger.debug(f"Processing chunk {chunk_count} with {len(chunk)} events")
                
                # Parse timestamps
                chunk = self._parse_timestamps(chunk, timestamp_formats)
                
                # Process chunk to create events
                self._process_chunk_for_events(chunk)
                
                total_events += len(chunk)
                
                # Limit total events to prevent memory issues
                max_events = self.config.get('general', {}).get('max_events_to_process', 1000000)
                if total_events >= max_events:
                    self.logger.warning(f"Reached maximum events limit ({max_events}), stopping processing")
                    break
                    
        except Exception as e:
            self.logger.error(f"Error processing CSV: {e}")
            raise
            
        self.logger.info(f"Completed processing {chunk_count} chunks, {total_events} total events")
        return total_events

    def _reset_aggregators(self):
        """Reset all data aggregators for a fresh analysis."""
        self.unique_files = set()
        self.unique_processes = set()
        self.registry_events = []
        self.network_events = []
        self.file_operations = defaultdict(list)
        self.process_operations = []
        self.timeline_events = []

    async def _process_csv_chunks(self, csv_path: Path) -> int:
        """Process CSV file in chunks to handle large files efficiently."""
        self.logger.info(f"Processing CSV in chunks of {self.chunk_size} events...")
        
        total_events = 0
        chunk_count = 0
        
        try:
            # Try different timestamp formats
            timestamp_formats = [
                '%I:%M:%S.%f %p',  # Default Procmon format
                '%H:%M:%S.%f',     # 24-hour format
                '%m/%d/%Y %I:%M:%S.%f %p',  # With date
                '%Y-%m-%d %H:%M:%S.%f',     # ISO format
            ]
            
            for chunk in pd.read_csv(csv_path, chunksize=self.chunk_size, 
                                   encoding='utf-8', on_bad_lines='skip'):
                chunk_count += 1
                self.logger.debug(f"Processing chunk {chunk_count}...")
                
                # Normalize column names
                chunk.columns = [c.strip().lower().replace(' ', '_').replace('&', 'and') 
                               for c in chunk.columns]
                
                # Find and parse timestamp column
                chunk = self._parse_timestamps(chunk, timestamp_formats)
                
                # Clean data
                chunk.fillna('', inplace=True)
                chunk.dropna(subset=['timestamp'], inplace=True)
                
                # Process chunk data
                self._process_chunk(chunk)
                
                total_events += len(chunk)
                
                if chunk_count % 10 == 0:
                    self.logger.info(f"Processed {chunk_count} chunks, {total_events} events so far...")
                    
        except Exception as e:
            self.logger.error(f"Error processing CSV chunks: {e}")
            raise
            
        self.logger.info(f"Completed processing {chunk_count} chunks, {total_events} total events")
        return total_events

    def _parse_timestamps(self, chunk: pd.DataFrame, formats: List[str]) -> pd.DataFrame:
        """Parse timestamps with multiple format attempts."""
        timestamp_cols = ['Time of Day', 'Date & Time', 'date_and_time', 'time_of_day', 'timestamp']
        timestamp_col = None
        
        for col in timestamp_cols:
            if col in chunk.columns:
                timestamp_col = col
                break
                
        if timestamp_col is None:
            # Fallback to first column that looks like a timestamp
            for col in chunk.columns:
                if any(keyword in col.lower() for keyword in ['time', 'date']):
                    timestamp_col = col
                    break
        
        if timestamp_col is None:
            self.logger.warning("No timestamp column found, using row index")
            chunk['timestamp'] = pd.to_datetime('now')
            return chunk
        
        # Try different timestamp formats
        for fmt in formats:
            try:
                chunk['timestamp'] = pd.to_datetime(chunk[timestamp_col], format=fmt, errors='coerce')
                if not chunk['timestamp'].isna().all():
                    break
            except:
                continue
        
        # Fallback to pandas auto-detection
        if chunk['timestamp'].isna().all():
            self.logger.warning("Using pandas auto timestamp detection as fallback")
            chunk['timestamp'] = pd.to_datetime(chunk[timestamp_col], errors='coerce')
            
        return chunk

    def _process_chunk_for_events(self, chunk: pd.DataFrame):
        """Process a single chunk of data to create detailed events."""
        
        for _, row in chunk.iterrows():
            try:
                # Create base event
                event = self._create_base_event(row)
                
                # Enhance event based on operation type - handle both lowercase and capitalized columns
                operation = str(row.get('Operation', row.get('operation', ''))).strip()
                
                if self._is_process_operation(operation):
                    self._enhance_process_event(event, row)
                    self.event_type_counts["process"] += 1
                elif self._is_file_operation(operation):
                    self._enhance_file_event(event, row)
                    self.event_type_counts["file"] += 1
                elif self._is_registry_operation(operation):
                    self._enhance_registry_event(event, row)
                    self.event_type_counts["registry"] += 1
                elif self._is_network_operation(operation):
                    self._enhance_network_event(event, row)
                    self.event_type_counts["network"] += 1
                else:
                    continue  # Skip unknown operations
                
                # Add to events list if it meets criteria
                if self._should_include_event(event):
                    self.events.append(event)
                    
            except Exception as e:
                self.logger.debug(f"Error processing row: {e}")
                continue

    def _create_base_event(self, row: pd.Series) -> Dict[str, Any]:
        """Create base event structure."""
        event_id = f"evt_{uuid.uuid4().hex[:12]}"
        
        # Parse timestamp
        timestamp = row.get('timestamp')
        if pd.isna(timestamp):
            timestamp = datetime.now(timezone.utc)
        elif not isinstance(timestamp, datetime):
            timestamp = pd.to_datetime(timestamp)
        
        # Ensure timezone awareness
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
        
        return {
            "id": event_id,
            "timestamp": timestamp.isoformat(),
            "operation": str(row.get('Operation', row.get('operation', ''))).strip(),
            "result": str(row.get('Result', row.get('result', 'unknown'))).strip().lower(),
            "process_info": {
                "pid": self._safe_int(row.get('PID', row.get('pid', 0))),
                "name": str(row.get('Process Name', row.get('process_name', ''))).strip(),
                "path": str(row.get('Image Path', row.get('Path', row.get('path', '')))).strip(),
            },
            "enrichment": {
                "threat_intel": {"iocs": [], "mitre_tactics": [], "severity": "unknown"},
                "behavioral_analysis": {"anomaly_score": 0.0, "pattern_matches": [], "baseline_deviation": False},
                "context": {"first_seen": timestamp.isoformat(), "frequency": 1, "related_events": []}
            },
            "tags": []
        }

    def _safe_int(self, value) -> int:
        """Safely convert value to integer."""
        try:
            if pd.isna(value):
                return 0
            return int(float(value))
        except (ValueError, TypeError):
            return 0

    def _is_process_operation(self, operation: str) -> bool:
        """Check if operation is process-related."""
        process_ops = self.config.get('operations_to_monitor', {}).get('process', [])
        return operation in process_ops

    def _is_file_operation(self, operation: str) -> bool:
        """Check if operation is file-related."""
        file_ops = self.config.get('operations_to_monitor', {}).get('file', [])
        return operation in file_ops

    def _is_registry_operation(self, operation: str) -> bool:
        """Check if operation is registry-related."""
        registry_ops = self.config.get('operations_to_monitor', {}).get('registry', [])
        return operation in registry_ops

    def _is_network_operation(self, operation: str) -> bool:
        """Check if operation is network-related."""
        network_ops = self.config.get('operations_to_monitor', {}).get('network', [])
        return operation in network_ops

    def _enhance_process_event(self, event: Dict[str, Any], row: pd.Series):
        """Enhance event with process-specific information."""
        event["event_type"] = "process"
        
        # Add detailed process info - handle different column names
        command_line = str(row.get('Command Line', row.get('command_line', ''))).strip()
        user = str(row.get('User', row.get('user', ''))).strip()
        
        event["process_info"].update({
            "command_line": command_line,
            "user": user,
            "session_id": self._safe_int(row.get('session_id', 1)),
            "integrity_level": str(row.get('integrity_level', 'medium')).strip(),
            "process_ancestry": []  # Will be filled later in tree building
        })
        
        # Analyze for suspicious indicators
        suspicion_indicators = self._analyze_process_suspicion_new(
            event["process_info"]["path"], 
            command_line
        )
        
        if suspicion_indicators:
            event["enrichment"]["behavioral_analysis"]["pattern_matches"] = suspicion_indicators
            event["enrichment"]["behavioral_analysis"]["anomaly_score"] = len(suspicion_indicators) * 2.0
            event["tags"].extend(suspicion_indicators)

    def _enhance_file_event(self, event: Dict[str, Any], row: pd.Series):
        """Enhance event with file-specific information."""
        event["event_type"] = "file"
        
        # Add file info - handle different column names
        file_path = str(row.get('Path', row.get('Detail', row.get('detail', row.get('path', ''))))).strip()
        
        event["file_info"] = {
            "path": file_path,
            "size": self._safe_int(row.get('file_size', 0)),
            "hash": {},  # Will be filled during enrichment
            "attributes": [],
            "creation_time": None,
            "reputation": {"score": 0, "verdict": "unknown", "sources": []}
        }
        
        # Track file operations for aggregation
        self.file_operations[file_path].append({
            "operation": event["operation"],
            "process": event["process_info"]["name"],
            "timestamp": event["timestamp"]
        })
        
        # Check for suspicious file paths
        suspicion_indicators = []
        for pattern in self.file_path_patterns:
            if pattern.search(file_path):
                suspicion_indicators.append("suspicious_file_path")
                break
        
        if suspicion_indicators:
            event["enrichment"]["behavioral_analysis"]["pattern_matches"] = suspicion_indicators
            event["tags"].extend(suspicion_indicators)

    def _enhance_registry_event(self, event: Dict[str, Any], row: pd.Series):
        """Enhance event with registry-specific information."""
        event["event_type"] = "registry"
        
        # Parse registry details - handle different column names
        detail = str(row.get('Detail', row.get('detail', ''))).strip()
        registry_path = str(row.get('Path', row.get('path', ''))).strip()
        
        event["registry_info"] = {
            "key": registry_path,
            "value_name": "",
            "value_data": "",
            "value_type": "REG_UNKNOWN"
        }
        
        # Try to parse registry value details from detail field
        self._parse_registry_details(event["registry_info"], detail)
        
        # Check for persistence mechanisms
        persistence_technique = self._identify_persistence_technique_new(registry_path)
        if persistence_technique:
            event["enrichment"]["threat_intel"]["mitre_tactics"].append("T1547.001")
            event["enrichment"]["behavioral_analysis"]["pattern_matches"].append("registry_persistence")
            event["tags"].extend(["persistence", "registry_modification"])

    def _enhance_network_event(self, event: Dict[str, Any], row: pd.Series):
        """Enhance event with network-specific information."""
        event["event_type"] = "network"
        
        # Parse network details - handle different column names
        detail = str(row.get('Detail', row.get('detail', ''))).strip()
        network_info = self._parse_network_detail(detail)
        
        if network_info:
            event["network_info"] = {
                "protocol": str(row.get('protocol', 'tcp')).lower(),
                "local_address": network_info.get('local_ip', ''),
                "local_port": network_info.get('local_port', ''),
                "remote_address": network_info.get('remote_ip', ''),
                "remote_port": network_info.get('remote_port', ''),
                "direction": "outbound",  # Default assumption
                "bytes_sent": 0,
                "bytes_received": 0,
                "geolocation": {}  # Will be filled during enrichment
            }
            
            # Track network connections for aggregation
            remote_ip = network_info.get('remote_ip', '')
            if remote_ip and self._is_external_ip(remote_ip):
                self.network_connections[remote_ip].append({
                    "timestamp": event["timestamp"],
                    "process": event["process_info"]["name"],
                    "local_port": network_info.get('local_port', ''),
                    "remote_port": network_info.get('remote_port', '')
                })

    def _should_include_event(self, event: Dict[str, Any]) -> bool:
        """Determine if event should be included in final output using intelligent filtering."""
        
        # Always include high-value events with pattern matches
        if event["enrichment"]["behavioral_analysis"]["pattern_matches"]:
            return True
        
        # Apply intelligent noise filtering based on configuration
        if self._is_noise_event(event):
            return False
            
        # Apply behavioral filtering
        if not self._passes_behavioral_filter(event):
            return False
            
        # Include process and network events (high value)
        if event.get("event_type") in ["process", "network"]:
            return True
            
        # Include registry persistence events
        if event.get("event_type") == "registry" and "registry_persistence" in event.get("tags", []):
            return True
            
        # Include file events for suspicious paths
        if event.get("event_type") == "file" and "suspicious_file_path" in event.get("tags", []):
            return True
            
        # Apply malware-specific filtering if enabled
        if self.malware_patterns and self._is_malware_relevant_event(event):
            return True
            
        # For file and registry events, apply more selective filtering
        if event.get("event_type") in ["file", "registry"]:
            # Include events from non-system processes
            process_name = event.get("process", {}).get("name", "").lower()
            if process_name and process_name not in self.always_filter_processes:
                return True
                
        # For large datasets, limit total events to prevent memory issues
        return len(self.events) < self.config.get('general', {}).get('max_events_to_process', 1000000)

    def _is_noise_event(self, event: Dict[str, Any]) -> bool:
        """Check if event should be filtered as noise using granular configurations."""
        if not self.noise_filters:
            return False
            
        process_name = event.get("process", {}).get("name", "").lower()
        
        # Always filter system noise processes
        always_filter = self.noise_filters.get('system_noise_patterns', {}).get('windows_system_processes', {}).get('always_filter', [])
        for noise_pattern in always_filter:
            if re.match(noise_pattern.replace('\\\\', ''), process_name, re.IGNORECASE):
                return True
                
        # Apply noise reduction based on level
        noise_level = self.config.get('filtering', {}).get('noise_reduction_level', 'balanced')
        filter_percentage = self.noise_filters.get('noise_reduction_levels', {}).get(noise_level, {}).get('filter_percentage', 85)
        
        # For high noise reduction, filter common operations from system processes
        if filter_percentage >= 90:
            operation = event.get("operation", "").lower()
            if process_name in self.conditionally_filter_processes and operation in ['process and thread activity', 'registry', 'file']:
                return True
                
        return False

    def _passes_behavioral_filter(self, event: Dict[str, Any]) -> bool:
        """Apply behavioral filters from granular configuration."""
        if not self.behavioral_filters:
            return True
            
        process_name = event.get("process", {}).get("name", "").lower()
        
        # Always filter system processes unless they show suspicious behavior
        if process_name in self.always_filter_processes:
            # But keep if they have pattern matches or suspicious tags
            has_patterns = bool(event["enrichment"]["behavioral_analysis"]["pattern_matches"])
            has_suspicious_tags = any(tag in ['suspicious_process', 'suspicious_file_path', 'registry_persistence'] 
                                    for tag in event.get("tags", []))
            return has_patterns or has_suspicious_tags
            
        return True

    def _is_malware_relevant_event(self, event: Dict[str, Any]) -> bool:
        """Check if event is relevant to malware analysis using patterns."""
        if not self.malware_patterns:
            return False
            
        # Check for ransomware file extensions
        if event.get("event_type") == "file":
            file_path = event.get("file", {}).get("path", "").lower()
            ransomware_extensions = self.malware_patterns.get('file_extensions', {}).get('ransomware_extensions', [])
            for ext in ransomware_extensions:
                if file_path.endswith(ext.lower()):
                    return True
                    
        # Check for suspicious process patterns
        process_name = event.get("process", {}).get("name", "").lower()
        suspicious_patterns = self.malware_patterns.get('suspicious_processes', {}).get('suspicious_name_patterns', [])
        for pattern in suspicious_patterns:
            try:
                if re.match(pattern, process_name, re.IGNORECASE):
                    return True
            except re.error:
                continue
                
        return False

    def _analyze_process_suspicion_new(self, process_path: str, command_line: str) -> List[str]:
        """Analyze process for suspicious indicators using config patterns."""
        indicators = []
        
        process_name = Path(process_path).name.lower()
        
        # Check for suspicious process names from config
        if process_name in self.suspicious_process_names:
            indicators.append("suspicious_process_name")
        
        # Check for suspicious command line patterns from config
        for pattern in self.cmdline_patterns:
            if pattern.search(command_line):
                indicators.append("suspicious_cmdline_pattern")
                break
        
        # Check for PowerShell obfuscation
        if 'powershell' in process_path.lower():
            if any(indicator in command_line.lower() for indicator in ['-enc', 'encodedcommand', 'bypass']):
                indicators.append("powershell_obfuscation")
        
        # Check for process masquerading
        legit_names = ['svchost.exe', 'explorer.exe', 'winlogon.exe', 'smss.exe']
        if process_name in legit_names:
            expected_paths = {
                'svchost.exe': r'\\windows\\system32\\',
                'explorer.exe': r'\\windows\\',
                'winlogon.exe': r'\\windows\\system32\\',
                'smss.exe': r'\\windows\\system32\\'
            }
            expected_path = expected_paths.get(process_name, '')
            if expected_path and not re.search(expected_path, process_path, re.IGNORECASE):
                indicators.append("process_masquerading")
        
        return indicators

    def _parse_registry_details(self, registry_info: Dict[str, Any], detail: str):
        """Parse registry operation details."""
        # Try to extract value name and data from detail string
        if 'name:' in detail.lower() and 'type:' in detail.lower():
            parts = detail.split(',')
            for part in parts:
                part = part.strip()
                if part.lower().startswith('name:'):
                    registry_info["value_name"] = part[5:].strip()
                elif part.lower().startswith('type:'):
                    registry_info["value_type"] = part[5:].strip()
                elif part.lower().startswith('data:'):
                    registry_info["value_data"] = part[5:].strip()

    def _identify_persistence_technique_new(self, reg_path: str) -> Optional[str]:
        """Identify specific persistence technique from registry path using config."""
        for pattern in self.registry_patterns:
            if pattern.search(reg_path):
                return "Registry Run Keys"
        return None

    async def _enrich_events(self):
        """Enrich events with external data sources."""
        self.logger.info("Enriching events with external data...")
        
        # Collect unique file paths and hashes for VT lookup
        file_paths = set()
        file_hashes = {}
        
        for event in self.events:
            if event.get("event_type") == "file":
                file_path = event.get("file_info", {}).get("path", "")
                if file_path and Path(file_path).exists():
                    file_paths.add(file_path)
        
        # Calculate hashes for existing files
        for file_path in file_paths:
            try:
                file_hash = self._calculate_file_hash(Path(file_path))
                if file_hash:
                    file_hashes[file_path] = file_hash
            except Exception as e:
                self.logger.debug(f"Could not hash {file_path}: {e}")
        
        # VT enrichment for files
        if self.vt and file_hashes:
            await self._enrich_with_virustotal(file_hashes)
        
        # YARA scanning
        await self._enrich_with_yara()
        
        # Geo enrichment for network events
        await self._enrich_with_geolocation()

    async def _enrich_with_virustotal(self, file_hashes: Dict[str, str]):
        """Enrich file events with VirusTotal data."""
        self.logger.info(f"Enriching {len(file_hashes)} files with VirusTotal...")
        
        # Bulk lookup hashes
        vt_results = {}
        for file_path, file_hash in file_hashes.items():
            try:
                result = await self.vt.get_file_report(file_hash)
                if result:
                    vt_results[file_path] = result
            except Exception as e:
                self.logger.debug(f"VT lookup failed for {file_hash}: {e}")
        
        # Apply results to events
        for event in self.events:
            if event.get("event_type") == "file":
                file_path = event.get("file_info", {}).get("path", "")
                if file_path in vt_results:
                    vt_result = vt_results[file_path]
                    self._apply_vt_results_to_event(event, vt_result)

    def _apply_vt_results_to_event(self, event: Dict[str, Any], vt_result: Dict[str, Any]):
        """Apply VirusTotal results to file event."""
        if 'data' in vt_result:
            attrs = vt_result['data'].get('attributes', {})
            stats = attrs.get('last_analysis_stats', {})
            
            # Update file hash
            event["file_info"]["hash"] = {
                "md5": attrs.get('md5', ''),
                "sha1": attrs.get('sha1', ''),  
                "sha256": attrs.get('sha256', '')
            }
            
            # Update reputation
            malicious_count = stats.get('malicious', 0)
            if malicious_count > 0:
                event["file_info"]["reputation"] = {
                    "score": malicious_count,
                    "verdict": "malicious" if malicious_count >= 5 else "suspicious",
                    "sources": ["virustotal"]
                }
                event["enrichment"]["threat_intel"]["iocs"].append("hash_match")
                event["tags"].append("malware_detected")

    async def _enrich_with_yara(self):
        """Enrich events with YARA scanning results.""" 
        self.logger.info("Enriching with YARA scanning...")
        
        for event in self.events:
            if event.get("event_type") == "file":
                file_path = event.get("file_info", {}).get("path", "")
                if file_path and Path(file_path).exists():
                    try:
                        yara_matches = self.yara.scan_file(Path(file_path))
                        if yara_matches:
                            event["enrichment"]["threat_intel"]["yara_matches"] = yara_matches
                            event["tags"].append("yara_match")
                    except Exception as e:
                        self.logger.debug(f"YARA scan failed for {file_path}: {e}")

    async def _enrich_with_geolocation(self):
        """Enrich network events with geolocation data."""
        self.logger.info("Enriching network events with geolocation...")
        
        # Collect unique external IPs
        external_ips = set()
        for event in self.events:
            if event.get("event_type") == "network":
                remote_ip = event.get("network_info", {}).get("remote_address", "")
                if remote_ip and self._is_external_ip(remote_ip):
                    external_ips.add(remote_ip)
        
        # Bulk geo lookup
        geo_cache = {}
        if external_ips:
            with GeoIPLookup() as geo:
                for ip in external_ips:
                    try:
                        geo_info = geo.lookup(ip)
                        if geo_info:
                            geo_cache[ip] = geo_info
                    except Exception as e:
                        self.logger.debug(f"Geo lookup failed for {ip}: {e}")
        
        # Apply geo data to events
        for event in self.events:
            if event.get("event_type") == "network":
                remote_ip = event.get("network_info", {}).get("remote_address", "")
                if remote_ip in geo_cache:
                    geo_info = geo_cache[remote_ip]
                    event["network_info"]["geolocation"] = {
                        "country": geo_info.get('country_code', ''),
                        "asn": geo_info.get('asn', ''),
                        "organization": geo_info.get('org', '')
                    }
                    
                    # Assess risk based on geolocation
                    if geo_info.get('country_code', '') in self.high_risk_countries:
                        event["tags"].extend(["high_risk_geo", "suspicious_network"])
                        event["enrichment"]["threat_intel"]["iocs"].append("high_risk_geo")

    def _build_metadata(self) -> Dict[str, Any]:
        """Build metadata section for the report."""
        return {
            "collection_start": self.analysis_start_time.isoformat() if self.analysis_start_time else None,
            "collection_end": self.analysis_end_time.isoformat() if self.analysis_end_time else None,
            "host_info": self.host_info,
            "parser_version": "2.1.0",
            "config_applied": {
                "filters": ["exclude_system_processes", "include_network_events"],
                "enrichment": ["process_ancestry", "file_reputation", "network_geolocation"],
                "aggregation_window": "1m"
            },
            "total_events": self.total_events_processed,
            "event_types": self.event_type_counts
        }

    def _build_process_tree(self):
        """Build process tree from events."""
        # For now, simplified implementation - can be enhanced
        self.process_tree = {
            "root_processes": [],
            "orphaned_processes": [],
            "pid_reuse_detected": []
        }
        
        # TODO: Implement full process tree building from events

    def _generate_aggregations(self) -> Dict[str, Any]:
        """Generate aggregation data."""
        return {
            "process_summary": self._generate_process_summary(),
            "network_summary": self._generate_network_summary(),
            "file_summary": self._generate_file_summary()
        }

    def _generate_process_summary(self) -> List[Dict[str, Any]]:
        """Generate process summary aggregations."""
        process_stats = defaultdict(lambda: {
            "event_count": 0,
            "first_seen": None,
            "last_seen": None,
            "operations": defaultdict(int),
            "risk_score": 0.0
        })
        
        for event in self.events:
            if event.get("event_type") == "process":
                process_name = event.get("process_info", {}).get("name", "unknown")
                timestamp = event.get("timestamp")
                operation = event.get("operation")
                
                stats = process_stats[process_name]
                stats["event_count"] += 1
                stats["operations"][operation] += 1
                
                if not stats["first_seen"] or timestamp < stats["first_seen"]:
                    stats["first_seen"] = timestamp
                if not stats["last_seen"] or timestamp > stats["last_seen"]:
                    stats["last_seen"] = timestamp
                
                # Calculate risk score based on behavioral analysis
                anomaly_score = event.get("enrichment", {}).get("behavioral_analysis", {}).get("anomaly_score", 0)
                if anomaly_score > stats["risk_score"]:
                    stats["risk_score"] = anomaly_score
        
        # Convert to list format
        return [
            {
                "process_name": name,
                "event_count": stats["event_count"],
                "first_seen": stats["first_seen"],
                "last_seen": stats["last_seen"],
                "operations": dict(stats["operations"]),
                "risk_score": stats["risk_score"]
            }
            for name, stats in process_stats.items()
        ]

    def _generate_network_summary(self) -> List[Dict[str, Any]]:
        """Generate network summary aggregations."""
        network_stats = defaultdict(lambda: {
            "connection_count": 0,
            "total_bytes": 0,
            "first_connection": None,
            "last_connection": None,
            "threat_intel": {"verdict": "unknown", "category": "unknown"}
        })
        
        for event in self.events:
            if event.get("event_type") == "network":
                remote_address = event.get("network_info", {}).get("remote_address", "")
                timestamp = event.get("timestamp")
                
                if remote_address:
                    stats = network_stats[remote_address]
                    stats["connection_count"] += 1
                    
                    if not stats["first_connection"] or timestamp < stats["first_connection"]:
                        stats["first_connection"] = timestamp
                    if not stats["last_connection"] or timestamp > stats["last_connection"]:
                        stats["last_connection"] = timestamp
                    
                    # Update threat intel if available
                    if "high_risk_geo" in event.get("tags", []):
                        stats["threat_intel"] = {"verdict": "suspicious", "category": "high_risk_geo"}
        
        return [
            {
                "remote_address": address,
                "connection_count": stats["connection_count"],
                "total_bytes": stats["total_bytes"],
                "first_connection": stats["first_connection"],
                "last_connection": stats["last_connection"],
                "threat_intel": stats["threat_intel"]
            }
            for address, stats in network_stats.items()
        ]

    def _generate_file_summary(self) -> List[Dict[str, Any]]:
        """Generate file summary aggregations."""
        file_stats = defaultdict(lambda: {
            "operations": [],
            "processes": set(),
            "risk_score": 0.0,
            "reputation": "unknown"
        })
        
        for event in self.events:
            if event.get("event_type") == "file":
                file_path = event.get("file_info", {}).get("path", "")
                operation = event.get("operation")
                process_name = event.get("process_info", {}).get("name", "")
                
                if file_path:
                    stats = file_stats[file_path]
                    stats["operations"].append(operation)
                    stats["processes"].add(process_name)
                    
                    # Update reputation from VT
                    reputation = event.get("file_info", {}).get("reputation", {}).get("verdict", "unknown")
                    if reputation != "unknown":
                        stats["reputation"] = reputation
                        stats["risk_score"] = event.get("file_info", {}).get("reputation", {}).get("score", 0)
        
        return [
            {
                "file_path": file_path,
                "operations": list(set(stats["operations"])),
                "processes": list(stats["processes"]),
                "risk_score": stats["risk_score"],
                "reputation": stats["reputation"]
            }
            for file_path, stats in file_stats.items()
        ]

    def _generate_alerts(self):
        """Generate alerts based on events."""
        alert_conditions = [
            {
                "condition": lambda e: "malware_detected" in e.get("tags", []),
                "title": "Malware Detection",
                "severity": "high",
                "description": "Malicious file detected through VirusTotal analysis"
            },
            {
                "condition": lambda e: "powershell_obfuscation" in e.get("enrichment", {}).get("behavioral_analysis", {}).get("pattern_matches", []),
                "title": "PowerShell Obfuscation Detected",
                "severity": "high", 
                "description": "Obfuscated PowerShell execution detected"
            },
            {
                "condition": lambda e: "registry_persistence" in e.get("enrichment", {}).get("behavioral_analysis", {}).get("pattern_matches", []),
                "title": "Registry Persistence Detected",
                "severity": "medium",
                "description": "Registry-based persistence mechanism detected"
            },
            {
                "condition": lambda e: "high_risk_geo" in e.get("tags", []),
                "title": "High Risk Geographic Connection",
                "severity": "medium",
                "description": "Network connection to high-risk geographic location"
            }
        ]
        
        for i, condition in enumerate(alert_conditions):
            matching_events = [e for e in self.events if condition["condition"](e)]
            
            if matching_events:
                alert = {
                    "id": f"alert_{i+1:03d}",
                    "timestamp": matching_events[0].get("timestamp"),
                    "severity": condition["severity"],
                    "title": condition["title"],
                    "description": condition["description"],
                    "related_events": [e.get("id") for e in matching_events[:5]],  # Limit to 5 events
                    "mitre_tactics": [],
                    "recommended_actions": self._get_recommended_actions(condition["title"])
                }
                
                # Extract MITRE tactics from related events
                for event in matching_events:
                    tactics = event.get("enrichment", {}).get("threat_intel", {}).get("mitre_tactics", [])
                    alert["mitre_tactics"].extend(tactics)
                
                alert["mitre_tactics"] = list(set(alert["mitre_tactics"]))  # Remove duplicates
                self.alerts.append(alert)

    def _get_recommended_actions(self, alert_title: str) -> List[str]:
        """Get recommended actions based on alert type."""
        action_map = {
            "Malware Detection": ["isolate_host", "collect_memory_dump", "scan_with_updated_av"],
            "PowerShell Obfuscation Detected": ["block_powershell", "investigate_parent_process", "check_for_downloads"],
            "Registry Persistence Detected": ["remove_registry_keys", "scan_startup_locations", "investigate_process"],
            "High Risk Geographic Connection": ["block_c2_traffic", "investigate_data_exfiltration", "check_dns_logs"]
        }
        return action_map.get(alert_title, ["investigate_further", "collect_additional_logs"])

    def _enhance_aggregations_with_analysis(self, report: Dict[str, Any]):
        """Enhance aggregations with risk scores and analysis."""
        # This method can be used to add calculated risk scores to aggregations
        # For now, basic implementation
        pass

    def _parse_network_detail(self, detail: str) -> Optional[Dict[str, str]]:
        """Parse network connection details with multiple regex patterns."""
        for pattern in self.network_patterns:
            match = pattern.search(detail)
            if match:
                groups = match.groups()
                if len(groups) == 4:  # IP:Port -> IP:Port
                    return {
                        "local_ip": groups[0],
                        "local_port": groups[1],
                        "remote_ip": groups[2], 
                        "remote_port": groups[3]
                    }
                elif len(groups) == 2:  # Generic source -> destination
                    return {
                        "local_ip": "",
                        "local_port": "",
                        "remote_ip": groups[1],
                        "remote_port": ""
                    }
        return None

    def _is_external_ip(self, ip: str) -> bool:
        """Check if IP is external (not private/local)."""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_multicast)
        except:
            return False

    def _calculate_file_hash(self, file_path: Path) -> Optional[str]:
        """Calculate SHA256 hash with memory efficiency."""
        try:
            hasher = hashlib.sha256()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception as e:
            self.logger.debug(f"Could not hash file {file_path}: {e}")
            return None

    