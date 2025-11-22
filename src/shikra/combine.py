import logging
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime
from collections import defaultdict

from .utils import jsonio
from .utils.logger import setup_logger

class ReportCombiner:
    """
    Combines individual analysis reports (Procmon, Memory, Network) into a
    single, cross-correlated master report.
    """
    def __init__(self, config_dir: Path = Path("config")):
        self.logger = setup_logger("ReportCombiner")
        
        # Handle config directory path resolution
        if config_dir.is_absolute():
            absolute_config_dir = config_dir
        else:
            absolute_config_dir = Path.cwd() / config_dir
            if not absolute_config_dir.exists():
                project_root = Path(__file__).resolve().parent.parent.parent.parent
                absolute_config_dir = project_root / config_dir
        
        try:
            self.risk_config = jsonio.load_config(absolute_config_dir / "risk_scoring.json")
        except FileNotFoundError:
            self.logger.warning("Risk scoring config not found, using defaults")
            self.risk_config = self._get_default_risk_config()

    def combine(
        self,
        procmon_path: Optional[Path] = None,
        memory_path: Optional[Path] = None,
        network_path: Optional[Path] = None,
        disk_path: Optional[Path] = None,
        streaming_path: Optional[Path] = None,
        timeline_path: Optional[Path] = None
    ) -> Dict[str, Any]:
        """
        Loads, merges, and correlates the available analysis reports from all SHIKRA modules.
        At least one report must be provided.
        """
        if not any([procmon_path, memory_path, network_path, disk_path, streaming_path, timeline_path]):
            raise ValueError("At least one report path must be provided")
        
        self.logger.info("Loading individual analysis reports...")
        
        # Load reports that exist
        procmon_report = jsonio.load_json(procmon_path) if procmon_path and procmon_path.exists() else None
        memory_report = jsonio.load_json(memory_path) if memory_path and memory_path.exists() else None
        network_report = jsonio.load_json(network_path) if network_path and network_path.exists() else None
        disk_report = jsonio.load_json(disk_path) if disk_path and disk_path.exists() else None
        streaming_report = jsonio.load_json(streaming_path) if streaming_path and streaming_path.exists() else None
        timeline_report = jsonio.load_json(timeline_path) if timeline_path and timeline_path.exists() else None

        self.logger.info("Combining reports and finding correlations...")
        
        # Enhanced combined report structure with new modules
        combined_report = {
            "metadata": self._get_combined_metadata(procmon_report, memory_report, network_report, disk_report, streaming_report, timeline_report),
            "analysis_results": {
                "procmon": procmon_report,
                "memory": memory_report,
                "network": network_report,
                "disk": disk_report,
                "streaming": streaming_report,
                "timeline": timeline_report
            },
            "correlation_analysis": {
                "cross_module_correlations": {},
                "temporal_correlations": {},
                "artifact_correlations": {},
                "behavioral_correlations": {}
            },
            "threat_assessment": {
                "overall_risk_score": 0,
                "risk_level": "unknown",
                "confidence_score": 0,
                "threat_indicators": [],
                "attack_progression": [],
                "mitre_techniques": []
            },
            "evidence_summary": {
                "iocs": {},
                "timeline": [],
                "file_artifacts": [],
                "network_artifacts": [],
                "process_artifacts": [],
                "registry_artifacts": []
            },
            "reporting": {
                "executive_summary": {},
                "detailed_findings": {},
                "recommendations": [],
                "false_positive_analysis": {}
            }
        }

        # Perform comprehensive correlation analysis
        combined_report["correlation_analysis"]["cross_module_correlations"] = self._find_cross_module_correlations(procmon_report, memory_report, network_report, disk_report, streaming_report)
        combined_report["correlation_analysis"]["temporal_correlations"] = self._find_temporal_correlations(procmon_report, memory_report, network_report, disk_report, streaming_report)
        combined_report["correlation_analysis"]["artifact_correlations"] = self._find_artifact_correlations(procmon_report, memory_report, network_report, disk_report)
        combined_report["correlation_analysis"]["behavioral_correlations"] = self._find_behavioral_correlations(procmon_report, memory_report, network_report, disk_report)
        
        # Build comprehensive evidence summary
        combined_report["evidence_summary"]["iocs"] = self._extract_comprehensive_iocs(procmon_report, memory_report, network_report, disk_report)
        combined_report["evidence_summary"]["timeline"] = self._merge_comprehensive_timeline(procmon_report, memory_report, network_report, disk_report, streaming_report)
        combined_report["evidence_summary"]["file_artifacts"] = self._extract_file_artifacts(procmon_report, memory_report, disk_report)
        combined_report["evidence_summary"]["network_artifacts"] = self._extract_network_artifacts(memory_report, network_report)
        combined_report["evidence_summary"]["process_artifacts"] = self._extract_process_artifacts(procmon_report, memory_report)
        combined_report["evidence_summary"]["registry_artifacts"] = self._extract_registry_artifacts(procmon_report, disk_report)
        
        # Perform comprehensive threat assessment
        combined_report["threat_assessment"]["mitre_techniques"] = self._merge_comprehensive_mitre_techniques(procmon_report, memory_report, network_report, disk_report)
        combined_report["threat_assessment"]["threat_indicators"] = self._extract_threat_indicators(procmon_report, memory_report, network_report, disk_report)
        combined_report["threat_assessment"]["attack_progression"] = self._analyze_attack_progression(combined_report["evidence_summary"]["timeline"], combined_report["threat_assessment"]["mitre_techniques"])
        combined_report["threat_assessment"]["overall_risk_score"] = self._calculate_comprehensive_risk(procmon_report, memory_report, network_report, disk_report, combined_report["correlation_analysis"])
        combined_report["threat_assessment"]["risk_level"] = self._map_score_to_risk_level(combined_report["threat_assessment"]["overall_risk_score"])
        combined_report["threat_assessment"]["confidence_score"] = self._calculate_confidence_score(combined_report["correlation_analysis"], combined_report["evidence_summary"])
        
        # Build reporting section
        combined_report["reporting"]["executive_summary"] = self._build_executive_summary(combined_report)
        combined_report["reporting"]["detailed_findings"] = self._build_detailed_findings(combined_report)
        combined_report["reporting"]["recommendations"] = self._generate_comprehensive_recommendations(combined_report)
        combined_report["reporting"]["false_positive_analysis"] = self._analyze_false_positives(combined_report)
        
        self.logger.info(f"Combination complete. Final risk score: {combined_report['threat_assessment']['overall_risk_score']:.2f} ({combined_report['threat_assessment']['risk_level']})")
        self.logger.info(f"Confidence score: {combined_report['threat_assessment']['confidence_score']:.2f}")
        return combined_report

    def _get_combined_metadata(self, procmon, memory, network, disk=None, streaming=None, timeline=None) -> Dict[str, Any]:
        """Creates comprehensive metadata for the combined report from all available modules."""
        sources = {}
        individual_scores = {}
        analysis_coverage = {}
        module_stats = {}
        
        # Process each module's metadata and extract key information
        if procmon:
            metadata = procmon.get("metadata", {})
            sources["procmon"] = metadata.get("source_file", metadata.get("filename", "N/A"))
            individual_scores["procmon"] = self._extract_procmon_risk_score(procmon)
            analysis_coverage["procmon"] = {
                "events_processed": len(procmon.get("events", [])),
                "alerts_generated": len(procmon.get("alerts", [])),
                "processes_analyzed": len(procmon.get("aggregations", {}).get("processes", []))
            }
            module_stats["procmon"] = procmon.get("statistics", {})
        
        if memory:
            metadata = memory.get("metadata", {})
            sources["memory"] = metadata.get("source_file", metadata.get("filename", "N/A"))
            threat_assessment = memory.get("threat_assessment", {})
            individual_scores["memory"] = threat_assessment.get("overall_risk_score", 0)
            analysis_results = memory.get("analysis_results", {})
            analysis_coverage["memory"] = {
                "processes_found": len(analysis_results.get("processes", [])),
                "network_connections": len(analysis_results.get("network_connections", [])),
                "file_artifacts": len(analysis_results.get("file_artifacts", []))
            }
            module_stats["memory"] = memory.get("statistics", {})
        
        if network:
            metadata = network.get("metadata", {})
            sources["network"] = metadata.get("source_file", metadata.get("filename", "N/A"))
            individual_scores["network"] = self._extract_network_risk_score(network)
            analysis_coverage["network"] = {
                "network_flows": len(network.get("network_flows", [])),
                "dns_queries": len(network.get("dns_analysis", [])),
                "http_requests": len(network.get("http_analysis", [])),
                "iocs_found": len(network.get("iocs", []))
            }
            module_stats["network"] = network.get("statistics", {})
        
        if disk:
            metadata = disk.get("metadata", {})
            sources["disk"] = metadata.get("source_file", "Disk comparison analysis")
            individual_scores["disk"] = self._extract_disk_risk_score(disk)
            analysis_coverage["disk"] = {
                "files_changed": disk.get("statistics", {}).get("total_files_changed", 0),
                "registry_changes": disk.get("statistics", {}).get("registry_changes", 0),
                "suspicious_changes": disk.get("statistics", {}).get("suspicious_changes", 0)
            }
            module_stats["disk"] = disk.get("statistics", {})
        
        if streaming:
            metadata = streaming.get("metadata", {})
            sources["streaming"] = metadata.get("source", "Real-time streaming data")
            individual_scores["streaming"] = self._extract_streaming_risk_score(streaming)
            analysis_coverage["streaming"] = {
                "events_received": streaming.get("statistics", {}).get("total_events", 0),
                "realtime_alerts": len(streaming.get("alerts", [])),
                "active_connections": streaming.get("statistics", {}).get("active_connections", 0)
            }
            module_stats["streaming"] = streaming.get("statistics", {})
        
        if timeline:
            metadata = timeline.get("metadata", {})
            sources["timeline"] = metadata.get("source", "Timeline correlation analysis")
            individual_scores["timeline"] = self._extract_timeline_risk_score(timeline)
            analysis_coverage["timeline"] = {
                "events_correlated": len(timeline.get("events", [])),
                "correlations_found": len(timeline.get("correlations", [])),
                "high_confidence_correlations": len([c for c in timeline.get("correlations", []) if c.get("confidence", "").lower() in ["high", "very_high"]])
            }
            module_stats["timeline"] = timeline.get("statistics", {})
        
        return {
            "analysis_timestamp": datetime.now().isoformat(),
            "shikra_version": "2.0.0",
            "analysis_id": f"shikra_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            "sources": sources,
            "individual_risk_scores": individual_scores,
            "available_modules": list(sources.keys()),
            "analysis_coverage": analysis_coverage,
            "module_statistics": module_stats,
            "correlation_engine_version": "2.0",
            "total_modules_analyzed": len(sources)
        }

    def _extract_procmon_risk_score(self, procmon_report: Dict[str, Any]) -> float:
        """Extract risk score from new procmon report format."""
        # Check if there's a risk score in aggregations
        aggregations = procmon_report.get("aggregations", {})
        if "risk_assessment" in aggregations:
            return aggregations["risk_assessment"].get("overall_risk_score", 0)
        
        # Calculate based on alert severity
        alerts = procmon_report.get("alerts", [])
        if not alerts:
            return 0
        
        # Simple scoring based on alert count and severity
        high_alerts = len([a for a in alerts if a.get("severity") == "high"])
        medium_alerts = len([a for a in alerts if a.get("severity") == "medium"])
        low_alerts = len([a for a in alerts if a.get("severity") == "low"])
        
        score = (high_alerts * 3) + (medium_alerts * 2) + (low_alerts * 1)
        return min(score, 10.0)

    def _extract_network_risk_score(self, network_report: Dict[str, Any]) -> float:
        """Extract risk score from new network report format."""
        # Check threat hunting results
        threat_hunting = network_report.get("threat_hunting", {})
        if "risk_score" in threat_hunting:
            return threat_hunting["risk_score"]
        
        # Calculate based on IOCs and threats
        iocs = network_report.get("iocs", [])
        protocol_anomalies = network_report.get("protocol_anomalies", [])
        
        if not iocs and not protocol_anomalies:
            return 0
        
        # Simple scoring based on IOC count and severity
        high_severity_iocs = len([ioc for ioc in iocs if ioc.get("severity") in ["high", "critical"]])
        medium_severity_iocs = len([ioc for ioc in iocs if ioc.get("severity") == "medium"])
        anomaly_count = len(protocol_anomalies)
        
        score = (high_severity_iocs * 2) + medium_severity_iocs + (anomaly_count * 0.5)
        return min(score, 10.0)

    def _extract_disk_risk_score(self, disk_report: Dict[str, Any]) -> float:
        """Extract risk score from disk analysis report."""
        risk_assessment = disk_report.get("risk_assessment", {})
        if "overall_risk_score" in risk_assessment:
            return risk_assessment["overall_risk_score"]
        
        # Calculate based on suspicious changes
        statistics = disk_report.get("statistics", {})
        encrypted_files = statistics.get("encrypted_files_detected", 0)
        ransom_notes = statistics.get("ransom_notes_found", 0)
        suspicious_changes = statistics.get("suspicious_changes", 0)
        
        # Weight different types of changes
        score = (encrypted_files * 3) + (ransom_notes * 4) + (suspicious_changes * 0.5)
        return min(score, 10.0)

    def _extract_streaming_risk_score(self, streaming_report: Dict[str, Any]) -> float:
        """Extract risk score from streaming analysis report."""
        # Check for real-time threat indicators
        alerts = streaming_report.get("alerts", [])
        if not alerts:
            return 0
        
        # Simple scoring based on alert severity and frequency
        high_alerts = len([a for a in alerts if a.get("severity") == "high"])
        medium_alerts = len([a for a in alerts if a.get("severity") == "medium"])
        
        score = (high_alerts * 2.5) + (medium_alerts * 1.5)
        return min(score, 10.0)

    def _extract_timeline_risk_score(self, timeline_report: Dict[str, Any]) -> float:
        """Extract risk score from timeline correlation analysis."""
        correlations = timeline_report.get("correlations", [])
        if not correlations:
            return 0
        
        # Score based on correlation confidence and attack techniques
        high_conf_correlations = len([c for c in correlations if c.get("confidence", "").lower() in ["high", "very_high"]])
        attack_techniques = len(set([c.get("attack_technique") for c in correlations if c.get("attack_technique")]))
        
        score = (high_conf_correlations * 1.5) + (attack_techniques * 0.8)
        return min(score, 10.0)

    def _find_cross_module_correlations(self, procmon, memory, network, disk=None, streaming=None) -> List[Dict[str, Any]]:
        """Find correlations across different SHIKRA modules."""
        correlations = []
        
        # Legacy correlations (enhanced)
        correlations.extend(self._correlate_by_pid(procmon, memory, network))
        correlations.extend(self._correlate_by_file_hash(procmon, memory, network, disk))
        correlations.extend(self._correlate_by_network_destinations(procmon, memory, network))
        correlations.extend(self._correlate_by_mitre_techniques(procmon, memory, network, disk))
        
        # New cross-module correlations
        correlations.extend(self._correlate_disk_with_procmon(disk, procmon))
        correlations.extend(self._correlate_streaming_with_modules(streaming, procmon, memory, network))
        correlations.extend(self._correlate_file_operations(procmon, disk, memory))
        correlations.extend(self._correlate_registry_changes(procmon, disk))
        
        return correlations

    def _find_temporal_correlations(self, procmon, memory, network, disk=None, streaming=None) -> Dict[str, Any]:
        """Find temporal patterns and correlations across modules."""
        temporal_analysis = {
            "attack_phases": [],
            "time_clustering": {},
            "sequence_analysis": {},
            "concurrent_activities": []
        }
        
        # Extract timestamps from all modules
        all_events = []
        
        if procmon:
            events = procmon.get("events", [])
            for event in events:
                if event.get("timestamp"):
                    all_events.append({
                        "timestamp": event["timestamp"],
                        "source": "procmon",
                        "event_type": event.get("operation", "unknown"),
                        "details": event
                    })
        
        if memory:
            processes = memory.get("analysis_results", {}).get("processes", [])
            for proc in processes:
                if proc.get("create_time"):
                    all_events.append({
                        "timestamp": proc["create_time"],
                        "source": "memory",
                        "event_type": "process_creation",
                        "details": proc
                    })
        
        if network:
            flows = network.get("network_flows", [])
            for flow in flows:
                if flow.get("timestamp"):
                    all_events.append({
                        "timestamp": flow["timestamp"],
                        "source": "network",
                        "event_type": "network_flow",
                        "details": flow
                    })
        
        if disk:
            changes = disk.get("file_changes", {}).get("files_added", [])
            for change in changes:
                if change.get("timestamp"):
                    all_events.append({
                        "timestamp": change["timestamp"],
                        "source": "disk",
                        "event_type": "file_added",
                        "details": change
                    })
        
        # Analyze temporal patterns
        if all_events:
            temporal_analysis["attack_phases"] = self._identify_attack_phases_temporal(all_events)
            temporal_analysis["time_clustering"] = self._cluster_events_by_time(all_events)
            temporal_analysis["sequence_analysis"] = self._analyze_event_sequences(all_events)
            temporal_analysis["concurrent_activities"] = self._find_concurrent_activities(all_events)
        
        return temporal_analysis

    def _find_artifact_correlations(self, procmon, memory, network, disk=None) -> Dict[str, Any]:
        """Find correlations based on shared artifacts (files, hashes, IPs, etc.)."""
        artifact_correlations = {
            "file_correlations": [],
            "hash_correlations": [],
            "ip_correlations": [],
            "domain_correlations": [],
            "process_correlations": []
        }
        
        # Collect artifacts from all modules
        artifacts = {
            "files": set(),
            "hashes": set(),
            "ips": set(),
            "domains": set(),
            "processes": set()
        }
        
        # Extract artifacts from each module
        if procmon:
            events = procmon.get("events", [])
            for event in events:
                if event.get("path"):
                    artifacts["files"].add(event["path"])
                if event.get("file_hash"):
                    artifacts["hashes"].add(event["file_hash"])
                if event.get("process_name"):
                    artifacts["processes"].add(event["process_name"])
        
        if memory:
            processes = memory.get("analysis_results", {}).get("processes", [])
            for proc in processes:
                if proc.get("imagefilename"):
                    artifacts["files"].add(proc["imagefilename"])
                if proc.get("hash_sha256"):
                    artifacts["hashes"].add(proc["hash_sha256"])
                if proc.get("name"):
                    artifacts["processes"].add(proc["name"])
            
            connections = memory.get("analysis_results", {}).get("network_connections", [])
            for conn in connections:
                if conn.get("remote_ip"):
                    artifacts["ips"].add(conn["remote_ip"])
        
        if network:
            flows = network.get("network_flows", [])
            for flow in flows:
                if flow.get("dest_ip"):
                    artifacts["ips"].add(flow["dest_ip"])
            
            dns_analysis = network.get("dns_analysis", [])
            for dns in dns_analysis:
                if dns.get("query"):
                    artifacts["domains"].add(dns["query"])
        
        if disk:
            file_changes = disk.get("file_changes", {})
            for change_type in ["files_added", "files_modified", "files_removed"]:
                for file_change in file_changes.get(change_type, []):
                    if file_change.get("path"):
                        artifacts["files"].add(file_change["path"])
                    if file_change.get("hash_sha256"):
                        artifacts["hashes"].add(file_change["hash_sha256"])
        
        # Find correlations based on shared artifacts
        artifact_correlations["file_correlations"] = self._correlate_shared_artifacts(artifacts["files"], "file")
        artifact_correlations["hash_correlations"] = self._correlate_shared_artifacts(artifacts["hashes"], "hash")
        artifact_correlations["ip_correlations"] = self._correlate_shared_artifacts(artifacts["ips"], "ip")
        artifact_correlations["domain_correlations"] = self._correlate_shared_artifacts(artifacts["domains"], "domain")
        artifact_correlations["process_correlations"] = self._correlate_shared_artifacts(artifacts["processes"], "process")
        
        return artifact_correlations

    def _find_behavioral_correlations(self, procmon, memory, network, disk=None) -> Dict[str, Any]:
        """Find behavioral patterns and correlations across modules."""
        behavioral_analysis = {
            "ransomware_behaviors": [],
            "persistence_mechanisms": [],
            "data_exfiltration": [],
            "lateral_movement": [],
            "defense_evasion": []
        }
        
        # Identify ransomware behaviors
        behavioral_analysis["ransomware_behaviors"] = self._identify_ransomware_behaviors(procmon, memory, network, disk)
        behavioral_analysis["persistence_mechanisms"] = self._identify_persistence_mechanisms(procmon, memory, disk)
        behavioral_analysis["data_exfiltration"] = self._identify_data_exfiltration(network, memory, procmon)
        behavioral_analysis["lateral_movement"] = self._identify_lateral_movement(network, memory, procmon)
        behavioral_analysis["defense_evasion"] = self._identify_defense_evasion(procmon, memory, disk)
        
        return behavioral_analysis
        """Finds correlations between artifacts across the different reports."""
        correlations = []
        
        # Process ID correlations
        correlations.extend(self._correlate_by_pid(procmon, memory, network))
        
        # File hash correlations
        correlations.extend(self._correlate_by_file_hash(procmon, memory, network))
        
        # Network destination correlations
        correlations.extend(self._correlate_by_network_destinations(procmon, memory, network))
        
        # MITRE technique correlations
        correlations.extend(self._correlate_by_mitre_techniques(procmon, memory, network))
        
        return correlations

    def _correlate_by_pid(self, procmon, memory, network) -> List[Dict[str, Any]]:
        """Correlate processes by PID across reports."""
        correlations = []
        
        if not procmon:
            return correlations
        
        # Build PID mappings for new formats
        mem_procs_by_pid = {}
        if memory:
            # New memory format: check analysis_results for processes
            analysis_results = memory.get("analysis_results", {})
            processes = analysis_results.get("processes", [])
            for p in processes:
                if p.get('pid'):
                    mem_procs_by_pid[str(p['pid'])] = p
        
        net_conns_by_pid = defaultdict(list)
        if network:
            # New network format: check network_flows for PID data
            network_flows = network.get("network_flows", [])
            for flow in network_flows:
                if flow.get('pid'):
                    net_conns_by_pid[str(flow['pid'])].append(flow)
        
        # Extract processes from new procmon format
        procmon_processes = []
        if "process_tree" in procmon:
            # Extract from process tree
            tree = procmon.get("process_tree", {})
            for root_proc in tree.get("root_processes", []):
                procmon_processes.extend(self._flatten_process_tree(root_proc))
            procmon_processes.extend(tree.get("orphaned_processes", []))
        elif "events" in procmon:
            # Extract process creation events
            events = procmon.get("events", [])
            process_events = [e for e in events if e.get("operation") == "Process Create"]
            for event in process_events:
                procmon_processes.append({
                    "pid": event.get("process_id"),
                    "name": event.get("process_name"),
                    "path": event.get("path")
                })

        # Find correlations
        for proc in procmon_processes:
            pid = str(proc.get("pid", ""))
            if not pid:
                continue

            correlation_found = False
            correlation = {
                "type": "Process Correlation",
                "pid": pid,
                "name": proc.get("name", "unknown"),
                "path": proc.get("path", ""),
                "has_memory_artifacts": False,
                "has_network_artifacts": False,
                "details": []
            }

            if pid in mem_procs_by_pid:
                correlation["has_memory_artifacts"] = True
                mem_proc = mem_procs_by_pid[pid]
                correlation["details"].append(f"Process found in memory dump: {mem_proc.get('name', mem_proc.get('imagefilename', 'unknown'))}")
                correlation_found = True

            if pid in net_conns_by_pid:
                correlation["has_network_artifacts"] = True
                correlation["details"].append(f"Process made {len(net_conns_by_pid[pid])} network connections")
                correlation_found = True

            if correlation_found:
                correlation["description"] = f"Process {proc.get('name')} (PID {pid}) observed across multiple data sources"
                correlations.append(correlation)
        
        return correlations
    
    def _flatten_process_tree(self, process_node: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Recursively flatten a process tree node into a list of processes."""
        processes = [process_node]
        for child in process_node.get("children", []):
            processes.extend(self._flatten_process_tree(child))
        return processes

    def _correlate_by_file_hash(self, procmon, memory, network) -> List[Dict[str, Any]]:
        """Correlate files by hash across reports."""
        correlations = []
        
        if not procmon:
            return correlations
        
        # Build hash mappings for new memory format
        memory_hashes = set()
        if memory:
            analysis_results = memory.get("analysis_results", {})
            processes = analysis_results.get("processes", [])
            for proc in processes:
                if proc.get("hash_sha256"):
                    memory_hashes.add(proc["hash_sha256"])
                # Also check for file artifacts
                if proc.get("file_hash"):
                    memory_hashes.add(proc["file_hash"])
        
        # Extract file information from new procmon format
        procmon_files = []
        if "events" in procmon:
            events = procmon.get("events", [])
            file_events = [e for e in events if e.get("operation") in ["CreateFile", "WriteFile", "ReadFile"]]
            for event in file_events:
                if event.get("file_hash") or event.get("hash_sha256"):
                    procmon_files.append({
                        "path": event.get("path"),
                        "hash_sha256": event.get("file_hash") or event.get("hash_sha256")
                    })
        elif "aggregations" in procmon:
            # Check aggregations for file operations
            aggregations = procmon.get("aggregations", {})
            files = aggregations.get("files", [])
            for file_info in files:
                if file_info.get("hash_sha256"):
                    procmon_files.append(file_info)
        
        # Find correlations
        for file_info in procmon_files:
            file_hash = file_info.get("hash_sha256")
            if file_hash and file_hash in memory_hashes:
                correlations.append({
                    "type": "File Hash Correlation",
                    "hash": file_hash,
                    "path": file_info.get("path", ""),
                    "description": f"File {file_info.get('path', 'unknown')} found in both Procmon events and memory",
                    "details": ["File was accessed in Procmon and loaded in memory"]
                })
        
        return correlations

    def _correlate_by_network_destinations(self, procmon, memory, network) -> List[Dict[str, Any]]:
        """Correlate network destinations across reports."""
        correlations = []
        
        if not network:
            return correlations
        
        # Extract network IOCs from new network report format
        network_ips = set()
        network_domains = set()
        
        # Check IOCs section
        iocs = network.get("iocs", [])
        for ioc in iocs:
            if ioc.get("type") == "ip_address":
                network_ips.add(ioc.get("value"))
            elif ioc.get("type") in ["domain", "hostname"]:
                network_domains.add(ioc.get("value"))
        
        # Check DNS analysis
        dns_analysis = network.get("dns_analysis", [])
        for dns_event in dns_analysis:
            if dns_event.get("suspicious") or dns_event.get("threat_score", 0) > 5:
                if dns_event.get("query"):
                    network_domains.add(dns_event["query"])
        
        # Check HTTP analysis
        http_analysis = network.get("http_analysis", [])
        for http_event in http_analysis:
            if http_event.get("suspicious") or http_event.get("threat_score", 0) > 5:
                if http_event.get("host"):
                    network_domains.add(http_event["host"])
        
        # Check threat hunting results
        threat_hunting = network.get("threat_hunting", {})
        for threat_type, threats in threat_hunting.items():
            if isinstance(threats, list):
                for threat in threats:
                    if threat.get("ip_address"):
                        network_ips.add(threat["ip_address"])
                    if threat.get("domain"):
                        network_domains.add(threat["domain"])
        
        # Check for mentions in other reports (enhanced)
        if (network_ips or network_domains):
            correlation = {
                "type": "Network IOC Correlation",
                "description": "Suspicious network activity detected",
                "network_indicators": {
                    "suspicious_ips": list(network_ips),
                    "suspicious_domains": list(network_domains)
                },
                "details": [f"Network analysis identified {len(network_ips)} suspicious IPs and {len(network_domains)} suspicious domains"]
            }
            
            # Check if any of these indicators appear in procmon or memory
            cross_references = []
            
            if procmon:
                # Check procmon events for network indicators
                events = procmon.get("events", [])
                for event in events:
                    event_details = event.get("details", "").lower()
                    for ip in network_ips:
                        if ip in event_details:
                            cross_references.append(f"IP {ip} referenced in Procmon event")
                    for domain in network_domains:
                        if domain.lower() in event_details:
                            cross_references.append(f"Domain {domain} referenced in Procmon event")
            
            if memory:
                # Check memory analysis for network indicators  
                analysis_results = memory.get("analysis_results", {})
                network_connections = analysis_results.get("network_connections", [])
                for conn in network_connections:
                    if conn.get("remote_ip") in network_ips:
                        cross_references.append(f"IP {conn['remote_ip']} found in memory network connections")
            
            if cross_references:
                correlation["details"].extend(cross_references)
                correlation["cross_reference_count"] = len(cross_references)
            
            correlations.append(correlation)
        
        return correlations

    def _correlate_by_mitre_techniques(self, procmon, memory, network) -> List[Dict[str, Any]]:
        """Correlate MITRE ATT&CK techniques across reports."""
        correlations = []
        
        # Collect techniques from all reports using new formats
        all_techniques = defaultdict(list)
        
        if procmon:
            # Check aggregations for MITRE techniques
            aggregations = procmon.get("aggregations", {})
            techniques = aggregations.get("mitre_techniques", [])
            for technique in techniques:
                technique_id = technique.get("technique_id")
                if technique_id:
                    all_techniques[technique_id].append(("procmon", technique))
            
            # Also check alerts for MITRE mappings
            alerts = procmon.get("alerts", [])
            for alert in alerts:
                mitre_techniques = alert.get("mitre_techniques", [])
                for technique_id in mitre_techniques:
                    if technique_id not in [t[1].get("technique_id") for t in all_techniques[technique_id]]:
                        all_techniques[technique_id].append(("procmon", {"technique_id": technique_id, "source": "alert"}))
        
        if memory:
            # Check threat assessment for MITRE techniques
            threat_assessment = memory.get("threat_assessment", {})
            techniques = threat_assessment.get("mitre_techniques", [])
            for technique in techniques:
                technique_id = technique.get("technique_id")
                if technique_id:
                    all_techniques[technique_id].append(("memory", technique))
            
            # Check analysis results for additional techniques
            analysis_results = memory.get("analysis_results", {})
            if "mitre_techniques" in analysis_results:
                for technique in analysis_results["mitre_techniques"]:
                    technique_id = technique.get("technique_id")
                    if technique_id:
                        all_techniques[technique_id].append(("memory", technique))
        
        if network:
            # Check threat hunting for MITRE techniques
            threat_hunting = network.get("threat_hunting", {})
            if "mitre_techniques" in threat_hunting:
                techniques = threat_hunting["mitre_techniques"]
                for technique in techniques:
                    technique_id = technique.get("technique_id")
                    if technique_id:
                        all_techniques[technique_id].append(("network", technique))
            
            # Check IOCs for MITRE mappings
            iocs = network.get("iocs", [])
            for ioc in iocs:
                mitre_techniques = ioc.get("mitre_techniques", [])
                for technique_id in mitre_techniques:
                    if technique_id not in [t[1].get("technique_id") for t in all_techniques[technique_id]]:
                        all_techniques[technique_id].append(("network", {"technique_id": technique_id, "source": "ioc"}))
        
        # Find techniques observed in multiple sources
        for technique_id, sources in all_techniques.items():
            if len(sources) > 1:
                unique_sources = list(set([source[0] for source in sources]))
                if len(unique_sources) > 1:  # Only correlate across different analyzers
                    correlations.append({
                        "type": "MITRE Technique Correlation",
                        "technique_id": technique_id,
                        "technique_name": sources[0][1].get("technique_name", ""),
                        "sources": unique_sources,
                        "description": f"MITRE technique {technique_id} observed in {len(unique_sources)} different data sources",
                        "details": [f"Technique seen in: {', '.join(unique_sources)}"],
                        "evidence_count": len(sources)
                    })
        
        return correlations

    def _calculate_combined_risk(self, procmon, memory, network, correlations) -> float:
        """Calculates a final, weighted risk score using the config."""
        global_weights = self.risk_config.get("global_weights", {
            "procmon": 0.4,
            "memory": 0.4,
            "network": 0.2
        })
        
        weighted_sum = 0.0
        total_weight = 0.0
        
        if procmon:
            score = self._extract_procmon_risk_score(procmon)
            weight = global_weights.get("procmon", 0.4)
            weighted_sum += score * weight
            total_weight += weight
        
        if memory:
            threat_assessment = memory.get("threat_assessment", {})
            score = threat_assessment.get("overall_risk_score", 0)
            weight = global_weights.get("memory", 0.4)
            weighted_sum += score * weight
            total_weight += weight
        
        if network:
            score = self._extract_network_risk_score(network)
            weight = global_weights.get("network", 0.2)
            weighted_sum += score * weight
            total_weight += weight
        
        # Normalize by actual weights used
        if total_weight > 0:
            base_score = weighted_sum / total_weight
        else:
            base_score = 0
        
        # Apply correlation amplifiers
        base_score = self._apply_correlation_amplifiers(correlations, base_score)
        
        max_score = self.risk_config.get("final_risk_mapping", {}).get("max_score", 10.0)
        return min(base_score, max_score)

    def _apply_correlation_amplifiers(self, correlations, base_score) -> float:
        """Apply correlation-based score amplifiers."""
        amplifiers = self.risk_config.get("correlation_engine", {}).get("amplifiers", [])
        
        for amplifier in amplifiers:
            conditions = amplifier.get("conditions", [])
            multiplier = amplifier.get("multiplier", 1.0)
            
            # Check if correlation conditions are met
            conditions_met = self._check_correlation_conditions(correlations, conditions)
            
            if conditions_met:
                self.logger.info(f"Applying correlation amplifier: {amplifier.get('description')} (x{multiplier})")
                base_score *= multiplier
        
        return base_score

    def _check_correlation_conditions(self, correlations, conditions) -> bool:
        """Check if correlation conditions are met."""
        # This is a simplified implementation - could be enhanced
        for condition in conditions:
            source = condition.get("source")
            indicator = condition.get("indicator")
            
            # Check if we have correlations involving this source and indicator type
            found = False
            for corr in correlations:
                if source in corr.get("sources", []) or source in corr.get("type", "").lower():
                    found = True
                    break
            
            if not found:
                return False
        
        return True

    def _merge_timelines(self, procmon, memory, network) -> List[Dict[str, Any]]:
        """Merges events from all reports into a single, sorted timeline."""
        timeline = []
        
        # Procmon timeline - extract from new format
        if procmon:
            events = procmon.get("events", [])
            for event in events:
                timeline.append({
                    "timestamp": event.get("timestamp"),
                    "source": "Procmon",
                    "event": f"{event.get('operation', 'Unknown')}: {event.get('path', event.get('details', ''))}",
                    "priority": event.get("priority", "normal"),
                    "details": event.get("details", ""),
                    "process_name": event.get("process_name", ""),
                    "pid": event.get("process_id", "")
                })
        
        # Memory timeline - extract from new format
        if memory:
            analysis_results = memory.get("analysis_results", {})
            processes = analysis_results.get("processes", [])
            for proc in processes:
                if proc.get('create_time'):
                    timeline.append({
                        "timestamp": proc['create_time'],
                        "source": "Memory",
                        "event": f"Process: {proc.get('name', proc.get('imagefilename', 'unknown'))} (PID: {proc.get('pid', 'unknown')})",
                        "priority": "high",
                        "details": f"Command: {proc.get('cmdline', proc.get('command_line', 'N/A'))}",
                        "process_name": proc.get('name', proc.get('imagefilename', '')),
                        "pid": proc.get('pid', '')
                    })
            
            # Add significant memory events
            if "significant_events" in analysis_results:
                for event in analysis_results["significant_events"]:
                    if event.get("timestamp"):
                        timeline.append({
                            "timestamp": event["timestamp"],
                            "source": "Memory",
                            "event": f"Memory Event: {event.get('description', 'Unknown event')}",
                            "priority": "high" if event.get("severity") in ["high", "critical"] else "medium",
                            "details": event.get("details", "")
                        })
        
        # Network timeline - extract from new format
        if network:
            # Add DNS events
            dns_analysis = network.get("dns_analysis", [])
            for dns_event in dns_analysis:
                if dns_event.get("timestamp"):
                    timeline.append({
                        "timestamp": dns_event["timestamp"],
                        "source": "Network",
                        "event": f"DNS Query: {dns_event.get('query', 'unknown')}",
                        "priority": "high" if dns_event.get("suspicious") else "medium",
                        "details": f"Response: {dns_event.get('response', 'N/A')}"
                    })
            
            # Add HTTP events
            http_analysis = network.get("http_analysis", [])
            for http_event in http_analysis:
                if http_event.get("timestamp"):
                    timeline.append({
                        "timestamp": http_event["timestamp"],
                        "source": "Network",
                        "event": f"HTTP {http_event.get('method', 'Request')}: {http_event.get('host', 'unknown')}{http_event.get('uri', '')}",
                        "priority": "high" if http_event.get("suspicious") else "medium",
                        "details": f"Status: {http_event.get('status_code', 'N/A')}, User-Agent: {http_event.get('user_agent', 'N/A')}"
                    })
            
            # Add IOCs
            iocs = network.get("iocs", [])
            for ioc in iocs:
                if ioc.get("timestamp"):
                    timeline.append({
                        "timestamp": ioc["timestamp"],
                        "source": "Network",
                        "event": f"Suspicious {ioc.get('type', 'activity')}: {ioc.get('value', 'unknown')}",
                        "priority": "high" if ioc.get("severity") in ["high", "critical"] else "medium",
                        "details": f"Severity: {ioc.get('severity', 'unknown')}, Confidence: {ioc.get('confidence', 'unknown')}"
                    })
        
        # Sort by timestamp and limit size
        timeline = [event for event in timeline if event.get("timestamp")]
        try:
            timeline.sort(key=lambda x: x["timestamp"])
        except (ValueError, TypeError):
            # Handle different timestamp formats
            self.logger.warning("Unable to sort timeline due to timestamp format issues")
        
        # Limit timeline size for performance
        max_timeline_events = 1000
        if len(timeline) > max_timeline_events:
            # Keep high priority events and sample others
            high_priority = [e for e in timeline if e.get("priority") == "high"]
            other_events = [e for e in timeline if e.get("priority") != "high"]
            
            sample_size = max_timeline_events - len(high_priority)
            if sample_size > 0 and other_events:
                step = max(1, len(other_events) // sample_size)
                sampled_others = other_events[::step][:sample_size]
                timeline = high_priority + sampled_others
                try:
                    timeline.sort(key=lambda x: x["timestamp"])
                except (ValueError, TypeError):
                    pass
        
        return timeline[:max_timeline_events]

    def _merge_mitre_techniques(self, procmon, memory, network) -> List[Dict[str, Any]]:
        """Merge and deduplicate MITRE techniques from all reports."""
        techniques_map = {}
        
        # Collect from all reports using new formats
        for report, source in [(procmon, "procmon"), (memory, "memory"), (network, "network")]:
            if not report:
                continue
            
            techniques = []
            
            # Extract techniques based on report structure
            if source == "procmon":
                # Check aggregations and alerts
                aggregations = report.get("aggregations", {})
                if "mitre_techniques" in aggregations:
                    techniques.extend(aggregations["mitre_techniques"])
                
                alerts = report.get("alerts", [])
                for alert in alerts:
                    for technique_id in alert.get("mitre_techniques", []):
                        techniques.append({"technique_id": technique_id, "source": "alert"})
            
            elif source == "memory":
                # Check threat assessment and analysis results
                threat_assessment = report.get("threat_assessment", {})
                if "mitre_techniques" in threat_assessment:
                    techniques.extend(threat_assessment["mitre_techniques"])
                
                analysis_results = report.get("analysis_results", {})
                if "mitre_techniques" in analysis_results:
                    techniques.extend(analysis_results["mitre_techniques"])
            
            elif source == "network":
                # Check threat hunting and IOCs
                threat_hunting = report.get("threat_hunting", {})
                if "mitre_techniques" in threat_hunting:
                    techniques.extend(threat_hunting["mitre_techniques"])
                
                iocs = report.get("iocs", [])
                for ioc in iocs:
                    for technique_id in ioc.get("mitre_techniques", []):
                        techniques.append({"technique_id": technique_id, "source": "ioc"})
            
            # Process techniques
            for technique in techniques:
                technique_id = technique.get("technique_id")
                if technique_id:
                    if technique_id not in techniques_map:
                        techniques_map[technique_id] = {
                            "technique_id": technique_id,
                            "technique_name": technique.get("technique_name", ""),
                            "description": technique.get("description", ""),
                            "tactic": technique.get("tactic", ""),
                            "sources": [],
                            "confidence": technique.get("confidence", "medium")
                        }
                    
                    if source not in techniques_map[technique_id]["sources"]:
                        techniques_map[technique_id]["sources"].append(source)
                    
                    # Update confidence if higher
                    current_confidence = techniques_map[technique_id]["confidence"]
                    new_confidence = technique.get("confidence", "medium")
                    if self._confidence_score(new_confidence) > self._confidence_score(current_confidence):
                        techniques_map[technique_id]["confidence"] = new_confidence
        
        return list(techniques_map.values())
    
    def _confidence_score(self, confidence: str) -> int:
        """Convert confidence level to numeric score for comparison."""
        confidence_map = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        return confidence_map.get(confidence.lower(), 2)

    def _merge_tags(self, procmon, memory, network) -> List[str]:
        """Merge and deduplicate tags from all reports."""
        all_tags = set()
        
        # Extract tags from new report formats
        for report in [procmon, memory, network]:
            if not report:
                continue
            
            # Check multiple possible locations for tags
            tags = []
            
            # Common locations across all analyzers
            if "tags" in report:
                tags.extend(report["tags"])
            
            # Procmon specific
            if "aggregations" in report:
                aggregations = report["aggregations"]
                if "tags" in aggregations:
                    tags.extend(aggregations["tags"])
                    
                # Extract tags from alerts
                alerts = report.get("alerts", [])
                for alert in alerts:
                    if "tags" in alert:
                        tags.extend(alert["tags"])
                    # Add severity as a tag
                    if alert.get("severity"):
                        tags.append(f"alert_{alert['severity']}")
            
            # Memory specific
            if "threat_assessment" in report:
                threat_assessment = report["threat_assessment"]
                if "tags" in threat_assessment:
                    tags.extend(threat_assessment["tags"])
                
                # Add threat indicators as tags
                if threat_assessment.get("threat_indicators"):
                    for indicator in threat_assessment["threat_indicators"]:
                        if indicator.get("type"):
                            tags.append(f"threat_{indicator['type']}")
            
            if "analysis_results" in report:
                analysis_results = report["analysis_results"]
                if "tags" in analysis_results:
                    tags.extend(analysis_results["tags"])
            
            # Network specific
            if "threat_hunting" in report:
                threat_hunting = report["threat_hunting"]
                if "tags" in threat_hunting:
                    tags.extend(threat_hunting["tags"])
            
            if "iocs" in report:
                iocs = report["iocs"]
                for ioc in iocs:
                    if "tags" in ioc:
                        tags.extend(ioc["tags"])
                    # Add IOC type as tag
                    if ioc.get("type"):
                        tags.append(f"ioc_{ioc['type']}")
            
            # Add analyzer-specific tags
            if "metadata" in report:
                metadata = report["metadata"]
                analyzer_version = metadata.get("analyzer_version", "")
                if "network" in analyzer_version:
                    tags.append("network_analysis")
                elif "memory" in analyzer_version:
                    tags.append("memory_analysis")
                elif "procmon" in analyzer_version:
                    tags.append("procmon_analysis")
            
            all_tags.update(tags)
        
        return sorted(list(all_tags))

    def _map_score_to_risk_level(self, score: float) -> str:
        """Map numerical score to risk level using config thresholds."""
        thresholds = self.risk_config.get("final_risk_mapping", {}).get("thresholds", [])
        
        if not thresholds:
            # Default thresholds
            if score >= 9: return "Critical"
            elif score >= 7: return "High"
            elif score >= 5: return "Medium"
            elif score >= 3: return "Low"
            else: return "Informational"
        
        # Use config thresholds
        sorted_thresholds = sorted(thresholds, key=lambda x: x.get("score", 0), reverse=True)
        
        for threshold in sorted_thresholds:
            if score >= threshold.get("score", 0):
                return threshold.get("level", "Unknown")
        
        return thresholds[-1].get("level", "Informational") if thresholds else "Informational"

    def _extract_iocs(self, procmon, memory, network) -> Dict[str, List[str]]:
        """Extracts and deduplicates all Indicators of Compromise."""
        iocs = {
            "ips": set(),
            "domains": set(),
            "urls": set(),
            "hashes_sha256": set(),
            "hashes_md5": set(),
            "paths": set(),
            "registry_keys": set(),
            "mutexes": set(),
            "file_names": set(),
            "process_names": set()
        }
        
        # Procmon IOCs - extract from new format
        if procmon:
            # Extract from events
            events = procmon.get("events", [])
            for event in events:
                if event.get("file_hash") or event.get("hash_sha256"):
                    iocs["hashes_sha256"].add(event.get("file_hash") or event.get("hash_sha256"))
                if event.get("hash_md5"):
                    iocs["hashes_md5"].add(event["hash_md5"])
                if event.get("path"):
                    iocs["paths"].add(event["path"])
                if event.get("operation") == "RegSetValue" and event.get("path"):
                    iocs["registry_keys"].add(event["path"])
                if event.get("process_name"):
                    iocs["process_names"].add(event["process_name"])
            
            # Extract from aggregations
            aggregations = procmon.get("aggregations", {})
            if "files" in aggregations:
                for file_info in aggregations["files"]:
                    if file_info.get("hash_sha256"):
                        iocs["hashes_sha256"].add(file_info["hash_sha256"])
                    if file_info.get("hash_md5"):
                        iocs["hashes_md5"].add(file_info["hash_md5"])
                    if file_info.get("path"):
                        iocs["paths"].add(file_info["path"])
                        # Extract filename
                        filename = Path(file_info["path"]).name
                        if filename:
                            iocs["file_names"].add(filename)
            
            if "registry" in aggregations:
                for reg_key in aggregations["registry"]:
                    if reg_key.get("path"):
                        iocs["registry_keys"].add(reg_key["path"])
            
            if "processes" in aggregations:
                for proc in aggregations["processes"]:
                    if proc.get("name"):
                        iocs["process_names"].add(proc["name"])
        
        # Memory IOCs - extract from new format
        if memory:
            analysis_results = memory.get("analysis_results", {})
            
            # Extract from processes
            processes = analysis_results.get("processes", [])
            for proc in processes:
                if proc.get("hash_sha256"):
                    iocs["hashes_sha256"].add(proc["hash_sha256"])
                if proc.get("hash_md5"):
                    iocs["hashes_md5"].add(proc["hash_md5"])
                if proc.get("imagefilename") or proc.get("name"):
                    path = proc.get("imagefilename") or proc.get("name")
                    iocs["paths"].add(path)
                    # Extract filename
                    filename = Path(path).name if path else ""
                    if filename:
                        iocs["file_names"].add(filename)
                if proc.get("name"):
                    iocs["process_names"].add(proc["name"])
            
            # Extract from network connections
            network_connections = analysis_results.get("network_connections", [])
            for conn in network_connections:
                if conn.get("remote_ip"):
                    iocs["ips"].add(conn["remote_ip"])
            
            # Extract from file artifacts
            file_artifacts = analysis_results.get("file_artifacts", [])
            for artifact in file_artifacts:
                if artifact.get("hash_sha256"):
                    iocs["hashes_sha256"].add(artifact["hash_sha256"])
                if artifact.get("path"):
                    iocs["paths"].add(artifact["path"])
            
            # Extract from mutants
            mutants = analysis_results.get("mutants", [])
            for mutant in mutants:
                if mutant.get("name"):
                    iocs["mutexes"].add(mutant["name"])
        
        # Network IOCs - extract from new format
        if network:
            # Extract from IOCs section
            network_iocs = network.get("iocs", [])
            for ioc in network_iocs:
                ioc_type = ioc.get("type", "").lower()
                value = ioc.get("value", "")
                
                if ioc_type == "ip_address" and value:
                    iocs["ips"].add(value)
                elif ioc_type in ["domain", "hostname"] and value:
                    iocs["domains"].add(value)
                elif ioc_type == "url" and value:
                    iocs["urls"].add(value)
                elif ioc_type == "hash_sha256" and value:
                    iocs["hashes_sha256"].add(value)
                elif ioc_type == "hash_md5" and value:
                    iocs["hashes_md5"].add(value)
            
            # Extract from DNS analysis
            dns_analysis = network.get("dns_analysis", [])
            for dns_event in dns_analysis:
                if dns_event.get("query"):
                    iocs["domains"].add(dns_event["query"])
            
            # Extract from HTTP analysis
            http_analysis = network.get("http_analysis", [])
            for http_event in http_analysis:
                if http_event.get("host"):
                    iocs["domains"].add(http_event["host"])
                if http_event.get("full_url"):
                    iocs["urls"].add(http_event["full_url"])
            
            # Extract from network flows
            network_flows = network.get("network_flows", [])
            for flow in network_flows:
                if flow.get("dest_ip"):
                    iocs["ips"].add(flow["dest_ip"])
                if flow.get("src_ip"):
                    iocs["ips"].add(flow["src_ip"])
        
        # Convert sets to sorted lists for JSON serialization, filtering empty values
        return {k: sorted(list(v)) for k, v in iocs.items() if v}

    def _get_default_risk_config(self) -> Dict[str, Any]:
        """Default risk configuration if config file is not found."""
        return {
            "global_weights": {
                "procmon": 0.4,
                "memory": 0.4,
                "network": 0.2
            },
            "correlation_engine": {
                "amplifiers": [
                    {
                        "description": "Multiple data sources show suspicious activity",
                        "multiplier": 1.2
                    }
                ]
            },
            "final_risk_mapping": {
                "max_score": 10.0,
                "thresholds": [
                    {"level": "Critical", "score": 9},
                    {"level": "High", "score": 7},
                    {"level": "Medium", "score": 5},
                    {"level": "Low", "score": 3},
                    {"level": "Informational", "score": 1}
                ]
            }
        }

    def _build_cross_correlations_analysis(self, correlations: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Build detailed cross-correlation analysis."""
        correlation_types = defaultdict(int)
        high_confidence_correlations = []
        
        for correlation in correlations:
            corr_type = correlation.get("type", "unknown")
            correlation_types[corr_type] += 1
            
            # Determine confidence based on evidence
            evidence_count = correlation.get("evidence_count", len(correlation.get("details", [])))
            if evidence_count >= 3:
                high_confidence_correlations.append(correlation)
        
        return {
            "total_correlations": len(correlations),
            "correlation_types": dict(correlation_types),
            "high_confidence_correlations": high_confidence_correlations,
            "correlation_strength": "high" if len(high_confidence_correlations) > 0 else "medium" if correlations else "low"
        }

    def _build_threat_landscape_analysis(self, procmon, memory, network) -> Dict[str, Any]:
        """Build comprehensive threat landscape analysis."""
        threat_indicators = {
            "process_anomalies": [],
            "network_threats": [],
            "memory_artifacts": [],
            "file_system_changes": []
        }
        
        # Extract threat indicators from each analyzer
        if procmon:
            alerts = procmon.get("alerts", [])
            high_severity_alerts = [a for a in alerts if a.get("severity") == "high"]
            threat_indicators["process_anomalies"] = len([a for a in high_severity_alerts if "process" in a.get("type", "").lower()])
            threat_indicators["file_system_changes"] = len([a for a in high_severity_alerts if "file" in a.get("type", "").lower()])
        
        if memory:
            threat_assessment = memory.get("threat_assessment", {})
            threat_indicators["memory_artifacts"] = len(threat_assessment.get("threat_indicators", []))
        
        if network:
            iocs = network.get("iocs", [])
            threat_indicators["network_threats"] = len([ioc for ioc in iocs if ioc.get("severity") in ["high", "critical"]])
        
        return {
            "threat_indicators": threat_indicators,
            "overall_threat_level": self._calculate_threat_level(threat_indicators),
            "primary_attack_vectors": self._identify_attack_vectors(procmon, memory, network)
        }

    def _build_attack_timeline_analysis(self, timeline: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Build attack timeline analysis."""
        if not timeline:
            return {"events": 0, "analysis": "No timeline events available"}
        
        # Group events by hour to identify attack phases
        hourly_activity = defaultdict(int)
        source_activity = defaultdict(int)
        
        for event in timeline:
            source_activity[event.get("source", "unknown")] += 1
            # Could add temporal analysis here if timestamps are parseable
        
        return {
            "total_events": len(timeline),
            "event_sources": dict(source_activity),
            "timeline_span": "Available but not analyzed",  # Could enhance with actual time span
            "attack_phases": self._identify_attack_phases(timeline)
        }

    def _build_evidence_summary(self, procmon, memory, network, iocs: Dict[str, List[str]]) -> Dict[str, Any]:
        """Build comprehensive evidence summary."""
        evidence = {
            "artifact_counts": {},
            "high_value_evidence": [],
            "evidence_quality": "unknown"
        }
        
        # Count artifacts from each source
        if procmon:
            events = procmon.get("events", [])
            evidence["artifact_counts"]["procmon_events"] = len(events)
            
            alerts = procmon.get("alerts", [])
            high_severity_alerts = [a for a in alerts if a.get("severity") == "high"]
            if high_severity_alerts:
                evidence["high_value_evidence"].extend([f"Procmon: {len(high_severity_alerts)} high-severity alerts"])
        
        if memory:
            analysis_results = memory.get("analysis_results", {})
            processes = analysis_results.get("processes", [])
            evidence["artifact_counts"]["memory_processes"] = len(processes)
            
            threat_assessment = memory.get("threat_assessment", {})
            if threat_assessment.get("overall_risk_score", 0) > 7:
                evidence["high_value_evidence"].append(f"Memory: High threat score ({threat_assessment.get('overall_risk_score')})")
        
        if network:
            network_flows = network.get("network_flows", [])
            evidence["artifact_counts"]["network_flows"] = len(network_flows)
            
            suspicious_iocs = [ioc for ioc in network.get("iocs", []) if ioc.get("severity") in ["high", "critical"]]
            if suspicious_iocs:
                evidence["high_value_evidence"].append(f"Network: {len(suspicious_iocs)} high-severity IOCs")
        
        # Calculate evidence quality
        total_artifacts = sum(evidence["artifact_counts"].values())
        high_value_count = len(evidence["high_value_evidence"])
        
        if total_artifacts > 1000 and high_value_count > 2:
            evidence["evidence_quality"] = "high"
        elif total_artifacts > 100 and high_value_count > 0:
            evidence["evidence_quality"] = "medium"
        else:
            evidence["evidence_quality"] = "low"
        
        return evidence

    def _calculate_threat_level(self, threat_indicators: Dict[str, Any]) -> str:
        """Calculate overall threat level from indicators."""
        total_threats = sum(threat_indicators.values())
        
        if total_threats > 10:
            return "critical"
        elif total_threats > 5:
            return "high"
        elif total_threats > 2:
            return "medium"
        elif total_threats > 0:
            return "low"
        else:
            return "minimal"

    def _identify_attack_vectors(self, procmon, memory, network) -> List[str]:
        """Identify primary attack vectors from analysis."""
        vectors = []
        
        if network:
            iocs = network.get("iocs", [])
            if any(ioc.get("type") == "domain" for ioc in iocs):
                vectors.append("DNS-based communication")
            if any(ioc.get("type") == "ip_address" for ioc in iocs):
                vectors.append("Direct IP communication")
        
        if memory:
            analysis_results = memory.get("analysis_results", {})
            if analysis_results.get("injection_detected"):
                vectors.append("Process injection")
            if analysis_results.get("persistence_detected"):
                vectors.append("Persistence mechanisms")
        
        if procmon:
            aggregations = procmon.get("aggregations", {})
            registry_ops = aggregations.get("registry", [])
            if any("run" in reg.get("path", "").lower() for reg in registry_ops):
                vectors.append("Registry persistence")
        
        return vectors if vectors else ["Unknown"]

    def _identify_attack_phases(self, timeline: List[Dict[str, Any]]) -> List[str]:
        """Identify attack phases from timeline."""
        phases = []
        
        # Simple heuristic based on event types
        has_process_events = any("process" in event.get("event", "").lower() for event in timeline)
        has_network_events = any(event.get("source") == "Network" for event in timeline)
        has_file_events = any("file" in event.get("event", "").lower() for event in timeline)
        
        if has_process_events:
            phases.append("Initial execution")
        if has_network_events:
            phases.append("Command and control")
        if has_file_events:
            phases.append("Data collection/exfiltration")
        
        return phases if phases else ["Unknown"]

    # New comprehensive correlation and analysis methods
    
    def _correlate_disk_with_procmon(self, disk, procmon) -> List[Dict[str, Any]]:
        """Correlate disk changes with procmon file operations."""
        correlations = []
        
        if not disk or not procmon:
            return correlations
        
        # Get file changes from disk analysis
        file_changes = disk.get("file_changes", {})
        files_added = file_changes.get("files_added", [])
        files_modified = file_changes.get("files_modified", [])
        
        # Get file operations from procmon
        procmon_events = procmon.get("events", [])
        file_operations = [e for e in procmon_events if e.get("operation") in ["CreateFile", "WriteFile", "SetFileInfo"]]
        
        # Find correlations
        for disk_file in files_added + files_modified:
            disk_path = disk_file.get("path", "")
            for procmon_event in file_operations:
                procmon_path = procmon_event.get("path", "")
                if disk_path and procmon_path and disk_path.lower() == procmon_path.lower():
                    correlations.append({
                        "type": "Disk-Procmon File Correlation",
                        "file_path": disk_path,
                        "disk_change": disk_file.get("change_type", "unknown"),
                        "procmon_operation": procmon_event.get("operation"),
                        "description": f"File {disk_path} was both changed on disk and accessed in Procmon",
                        "confidence": "high"
                    })
        
        return correlations

    def _correlate_streaming_with_modules(self, streaming, procmon, memory, network) -> List[Dict[str, Any]]:
        """Correlate real-time streaming data with other modules."""
        correlations = []
        
        if not streaming:
            return correlations
        
        # Extract streaming events
        streaming_events = streaming.get("events", [])
        
        # Correlate with procmon events by timestamp and process
        if procmon:
            procmon_events = procmon.get("events", [])
            for stream_event in streaming_events:
                stream_pid = stream_event.get("process_id")
                stream_time = stream_event.get("timestamp")
                
                for procmon_event in procmon_events:
                    if (procmon_event.get("process_id") == stream_pid and 
                        abs(self._parse_timestamp(stream_time) - self._parse_timestamp(procmon_event.get("timestamp", ""))) < 5):
                        correlations.append({
                            "type": "Streaming-Procmon Process Correlation",
                            "pid": stream_pid,
                            "time_diff": abs(self._parse_timestamp(stream_time) - self._parse_timestamp(procmon_event.get("timestamp", ""))),
                            "description": f"Process {stream_pid} active in both streaming and Procmon data",
                            "confidence": "medium"
                        })
        
        return correlations

    def _correlate_file_operations(self, procmon, disk, memory) -> List[Dict[str, Any]]:
        """Cross-correlate file operations across modules."""
        correlations = []
        
        # Collect file hashes from all modules
        file_hashes = {}
        
        if procmon:
            events = procmon.get("events", [])
            for event in events:
                if event.get("file_hash") and event.get("path"):
                    file_hashes[event["file_hash"]] = file_hashes.get(event["file_hash"], [])
                    file_hashes[event["file_hash"]].append(("procmon", event["path"]))
        
        if disk:
            file_changes = disk.get("file_changes", {})
            for change_type in ["files_added", "files_modified"]:
                for file_change in file_changes.get(change_type, []):
                    if file_change.get("hash_sha256") and file_change.get("path"):
                        hash_val = file_change["hash_sha256"]
                        file_hashes[hash_val] = file_hashes.get(hash_val, [])
                        file_hashes[hash_val].append(("disk", file_change["path"]))
        
        if memory:
            processes = memory.get("analysis_results", {}).get("processes", [])
            for proc in processes:
                if proc.get("hash_sha256") and proc.get("imagefilename"):
                    hash_val = proc["hash_sha256"]
                    file_hashes[hash_val] = file_hashes.get(hash_val, [])
                    file_hashes[hash_val].append(("memory", proc["imagefilename"]))
        
        # Find correlations where same hash appears in multiple modules
        for file_hash, sources in file_hashes.items():
            if len(sources) > 1:
                unique_modules = list(set([s[0] for s in sources]))
                if len(unique_modules) > 1:
                    correlations.append({
                        "type": "Multi-Module File Correlation",
                        "file_hash": file_hash,
                        "modules": unique_modules,
                        "file_paths": [s[1] for s in sources],
                        "description": f"Same file hash found across {len(unique_modules)} modules",
                        "confidence": "very_high"
                    })
        
        return correlations

    def _correlate_registry_changes(self, procmon, disk) -> List[Dict[str, Any]]:
        """Correlate registry changes between procmon and disk analysis."""
        correlations = []
        
        if not procmon or not disk:
            return correlations
        
        # Get registry operations from procmon
        procmon_events = procmon.get("events", [])
        registry_ops = [e for e in procmon_events if e.get("operation", "").startswith("Reg")]
        
        # Get registry changes from disk
        registry_changes = disk.get("registry_changes", {}).get("changes_detected", [])
        
        # Find correlations
        for procmon_reg in registry_ops:
            procmon_path = procmon_reg.get("path", "")
            for disk_reg in registry_changes:
                disk_path = disk_reg.get("key_path", "")
                if procmon_path and disk_path and procmon_path.lower() in disk_path.lower():
                    correlations.append({
                        "type": "Registry Change Correlation",
                        "registry_key": disk_path,
                        "procmon_operation": procmon_reg.get("operation"),
                        "description": f"Registry key {disk_path} modified in both Procmon and disk analysis",
                        "confidence": "high"
                    })
        
        return correlations

    def _identify_attack_phases_temporal(self, all_events) -> List[Dict[str, Any]]:
        """Identify attack phases based on temporal analysis of all events."""
        phases = []
        
        if not all_events:
            return phases
        
        # Sort events by timestamp
        try:
            sorted_events = sorted(all_events, key=lambda x: self._parse_timestamp(x["timestamp"]))
        except:
            return phases
        
        # Group events into time windows (e.g., 5-minute windows)
        time_windows = {}
        for event in sorted_events:
            try:
                timestamp = self._parse_timestamp(event["timestamp"])
                window = int(timestamp // 300) * 300  # 5-minute windows
                if window not in time_windows:
                    time_windows[window] = []
                time_windows[window].append(event)
            except:
                continue
        
        # Analyze each time window for attack phase characteristics
        for window_time, events in time_windows.items():
            phase_indicators = {
                "initial_access": 0,
                "execution": 0,
                "persistence": 0,
                "privilege_escalation": 0,
                "defense_evasion": 0,
                "discovery": 0,
                "collection": 0,
                "exfiltration": 0,
                "impact": 0
            }
            
            for event in events:
                event_type = event.get("event_type", "").lower()
                source = event.get("source", "").lower()
                
                # Simple heuristics for phase detection
                if "network" in source and ("connect" in event_type or "flow" in event_type):
                    phase_indicators["initial_access"] += 1
                elif "process" in event_type or "execute" in event_type:
                    phase_indicators["execution"] += 1
                elif "registry" in event_type or ("file" in event_type and "startup" in str(event.get("details", {}))):
                    phase_indicators["persistence"] += 1
                elif "encrypt" in str(event.get("details", {})).lower():
                    phase_indicators["impact"] += 1
            
            # Determine primary phase for this window
            primary_phase = max(phase_indicators, key=phase_indicators.get)
            if phase_indicators[primary_phase] > 0:
                phases.append({
                    "phase": primary_phase,
                    "start_time": window_time,
                    "duration": 300,  # 5 minutes
                    "event_count": len(events),
                    "confidence": min(phase_indicators[primary_phase] / len(events), 1.0)
                })
        
        return phases

    def _cluster_events_by_time(self, all_events) -> Dict[str, Any]:
        """Cluster events by time to identify patterns."""
        clusters = {}
        
        if not all_events:
            return clusters
        
        # Simple time-based clustering
        time_buckets = {}
        for event in all_events:
            try:
                timestamp = self._parse_timestamp(event["timestamp"])
                # 1-minute buckets
                bucket = int(timestamp // 60) * 60
                if bucket not in time_buckets:
                    time_buckets[bucket] = []
                time_buckets[bucket].append(event)
            except:
                continue
        
        # Identify high-activity periods
        avg_events = sum(len(events) for events in time_buckets.values()) / len(time_buckets) if time_buckets else 0
        high_activity_threshold = avg_events * 2
        
        clusters["high_activity_periods"] = []
        for bucket_time, events in time_buckets.items():
            if len(events) > high_activity_threshold:
                clusters["high_activity_periods"].append({
                    "timestamp": bucket_time,
                    "event_count": len(events),
                    "sources": list(set([e.get("source") for e in events])),
                    "event_types": list(set([e.get("event_type") for e in events]))
                })
        
        return clusters

    def _analyze_event_sequences(self, all_events) -> Dict[str, Any]:
        """Analyze sequences of events for patterns."""
        sequences = {
            "common_sequences": [],
            "suspicious_sequences": [],
            "attack_chains": []
        }
        
        # This is a simplified implementation - could be enhanced with more sophisticated sequence analysis
        if len(all_events) < 2:
            return sequences
        
        # Look for common attack patterns
        attack_patterns = [
            ["process_creation", "file_creation", "registry_modification"],
            ["network_connection", "file_download", "process_execution"],
            ["file_encryption", "registry_persistence", "network_exfiltration"]
        ]
        
        for pattern in attack_patterns:
            if self._sequence_matches_pattern(all_events, pattern):
                sequences["attack_chains"].append({
                    "pattern": pattern,
                    "description": f"Detected attack chain: {' -> '.join(pattern)}",
                    "confidence": "medium"
                })
        
        return sequences

    def _find_concurrent_activities(self, all_events) -> List[Dict[str, Any]]:
        """Find activities that occur concurrently across modules."""
        concurrent = []
        
        if len(all_events) < 2:
            return concurrent
        
        # Group events by time windows (30-second windows)
        time_windows = {}
        for event in all_events:
            try:
                timestamp = self._parse_timestamp(event["timestamp"])
                window = int(timestamp // 30) * 30
                if window not in time_windows:
                    time_windows[window] = []
                time_windows[window].append(event)
            except:
                continue
        
        # Find windows with activities from multiple modules
        for window_time, events in time_windows.items():
            sources = set([e.get("source") for e in events])
            if len(sources) > 1:
                concurrent.append({
                    "timestamp": window_time,
                    "duration": 30,
                    "modules": list(sources),
                    "event_count": len(events),
                    "description": f"Concurrent activity across {len(sources)} modules"
                })
        
        return concurrent

    def _correlate_shared_artifacts(self, artifacts, artifact_type) -> List[Dict[str, Any]]:
        """Find correlations based on shared artifacts."""
        correlations = []
        
        # This method would analyze which artifacts appear in multiple modules
        # For now, just count unique artifacts
        if artifacts:
            correlations.append({
                "artifact_type": artifact_type,
                "unique_count": len(artifacts),
                "description": f"Found {len(artifacts)} unique {artifact_type} artifacts"
            })
        
        return correlations

    def _identify_ransomware_behaviors(self, procmon, memory, network, disk) -> List[Dict[str, Any]]:
        """Identify specific ransomware behaviors across modules."""
        behaviors = []
        
        # File encryption behavior
        if procmon:
            events = procmon.get("events", [])
            encryption_events = [e for e in events if "encrypt" in str(e.get("details", "")).lower()]
            if encryption_events:
                behaviors.append({
                    "behavior": "File Encryption",
                    "evidence_count": len(encryption_events),
                    "source": "procmon",
                    "confidence": "high"
                })
        
        # Ransom note creation
        if disk:
            file_changes = disk.get("file_changes", {})
            ransom_notes = [f for f in file_changes.get("files_added", []) 
                          if any(keyword in f.get("path", "").lower() 
                                for keyword in ["readme", "ransom", "decrypt", "restore"])]
            if ransom_notes:
                behaviors.append({
                    "behavior": "Ransom Note Creation",
                    "evidence_count": len(ransom_notes),
                    "source": "disk",
                    "confidence": "very_high"
                })
        
        return behaviors

    def _identify_persistence_mechanisms(self, procmon, memory, disk) -> List[Dict[str, Any]]:
        """Identify persistence mechanisms across modules."""
        mechanisms = []
        
        # Registry persistence
        if procmon:
            events = procmon.get("events", [])
            reg_persistence = [e for e in events if e.get("operation", "").startswith("Reg") and 
                             any(keyword in e.get("path", "").lower() for keyword in ["run", "startup", "service"])]
            if reg_persistence:
                mechanisms.append({
                    "mechanism": "Registry Persistence",
                    "evidence_count": len(reg_persistence),
                    "source": "procmon",
                    "confidence": "high"
                })
        
        return mechanisms

    def _identify_data_exfiltration(self, network, memory, procmon) -> List[Dict[str, Any]]:
        """Identify data exfiltration activities."""
        exfiltration = []
        
        if network:
            flows = network.get("network_flows", [])
            large_uploads = [f for f in flows if f.get("bytes_out", 0) > 1024*1024]  # > 1MB upload
            if large_uploads:
                exfiltration.append({
                    "activity": "Large Data Upload",
                    "evidence_count": len(large_uploads),
                    "total_bytes": sum(f.get("bytes_out", 0) for f in large_uploads),
                    "source": "network",
                    "confidence": "medium"
                })
        
        return exfiltration

    def _identify_lateral_movement(self, network, memory, procmon) -> List[Dict[str, Any]]:
        """Identify lateral movement activities."""
        lateral_movement = []
        
        if network:
            flows = network.get("network_flows", [])
            internal_connections = [f for f in flows if self._is_internal_ip(f.get("dest_ip", ""))]
            if internal_connections:
                lateral_movement.append({
                    "activity": "Internal Network Connections",
                    "evidence_count": len(internal_connections),
                    "source": "network",
                    "confidence": "medium"
                })
        
        return lateral_movement

    def _identify_defense_evasion(self, procmon, memory, disk) -> List[Dict[str, Any]]:
        """Identify defense evasion techniques."""
        evasion = []
        
        # Process hollowing/injection
        if memory:
            processes = memory.get("analysis_results", {}).get("processes", [])
            suspicious_processes = [p for p in processes if p.get("ppid") == 0 or p.get("threads", 0) == 0]
            if suspicious_processes:
                evasion.append({
                    "technique": "Process Injection/Hollowing",
                    "evidence_count": len(suspicious_processes),
                    "source": "memory",
                    "confidence": "medium"
                })
        
        return evasion

    def _sequence_matches_pattern(self, events, pattern) -> bool:
        """Check if events contain a specific sequence pattern."""
        # Simplified pattern matching - could be enhanced
        event_types = [e.get("event_type", "") for e in events]
        pattern_str = " ".join(pattern)
        events_str = " ".join(event_types)
        return pattern_str.lower() in events_str.lower()

    def _parse_timestamp(self, timestamp_str) -> float:
        """Parse timestamp string to float (seconds since epoch)."""
        try:
            if isinstance(timestamp_str, (int, float)):
                return float(timestamp_str)
            # Add more timestamp parsing logic as needed
            from datetime import datetime
            dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
            return dt.timestamp()
        except:
            return 0.0

    def _is_internal_ip(self, ip_str) -> bool:
        """Check if IP address is internal/private."""
        try:
            import ipaddress
            ip = ipaddress.ip_address(ip_str)
            return ip.is_private
        except:
            return False

    # Additional comprehensive analysis methods would go here...

    def _extract_comprehensive_iocs(self, procmon, memory, network, disk) -> Dict[str, List[str]]:
        """Extract comprehensive IOCs from all modules."""
        iocs = {
            "ips": set(),
            "domains": set(),
            "urls": set(),
            "hashes_sha256": set(),
            "hashes_md5": set(),
            "file_paths": set(),
            "registry_keys": set(),
            "mutexes": set(),
            "file_names": set(),
            "process_names": set(),
            "email_addresses": set(),
            "crypto_wallets": set()
        }
        
        # Extract IOCs from all existing modules (enhanced version of original method)
        iocs.update(self._extract_iocs(procmon, memory, network))
        
        # Add disk-specific IOCs
        if disk:
            file_changes = disk.get("file_changes", {})
            for change_type in ["files_added", "files_modified"]:
                for file_change in file_changes.get(change_type, []):
                    if file_change.get("path"):
                        iocs["file_paths"].add(file_change["path"])
                        # Extract filename
                        filename = Path(file_change["path"]).name
                        if filename:
                            iocs["file_names"].add(filename)
                    if file_change.get("hash_sha256"):
                        iocs["hashes_sha256"].add(file_change["hash_sha256"])
                    if file_change.get("hash_md5"):
                        iocs["hashes_md5"].add(file_change["hash_md5"])
            
            # Registry IOCs from disk analysis
            registry_changes = disk.get("registry_changes", {}).get("changes_detected", [])
            for reg_change in registry_changes:
                if reg_change.get("key_path"):
                    iocs["registry_keys"].add(reg_change["key_path"])
        
        # Convert sets to sorted lists for JSON serialization
        return {k: sorted(list(v)) for k, v in iocs.items() if v}

    def _merge_comprehensive_timeline(self, procmon, memory, network, disk, streaming) -> List[Dict[str, Any]]:
        """Merge timeline events from all modules."""
        timeline = []
        
        # Add events from original modules (enhanced)
        timeline.extend(self._merge_timelines(procmon, memory, network))
        
        # Add disk analysis events
        if disk:
            file_changes = disk.get("file_changes", {})
            for change_type, changes in file_changes.items():
                for change in changes:
                    if change.get("timestamp"):
                        timeline.append({
                            "timestamp": change["timestamp"],
                            "source": "Disk",
                            "event": f"File {change_type.replace('files_', '').replace('_', ' ')}: {change.get('path', 'unknown')}",
                            "priority": "high" if "ransom" in change.get("path", "").lower() else "medium",
                            "details": f"Size: {change.get('size', 'unknown')}, Hash: {change.get('hash_sha256', 'N/A')[:16]}...",
                            "module": "disk_analysis"
                        })
        
        # Add streaming events
        if streaming:
            stream_events = streaming.get("events", [])
            for event in stream_events:
                if event.get("timestamp"):
                    timeline.append({
                        "timestamp": event["timestamp"],
                        "source": "Streaming",
                        "event": f"Real-time event: {event.get('event_type', 'unknown')}",
                        "priority": "high" if event.get("severity") == "high" else "medium",
                        "details": event.get("details", ""),
                        "module": "streaming"
                    })
        
        # Sort and limit timeline
        timeline = [event for event in timeline if event.get("timestamp")]
        try:
            timeline.sort(key=lambda x: self._parse_timestamp(x["timestamp"]))
        except:
            pass
        
        return timeline[:2000]  # Increased limit for comprehensive analysis

    def _extract_file_artifacts(self, procmon, memory, disk) -> List[Dict[str, Any]]:
        """Extract comprehensive file artifacts from multiple modules."""
        artifacts = []
        
        # Combine file information from all modules
        file_info = {}
        
        if procmon:
            events = procmon.get("events", [])
            for event in events:
                if event.get("path") and event.get("operation") in ["CreateFile", "WriteFile"]:
                    path = event["path"]
                    if path not in file_info:
                        file_info[path] = {"sources": set(), "operations": set(), "timestamps": set()}
                    file_info[path]["sources"].add("procmon")
                    file_info[path]["operations"].add(event["operation"])
                    file_info[path]["timestamps"].add(event.get("timestamp", ""))
        
        if memory:
            processes = memory.get("analysis_results", {}).get("processes", [])
            for proc in processes:
                if proc.get("imagefilename"):
                    path = proc["imagefilename"]
                    if path not in file_info:
                        file_info[path] = {"sources": set(), "operations": set(), "timestamps": set()}
                    file_info[path]["sources"].add("memory")
                    file_info[path]["operations"].add("process_execution")
                    if proc.get("create_time"):
                        file_info[path]["timestamps"].add(proc["create_time"])
        
        if disk:
            file_changes = disk.get("file_changes", {})
            for change_type, changes in file_changes.items():
                for change in changes:
                    if change.get("path"):
                        path = change["path"]
                        if path not in file_info:
                            file_info[path] = {"sources": set(), "operations": set(), "timestamps": set()}
                        file_info[path]["sources"].add("disk")
                        file_info[path]["operations"].add(change_type)
                        if change.get("timestamp"):
                            file_info[path]["timestamps"].add(change["timestamp"])
        
        # Convert to artifacts list
        for path, info in file_info.items():
            artifacts.append({
                "file_path": path,
                "sources": list(info["sources"]),
                "operations": list(info["operations"]),
                "first_seen": min(info["timestamps"]) if info["timestamps"] else None,
                "last_seen": max(info["timestamps"]) if info["timestamps"] else None,
                "correlation_score": len(info["sources"])  # Higher score for files seen in multiple modules
            })
        
        # Sort by correlation score
        artifacts.sort(key=lambda x: x["correlation_score"], reverse=True)
        return artifacts

    def _extract_network_artifacts(self, memory, network) -> List[Dict[str, Any]]:
        """Extract network artifacts from memory and network modules."""
        artifacts = []
        
        # Combine network information
        network_info = {}
        
        if memory:
            connections = memory.get("analysis_results", {}).get("network_connections", [])
            for conn in connections:
                if conn.get("remote_ip"):
                    ip = conn["remote_ip"]
                    if ip not in network_info:
                        network_info[ip] = {"sources": set(), "ports": set(), "protocols": set()}
                    network_info[ip]["sources"].add("memory")
                    if conn.get("remote_port"):
                        network_info[ip]["ports"].add(conn["remote_port"])
                    if conn.get("protocol"):
                        network_info[ip]["protocols"].add(conn["protocol"])
        
        if network:
            flows = network.get("network_flows", [])
            for flow in flows:
                if flow.get("dest_ip"):
                    ip = flow["dest_ip"]
                    if ip not in network_info:
                        network_info[ip] = {"sources": set(), "ports": set(), "protocols": set()}
                    network_info[ip]["sources"].add("network")
                    if flow.get("dest_port"):
                        network_info[ip]["ports"].add(flow["dest_port"])
                    if flow.get("protocol"):
                        network_info[ip]["protocols"].add(flow["protocol"])
        
        # Convert to artifacts
        for ip, info in network_info.items():
            artifacts.append({
                "ip_address": ip,
                "sources": list(info["sources"]),
                "ports": list(info["ports"]),
                "protocols": list(info["protocols"]),
                "correlation_score": len(info["sources"])
            })
        
        artifacts.sort(key=lambda x: x["correlation_score"], reverse=True)
        return artifacts

    def _extract_process_artifacts(self, procmon, memory) -> List[Dict[str, Any]]:
        """Extract process artifacts from procmon and memory."""
        artifacts = []
        
        # Combine process information
        process_info = {}
        
        if procmon:
            events = procmon.get("events", [])
            for event in events:
                if event.get("process_name") and event.get("process_id"):
                    key = f"{event['process_name']}_{event['process_id']}"
                    if key not in process_info:
                        process_info[key] = {"sources": set(), "operations": set(), "files_accessed": set()}
                    process_info[key]["sources"].add("procmon")
                    process_info[key]["operations"].add(event.get("operation", ""))
                    if event.get("path"):
                        process_info[key]["files_accessed"].add(event["path"])
        
        if memory:
            processes = memory.get("analysis_results", {}).get("processes", [])
            for proc in processes:
                if proc.get("name") and proc.get("pid"):
                    key = f"{proc['name']}_{proc['pid']}"
                    if key not in process_info:
                        process_info[key] = {"sources": set(), "operations": set(), "files_accessed": set()}
                    process_info[key]["sources"].add("memory")
                    if proc.get("imagefilename"):
                        process_info[key]["files_accessed"].add(proc["imagefilename"])
        
        # Convert to artifacts
        for key, info in process_info.items():
            name, pid = key.rsplit("_", 1)
            artifacts.append({
                "process_name": name,
                "pid": pid,
                "sources": list(info["sources"]),
                "operations": list(info["operations"]),
                "files_accessed": list(info["files_accessed"]),
                "correlation_score": len(info["sources"])
            })
        
        artifacts.sort(key=lambda x: x["correlation_score"], reverse=True)
        return artifacts

    def _extract_registry_artifacts(self, procmon, disk) -> List[Dict[str, Any]]:
        """Extract registry artifacts from procmon and disk analysis."""
        artifacts = []
        
        # Combine registry information
        registry_info = {}
        
        if procmon:
            events = procmon.get("events", [])
            for event in events:
                if event.get("operation", "").startswith("Reg") and event.get("path"):
                    path = event["path"]
                    if path not in registry_info:
                        registry_info[path] = {"sources": set(), "operations": set(), "values": set()}
                    registry_info[path]["sources"].add("procmon")
                    registry_info[path]["operations"].add(event["operation"])
                    if event.get("details"):
                        registry_info[path]["values"].add(event["details"])
        
        if disk:
            registry_changes = disk.get("registry_changes", {}).get("changes_detected", [])
            for change in registry_changes:
                if change.get("key_path"):
                    path = change["key_path"]
                    if path not in registry_info:
                        registry_info[path] = {"sources": set(), "operations": set(), "values": set()}
                    registry_info[path]["sources"].add("disk")
                    registry_info[path]["operations"].add("registry_change")
                    if change.get("value_data"):
                        registry_info[path]["values"].add(change["value_data"])
        
        # Convert to artifacts
        for path, info in registry_info.items():
            artifacts.append({
                "registry_path": path,
                "sources": list(info["sources"]),
                "operations": list(info["operations"]),
                "values": list(info["values"]),
                "correlation_score": len(info["sources"])
            })
        
        artifacts.sort(key=lambda x: x["correlation_score"], reverse=True)
        return artifacts

    def _merge_comprehensive_mitre_techniques(self, procmon, memory, network, disk) -> List[Dict[str, Any]]:
        """Merge MITRE techniques from all modules."""
        # Enhanced version of original method
        techniques = self._merge_mitre_techniques(procmon, memory, network)
        
        # Add disk-specific techniques
        if disk:
            ransomware_indicators = disk.get("ransomware_indicators", [])
            for indicator in ransomware_indicators:
                if indicator.get("mitre_technique"):
                    technique_id = indicator["mitre_technique"]
                    # Check if already exists
                    existing = next((t for t in techniques if t["technique_id"] == technique_id), None)
                    if existing:
                        if "disk" not in existing["sources"]:
                            existing["sources"].append("disk")
                    else:
                        techniques.append({
                            "technique_id": technique_id,
                            "technique_name": indicator.get("technique_name", ""),
                            "description": indicator.get("description", ""),
                            "tactic": indicator.get("tactic", ""),
                            "sources": ["disk"],
                            "confidence": indicator.get("confidence", "medium")
                        })
        
        return techniques

    def _extract_threat_indicators(self, procmon, memory, network, disk) -> List[Dict[str, Any]]:
        """Extract comprehensive threat indicators from all modules."""
        indicators = []
        
        # File-based indicators
        if disk:
            encrypted_files = disk.get("statistics", {}).get("encrypted_files_detected", 0)
            if encrypted_files > 0:
                indicators.append({
                    "type": "File Encryption",
                    "severity": "critical",
                    "count": encrypted_files,
                    "source": "disk",
                    "description": f"{encrypted_files} files appear to be encrypted"
                })
            
            ransom_notes = disk.get("statistics", {}).get("ransom_notes_found", 0)
            if ransom_notes > 0:
                indicators.append({
                    "type": "Ransom Note",
                    "severity": "critical",
                    "count": ransom_notes,
                    "source": "disk",
                    "description": f"{ransom_notes} ransom notes detected"
                })
        
        # Network-based indicators
        if network:
            suspicious_domains = len([ioc for ioc in network.get("iocs", []) if ioc.get("type") == "domain"])
            if suspicious_domains > 0:
                indicators.append({
                    "type": "Suspicious Network Communication",
                    "severity": "high",
                    "count": suspicious_domains,
                    "source": "network",
                    "description": f"{suspicious_domains} suspicious domains contacted"
                })
        
        # Process-based indicators
        if memory:
            suspicious_processes = len([p for p in memory.get("analysis_results", {}).get("processes", []) 
                                      if p.get("suspicious", False)])
            if suspicious_processes > 0:
                indicators.append({
                    "type": "Suspicious Process",
                    "severity": "high",
                    "count": suspicious_processes,
                    "source": "memory",
                    "description": f"{suspicious_processes} suspicious processes detected"
                })
        
        return indicators

    def _analyze_attack_progression(self, timeline, mitre_techniques) -> List[Dict[str, Any]]:
        """Analyze the progression of the attack based on timeline and MITRE techniques."""
        progression = []
        
        # Group MITRE techniques by tactic
        tactics_timeline = {}
        
        for technique in mitre_techniques:
            tactic = technique.get("tactic", "unknown")
            if tactic not in tactics_timeline:
                tactics_timeline[tactic] = []
            tactics_timeline[tactic].append(technique)
        
        # MITRE ATT&CK kill chain order
        kill_chain_order = [
            "initial-access",
            "execution", 
            "persistence",
            "privilege-escalation",
            "defense-evasion",
            "credential-access",
            "discovery",
            "lateral-movement",
            "collection",
            "command-and-control",
            "exfiltration",
            "impact"
        ]
        
        for i, tactic in enumerate(kill_chain_order):
            if tactic in tactics_timeline:
                progression.append({
                    "phase": i + 1,
                    "tactic": tactic,
                    "techniques": tactics_timeline[tactic],
                    "description": f"Phase {i + 1}: {tactic.replace('-', ' ').title()}"
                })
        
        return progression

    def _calculate_comprehensive_risk(self, procmon, memory, network, disk, correlations) -> float:
        """Calculate comprehensive risk score using all modules and correlations."""
        # Base weights for different modules
        weights = {
            "procmon": 0.25,
            "memory": 0.25,
            "network": 0.20,
            "disk": 0.30  # Higher weight for disk analysis in ransomware detection
        }
        
        weighted_sum = 0.0
        total_weight = 0.0
        
        # Calculate individual module scores
        if procmon:
            score = self._extract_procmon_risk_score(procmon)
            weighted_sum += score * weights["procmon"]
            total_weight += weights["procmon"]
        
        if memory:
            threat_assessment = memory.get("threat_assessment", {})
            score = threat_assessment.get("overall_risk_score", 0)
            weighted_sum += score * weights["memory"]
            total_weight += weights["memory"]
        
        if network:
            score = self._extract_network_risk_score(network)
            weighted_sum += score * weights["network"]
            total_weight += weights["network"]
        
        if disk:
            score = self._extract_disk_risk_score(disk)
            weighted_sum += score * weights["disk"]
            total_weight += weights["disk"]
        
        # Normalize base score
        base_score = weighted_sum / total_weight if total_weight > 0 else 0
        
        # Apply correlation multipliers
        correlation_multiplier = self._calculate_correlation_multiplier(correlations)
        final_score = base_score * correlation_multiplier
        
        return min(final_score, 10.0)

    def _calculate_confidence_score(self, correlations, evidence_summary) -> float:
        """Calculate confidence score based on correlations and evidence quality."""
        confidence_factors = []
        
        # Cross-module correlations boost confidence
        cross_correlations = correlations.get("cross_module_correlations", [])
        if cross_correlations:
            confidence_factors.append(min(len(cross_correlations) * 0.2, 1.0))
        
        # Multiple evidence sources boost confidence
        evidence_sources = len([k for k, v in evidence_summary.items() if v])
        confidence_factors.append(min(evidence_sources * 0.15, 1.0))
        
        # File artifacts correlation
        file_artifacts = evidence_summary.get("file_artifacts", [])
        high_correlation_files = len([f for f in file_artifacts if f.get("correlation_score", 0) > 1])
        if high_correlation_files:
            confidence_factors.append(min(high_correlation_files * 0.1, 0.5))
        
        # Calculate overall confidence
        if confidence_factors:
            confidence = sum(confidence_factors) / len(confidence_factors)
            return min(confidence * 10, 10.0)  # Scale to 0-10
        
        return 5.0  # Default medium confidence

    def _calculate_correlation_multiplier(self, correlations) -> float:
        """Calculate multiplier based on correlation strength."""
        multiplier = 1.0
        
        # Cross-module correlations
        cross_correlations = correlations.get("cross_module_correlations", [])
        high_confidence_correlations = len([c for c in cross_correlations 
                                          if c.get("confidence") in ["high", "very_high"]])
        
        if high_confidence_correlations > 5:
            multiplier *= 1.5
        elif high_confidence_correlations > 2:
            multiplier *= 1.3
        elif high_confidence_correlations > 0:
            multiplier *= 1.1
        
        # Temporal correlations
        temporal_correlations = correlations.get("temporal_correlations", {})
        if temporal_correlations.get("attack_phases"):
            multiplier *= 1.2
        
        # Behavioral correlations
        behavioral_correlations = correlations.get("behavioral_correlations", {})
        ransomware_behaviors = behavioral_correlations.get("ransomware_behaviors", [])
        if len(ransomware_behaviors) > 2:
            multiplier *= 1.4
        elif len(ransomware_behaviors) > 0:
            multiplier *= 1.2
        
        return min(multiplier, 2.0)  # Cap at 2x multiplier

    def _build_executive_summary(self, combined_report) -> Dict[str, Any]:
        """Build executive summary from combined analysis."""
        threat_assessment = combined_report["threat_assessment"]
        evidence_summary = combined_report["evidence_summary"]
        correlations = combined_report["correlation_analysis"]
        
        summary = {
            "overall_assessment": {
                "risk_level": threat_assessment["risk_level"],
                "risk_score": threat_assessment["overall_risk_score"],
                "confidence": threat_assessment["confidence_score"]
            },
            "key_findings": [],
            "attack_summary": {
                "attack_phases_detected": len(threat_assessment.get("attack_progression", [])),
                "mitre_techniques_identified": len(threat_assessment.get("mitre_techniques", [])),
                "modules_with_evidence": len([k for k, v in combined_report["analysis_results"].items() if v])
            },
            "evidence_quality": {
                "total_correlations": len(correlations.get("cross_module_correlations", [])),
                "high_confidence_correlations": len([c for c in correlations.get("cross_module_correlations", []) 
                                                   if c.get("confidence") in ["high", "very_high"]]),
                "unique_iocs": sum(len(v) for v in evidence_summary.get("iocs", {}).values()),
                "timeline_events": len(evidence_summary.get("timeline", []))
            }
        }
        
        # Generate key findings
        threat_indicators = threat_assessment.get("threat_indicators", [])
        critical_indicators = [t for t in threat_indicators if t.get("severity") == "critical"]
        if critical_indicators:
            summary["key_findings"].extend([f"Critical: {t['description']}" for t in critical_indicators[:3]])
        
        high_indicators = [t for t in threat_indicators if t.get("severity") == "high"]
        if high_indicators:
            summary["key_findings"].extend([f"High: {t['description']}" for t in high_indicators[:2]])
        
        return summary

    def _build_detailed_findings(self, combined_report) -> Dict[str, Any]:
        """Build detailed findings section."""
        return {
            "correlation_analysis": combined_report["correlation_analysis"],
            "threat_assessment": combined_report["threat_assessment"],
            "evidence_summary": combined_report["evidence_summary"],
            "module_summaries": self._build_module_summaries(combined_report["analysis_results"])
        }

    def _build_module_summaries(self, analysis_results) -> Dict[str, Any]:
        """Build summary for each analysis module."""
        summaries = {}
        
        for module_name, module_data in analysis_results.items():
            if module_data:
                summaries[module_name] = {
                    "status": "analyzed",
                    "key_metrics": self._extract_module_metrics(module_name, module_data),
                    "top_findings": self._extract_top_findings(module_name, module_data)
                }
            else:
                summaries[module_name] = {
                    "status": "not_available",
                    "key_metrics": {},
                    "top_findings": []
                }
        
        return summaries

    def _extract_module_metrics(self, module_name, module_data) -> Dict[str, Any]:
        """Extract key metrics for each module."""
        metrics = {}
        
        if module_name == "procmon":
            metrics = {
                "events_processed": len(module_data.get("events", [])),
                "alerts_generated": len(module_data.get("alerts", [])),
                "processes_monitored": len(module_data.get("aggregations", {}).get("processes", []))
            }
        elif module_name == "memory":
            analysis_results = module_data.get("analysis_results", {})
            metrics = {
                "processes_analyzed": len(analysis_results.get("processes", [])),
                "network_connections": len(analysis_results.get("network_connections", [])),
                "file_artifacts": len(analysis_results.get("file_artifacts", []))
            }
        elif module_name == "network":
            metrics = {
                "network_flows": len(module_data.get("network_flows", [])),
                "dns_queries": len(module_data.get("dns_analysis", [])),
                "iocs_found": len(module_data.get("iocs", []))
            }
        elif module_name == "disk":
            statistics = module_data.get("statistics", {})
            metrics = {
                "files_changed": statistics.get("total_files_changed", 0),
                "files_encrypted": statistics.get("encrypted_files_detected", 0),
                "ransom_notes": statistics.get("ransom_notes_found", 0)
            }
        
        return metrics

    def _extract_top_findings(self, module_name, module_data) -> List[str]:
        """Extract top findings for each module."""
        findings = []
        
        if module_name == "procmon":
            alerts = module_data.get("alerts", [])
            high_severity = [a for a in alerts if a.get("severity") == "high"]
            findings.extend([a.get("description", "High severity alert") for a in high_severity[:3]])
        
        elif module_name == "memory":
            threat_assessment = module_data.get("threat_assessment", {})
            threat_indicators = threat_assessment.get("threat_indicators", [])
            findings.extend([t.get("description", "Threat indicator") for t in threat_indicators[:3]])
        
        elif module_name == "network":
            iocs = module_data.get("iocs", [])
            critical_iocs = [i for i in iocs if i.get("severity") in ["high", "critical"]]
            findings.extend([f"Suspicious {i.get('type', 'activity')}: {i.get('value', 'unknown')}" 
                           for i in critical_iocs[:3]])
        
        elif module_name == "disk":
            indicators = module_data.get("ransomware_indicators", [])
            findings.extend([i.get("description", "Ransomware indicator") for i in indicators[:3]])
        
        return findings

    def _generate_comprehensive_recommendations(self, combined_report) -> List[Dict[str, Any]]:
        """Generate comprehensive recommendations based on analysis."""
        recommendations = []
        
        risk_level = combined_report["threat_assessment"]["risk_level"].lower()
        threat_indicators = combined_report["threat_assessment"]["threat_indicators"]
        
        # Risk-based recommendations
        if risk_level in ["critical", "high"]:
            recommendations.append({
                "priority": "immediate",
                "category": "containment",
                "action": "Isolate affected systems immediately",
                "description": "High risk level detected - immediate containment required"
            })
            
            recommendations.append({
                "priority": "immediate", 
                "category": "backup",
                "action": "Check backup integrity and availability",
                "description": "Verify that backups are clean and restorable"
            })
        
        # Indicator-based recommendations
        ransomware_indicators = [t for t in threat_indicators if "encrypt" in t.get("description", "").lower()]
        if ransomware_indicators:
            recommendations.append({
                "priority": "high",
                "category": "investigation",
                "action": "Conduct forensic analysis of encrypted files",
                "description": "Determine encryption method and potential recovery options"
            })
        
        network_indicators = [t for t in threat_indicators if t.get("source") == "network"]
        if network_indicators:
            recommendations.append({
                "priority": "high",
                "category": "network_security",
                "action": "Block suspicious network communications",
                "description": "Implement network-level blocking for identified IOCs"
            })
        
        # General recommendations
        recommendations.extend([
            {
                "priority": "medium",
                "category": "monitoring",
                "action": "Enhance monitoring for identified IOCs",
                "description": "Deploy additional monitoring for artifacts found in analysis"
            },
            {
                "priority": "medium",
                "category": "patch_management",
                "action": "Review and apply security patches",
                "description": "Ensure systems are up to date with latest security patches"
            },
            {
                "priority": "low",
                "category": "training",
                "action": "Conduct security awareness training",
                "description": "Train users on identifying and reporting suspicious activities"
            }
        ])
        
        return recommendations

    def _analyze_false_positives(self, combined_report) -> Dict[str, Any]:
        """Analyze potential false positives in the analysis."""
        false_positive_analysis = {
            "potential_false_positives": [],
            "confidence_factors": [],
            "validation_needed": []
        }
        
        # Check for low-confidence indicators
        threat_indicators = combined_report["threat_assessment"]["threat_indicators"]
        low_confidence = [t for t in threat_indicators if t.get("confidence", "medium") == "low"]
        
        if low_confidence:
            false_positive_analysis["potential_false_positives"].extend([
                f"Low confidence indicator: {t.get('description', 'Unknown')}" for t in low_confidence
            ])
        
        # Check for single-source indicators
        correlations = combined_report["correlation_analysis"]["cross_module_correlations"]
        single_source_indicators = []
        
        for module_name, module_data in combined_report["analysis_results"].items():
            if module_data and module_name not in [c.get("modules", []) for c in correlations]:
                single_source_indicators.append(module_name)
        
        if single_source_indicators:
            false_positive_analysis["validation_needed"].extend([
                f"Single-source findings from {module} require validation" for module in single_source_indicators
            ])
        
        # Confidence factors
        confidence_score = combined_report["threat_assessment"]["confidence_score"]
        if confidence_score < 7:
            false_positive_analysis["confidence_factors"].append(
                f"Overall confidence score is {confidence_score:.1f}/10 - consider additional validation"
            )
        
        return false_positive_analysis
