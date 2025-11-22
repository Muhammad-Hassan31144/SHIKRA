#!/usr/bin/env python3
"""
Native Zeek-based Network Analysis Automation for RansomKit

This script provides full automation of ransomware analysis using Zeek's 
native event-driven architecture and built-in log generation capabilities.
Designed for Linux deployment with proper Zeek integration.
"""

import asyncio
import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime
import subprocess
import tempfile
import os

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from shikra.analysis.network.zeek_analyzer_native import ZeekAnalyzer
from shikra.analysis.network.file_reconstructor import FileReconstructor
from shikra.analysis.network.analyse import NetworkAnalyzer
from shikra.utils.logger import setup_logger


class NativeZeekAutomation:
    """
    Full automation pipeline using Zeek's native capabilities for ransomware analysis.
    """
    
    def __init__(self, 
                 zeek_path: str = "zeek",
                 workspace_dir: Optional[Path] = None,
                 config_dir: Optional[Path] = None):
        """
        Initialize native Zeek automation pipeline.
        
        Args:
            zeek_path: Path to Zeek binary
            workspace_dir: Working directory for analysis
            config_dir: Configuration directory
        """
        self.logger = setup_logger("NativeZeekAutomation")
        self.zeek_path = zeek_path
        self.workspace_dir = workspace_dir or Path("/tmp/ransomkit_native_analysis")
        self.config_dir = config_dir or Path(__file__).parent.parent.parent / "config"
        
        # Initialize components with native Zeek integration
        self.zeek_analyzer = ZeekAnalyzer(zeek_path=zeek_path)
        self.file_reconstructor = FileReconstructor()
        self.network_analyzer = NetworkAnalyzer()
        
        # Setup workspace
        self.workspace_dir.mkdir(parents=True, exist_ok=True)
        self.zeek_output_dir = self.workspace_dir / "zeek_native_output"
        self.reconstructed_files_dir = self.workspace_dir / "reconstructed_files"
        self.final_reports_dir = self.workspace_dir / "reports"
        
        # Create directories
        for dir_path in [self.zeek_output_dir, self.reconstructed_files_dir, self.final_reports_dir]:
            dir_path.mkdir(parents=True, exist_ok=True)
    
    async def run_full_analysis(self, pcap_path: Path, 
                               output_dir: Optional[Path] = None,
                               enable_file_reconstruction: bool = True,
                               custom_zeek_scripts: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Run complete automated analysis using native Zeek capabilities.
        
        Args:
            pcap_path: Path to PCAP file for analysis
            output_dir: Custom output directory (uses workspace if None)
            enable_file_reconstruction: Whether to reconstruct files from traffic
            custom_zeek_scripts: Additional Zeek scripts to load
            
        Returns:
            Comprehensive analysis results
        """
        analysis_start = datetime.now()
        
        if output_dir:
            self.final_reports_dir = output_dir
            self.final_reports_dir.mkdir(parents=True, exist_ok=True)
        
        self.logger.info(f"Starting native Zeek automation for: {pcap_path}")
        self.logger.info(f"Workspace: {self.workspace_dir}")
        self.logger.info(f"Output: {self.final_reports_dir}")
        
        try:
            # Phase 1: Native Zeek Analysis with Event-Driven Detection
            self.logger.info("Phase 1: Running native Zeek analysis with ransomware detection...")
            zeek_results = await self._run_native_zeek_analysis(pcap_path, custom_zeek_scripts)
            
            # Phase 2: File Reconstruction from Zeek Extracted Files
            reconstructed_files = []
            if enable_file_reconstruction:
                self.logger.info("Phase 2: Reconstructing files from Zeek extractions...")
                reconstructed_files = await self._reconstruct_files_from_zeek(zeek_results)
            
            # Phase 3: Enhanced Network Analysis with Zeek Intelligence
            self.logger.info("Phase 3: Running enhanced network analysis...")
            network_results = await self._run_enhanced_network_analysis(pcap_path, zeek_results)
            
            # Phase 4: Comprehensive Correlation and Risk Assessment
            self.logger.info("Phase 4: Correlating results and assessing risk...")
            correlation_results = await self._correlate_all_results(
                zeek_results, network_results, reconstructed_files
            )
            
            # Phase 5: Generate Final Reports
            self.logger.info("Phase 5: Generating comprehensive reports...")
            final_report = await self._generate_final_report(
                zeek_results, network_results, reconstructed_files, correlation_results
            )
            
            analysis_end = datetime.now()
            analysis_duration = (analysis_end - analysis_start).total_seconds()
            
            # Add execution metadata
            final_report["execution_metadata"] = {
                "analysis_start": analysis_start.isoformat(),
                "analysis_end": analysis_end.isoformat(),
                "duration_seconds": analysis_duration,
                "zeek_version": await self._get_zeek_version(),
                "pcap_file": str(pcap_path),
                "workspace_dir": str(self.workspace_dir),
                "output_dir": str(self.final_reports_dir),
                "file_reconstruction_enabled": enable_file_reconstruction,
                "custom_scripts": custom_zeek_scripts or []
            }
            
            # Save final results
            await self._save_final_results(final_report)
            
            self.logger.info(f"Native Zeek automation completed in {analysis_duration:.2f} seconds")
            return final_report
            
        except Exception as e:
            self.logger.error(f"Native Zeek automation failed: {e}")
            raise
    
    async def _run_native_zeek_analysis(self, pcap_path: Path, 
                                       custom_scripts: Optional[List[str]] = None) -> Dict[str, Any]:
        """Run native Zeek analysis with event-driven ransomware detection."""
        
        # Zeek will automatically load and execute the ransomware detection script
        # which uses Zeek's native event system for real-time analysis
        results = await self.zeek_analyzer.analyze_pcap(
            pcap_path, 
            self.zeek_output_dir,
            custom_scripts
        )
        
        # Log key findings from native Zeek analysis
        summary = self.zeek_analyzer.get_summary()
        self.logger.info(f"Native Zeek analysis complete:")
        self.logger.info(f"  - Risk Level: {summary.get('risk_assessment', {}).get('risk_level', 'UNKNOWN')}")
        self.logger.info(f"  - Ransomware Indicators: {len(self.zeek_analyzer.get_detailed_indicators())}")
        self.logger.info(f"  - Zeek Notices: {len(self.zeek_analyzer.get_zeek_notices())}")
        self.logger.info(f"  - Intel Hits: {len(self.zeek_analyzer.get_intel_hits())}")
        
        return results
    
    async def _reconstruct_files_from_zeek(self, zeek_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Reconstruct files using Zeek's native file extraction capabilities."""
        
        reconstructed = []
        
        # Zeek automatically extracts files - we just need to analyze them
        extract_dir = self.zeek_output_dir / "extract_files"
        if extract_dir.exists():
            
            # Get file metadata from Zeek's files.log
            zeek_files = zeek_results.get("files", [])
            
            for zeek_file in zeek_files:
                if zeek_file.get("extracted"):
                    extracted_path = Path(zeek_file["extracted"])
                    
                    if extracted_path.exists():
                        # Reconstruct using Zeek's extracted file
                        reconstructed_file = await self.file_reconstructor.reconstruct_from_zeek_extract(
                            extracted_path,
                            zeek_file,
                            self.reconstructed_files_dir
                        )
                        
                        if reconstructed_file:
                            reconstructed.append(reconstructed_file)
                            self.logger.info(f"Reconstructed file: {reconstructed_file['filename']}")
        
        self.logger.info(f"Total files reconstructed from Zeek extractions: {len(reconstructed)}")
        return reconstructed
    
    async def _run_enhanced_network_analysis(self, pcap_path: Path, 
                                           zeek_results: Dict[str, Any]) -> Dict[str, Any]:
        """Run enhanced network analysis incorporating Zeek intelligence."""
        
        # Use traditional network analysis enhanced with Zeek findings
        results = await self.network_analyzer.analyze_pcap(
            pcap_path,
            self.workspace_dir / "network_analysis"
        )
        
        # Enhance with Zeek intelligence
        results["zeek_enhanced"] = {
            "suspicious_ips": zeek_results.get("key_entities", {}).get("suspicious_ips", []),
            "c2_servers": zeek_results.get("key_entities", {}).get("c2_servers", []),
            "malicious_domains": zeek_results.get("key_entities", {}).get("suspicious_domains", []),
            "crypto_addresses": zeek_results.get("key_entities", {}).get("crypto_addresses", []),
            "tor_nodes": zeek_results.get("key_entities", {}).get("tor_nodes", [])
        }
        
        return results
    
    async def _correlate_all_results(self, zeek_results: Dict[str, Any], 
                                    network_results: Dict[str, Any],
                                    reconstructed_files: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Correlate all analysis results for comprehensive assessment."""
        
        correlation = {
            "unified_timeline": [],
            "cross_validated_indicators": {},
            "confidence_scored_threats": [],
            "attack_chain_reconstruction": {},
            "comprehensive_risk_score": 0,
            "actionable_recommendations": []
        }
        
        # Merge timelines from all sources
        timeline_events = []
        
        # Add Zeek timeline
        zeek_timeline = zeek_results.get("timeline", [])
        for event in zeek_timeline:
            event["source"] = "zeek_native"
            timeline_events.append(event)
        
        # Add network timeline if available
        network_timeline = network_results.get("timeline", [])
        for event in network_timeline:
            event["source"] = "network_analysis"
            timeline_events.append(event)
        
        # Sort unified timeline
        timeline_events.sort(key=lambda x: float(x.get("timestamp", 0)))
        correlation["unified_timeline"] = timeline_events
        
        # Cross-validate indicators
        zeek_risk = zeek_results.get("risk_assessment", {})
        network_risk = network_results.get("risk_assessment", {})
        
        # Comprehensive risk scoring
        zeek_score = zeek_risk.get("risk_score", 0)
        network_score = network_risk.get("risk_score", 0)
        file_score = len(reconstructed_files) * 10  # Bonus for file reconstruction
        
        correlation["comprehensive_risk_score"] = zeek_score + network_score + file_score
        
        # Determine final risk level
        total_score = correlation["comprehensive_risk_score"]
        if total_score >= 150:
            correlation["final_risk_level"] = "CRITICAL"
        elif total_score >= 100:
            correlation["final_risk_level"] = "HIGH"  
        elif total_score >= 50:
            correlation["final_risk_level"] = "MEDIUM"
        elif total_score > 0:
            correlation["final_risk_level"] = "LOW"
        else:
            correlation["final_risk_level"] = "MINIMAL"
        
        # Generate actionable recommendations
        correlation["actionable_recommendations"] = await self._generate_recommendations(
            zeek_results, network_results, reconstructed_files, correlation
        )
        
        return correlation
    
    async def _generate_recommendations(self, zeek_results: Dict[str, Any],
                                       network_results: Dict[str, Any], 
                                       reconstructed_files: List[Dict[str, Any]],
                                       correlation: Dict[str, Any]) -> List[str]:
        """Generate actionable security recommendations."""
        
        recommendations = []
        
        # Zeek-based recommendations
        zeek_indicators = zeek_results.get("ransomware_indicators", [])
        if zeek_indicators:
            recommendations.append(f"URGENT: {len(zeek_indicators)} ransomware indicators detected by Zeek")
        
        # C2 communication recommendations  
        c2_servers = zeek_results.get("key_entities", {}).get("c2_servers", [])
        if c2_servers:
            recommendations.extend([
                f"Block C2 server communication: {ip}" for ip in c2_servers[:5]
            ])
        
        # Cryptocurrency recommendations
        crypto_addresses = zeek_results.get("key_entities", {}).get("crypto_addresses", [])
        if crypto_addresses:
            recommendations.append(f"Monitor cryptocurrency transactions to {len(crypto_addresses)} addresses")
        
        # TOR usage recommendations
        tor_nodes = zeek_results.get("key_entities", {}).get("tor_nodes", [])
        if tor_nodes:
            recommendations.append("Investigate TOR usage for potential data exfiltration")
        
        # File analysis recommendations
        if reconstructed_files:
            suspicious_files = [f for f in reconstructed_files if f.get("is_suspicious", False)]
            if suspicious_files:
                recommendations.append(f"Quarantine {len(suspicious_files)} suspicious reconstructed files")
        
        # Risk-based recommendations
        risk_level = correlation.get("final_risk_level", "MINIMAL")
        if risk_level in ["CRITICAL", "HIGH"]:
            recommendations.extend([
                "Immediate incident response required",
                "Isolate affected systems from network",
                "Backup critical data immediately",
                "Engage cybersecurity incident response team"
            ])
        
        return recommendations
    
    async def _generate_final_report(self, zeek_results: Dict[str, Any],
                                    network_results: Dict[str, Any],
                                    reconstructed_files: List[Dict[str, Any]],
                                    correlation: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive final report."""
        
        return {
            "executive_summary": {
                "risk_level": correlation.get("final_risk_level", "UNKNOWN"),
                "risk_score": correlation.get("comprehensive_risk_score", 0),
                "key_findings": await self._extract_key_findings(zeek_results, network_results),
                "recommendations": correlation.get("actionable_recommendations", [])
            },
            "zeek_native_analysis": {
                "summary": self.zeek_analyzer.get_summary(),
                "detailed_indicators": self.zeek_analyzer.get_detailed_indicators(),
                "zeek_notices": self.zeek_analyzer.get_zeek_notices(),
                "intel_hits": self.zeek_analyzer.get_intel_hits()
            },
            "network_analysis": network_results,
            "file_reconstruction": {
                "total_files": len(reconstructed_files),
                "files": reconstructed_files
            },
            "correlation_analysis": correlation,
            "raw_zeek_results": zeek_results
        }
    
    async def _extract_key_findings(self, zeek_results: Dict[str, Any],
                                   network_results: Dict[str, Any]) -> List[str]:
        """Extract key findings for executive summary."""
        
        findings = []
        
        # Zeek findings
        ransomware_indicators = len(zeek_results.get("ransomware_indicators", []))
        if ransomware_indicators > 0:
            findings.append(f"Zeek detected {ransomware_indicators} ransomware-specific indicators")
        
        zeek_notices = len(zeek_results.get("notice_log", []))
        if zeek_notices > 0:
            findings.append(f"Zeek generated {zeek_notices} security notices")
        
        intel_hits = len(zeek_results.get("intel_log", []))
        if intel_hits > 0:
            findings.append(f"Threat intelligence matched {intel_hits} indicators")
        
        # Network findings
        suspicious_connections = network_results.get("statistics", {}).get("suspicious_connections", 0)
        if suspicious_connections > 0:
            findings.append(f"Network analysis found {suspicious_connections} suspicious connections")
        
        return findings
    
    async def _save_final_results(self, final_report: Dict[str, Any]):
        """Save final analysis results in multiple formats."""
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Save JSON report
        json_path = self.final_reports_dir / f"native_zeek_analysis_{timestamp}.json"
        with open(json_path, 'w') as f:
            json.dump(final_report, f, indent=2, default=str)
        
        # Save executive summary
        summary_path = self.final_reports_dir / f"executive_summary_{timestamp}.json"
        with open(summary_path, 'w') as f:
            json.dump(final_report["executive_summary"], f, indent=2, default=str)
        
        # Export Zeek results separately
        zeek_export_path = self.final_reports_dir / f"zeek_native_export_{timestamp}.json"
        self.zeek_analyzer.export_to_json(zeek_export_path)
        
        self.logger.info(f"Final results saved:")
        self.logger.info(f"  - Full report: {json_path}")
        self.logger.info(f"  - Executive summary: {summary_path}")
        self.logger.info(f"  - Zeek export: {zeek_export_path}")
    
    async def _get_zeek_version(self) -> str:
        """Get Zeek version for metadata."""
        try:
            result = subprocess.run([self.zeek_path, "--version"], 
                                  capture_output=True, text=True, timeout=5)
            return result.stdout.strip() if result.returncode == 0 else "unknown"
        except:
            return "unknown"


async def main():
    """Main entry point for native Zeek automation."""
    
    parser = argparse.ArgumentParser(
        description="Native Zeek-based Network Analysis Automation for RansomKit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic analysis with native Zeek
  python native_zeek_automation.py -i capture.pcap -o /tmp/analysis

  # Analysis with custom Zeek scripts  
  python native_zeek_automation.py -i capture.pcap -o /tmp/analysis \\
    --zeek-scripts dns-tunneling file-analysis

  # Full automation with file reconstruction
  python native_zeek_automation.py -i capture.pcap -o /tmp/analysis \\
    --enable-file-reconstruction --zeek-path /opt/zeek/bin/zeek

  # Quick analysis without file reconstruction
  python native_zeek_automation.py -i capture.pcap -o /tmp/analysis \\
    --no-file-reconstruction
        """
    )
    
    parser.add_argument("-i", "--input", required=True, type=Path,
                       help="Input PCAP file for analysis")
    parser.add_argument("-o", "--output", type=Path,
                       help="Output directory for results")
    parser.add_argument("--workspace", type=Path,
                       help="Workspace directory (default: /tmp/ransomkit_native)")
    parser.add_argument("--zeek-path", default="zeek",
                       help="Path to Zeek binary (default: zeek)")
    parser.add_argument("--zeek-scripts", nargs="+",
                       help="Additional Zeek scripts to load")
    parser.add_argument("--enable-file-reconstruction", action="store_true", default=True,
                       help="Enable file reconstruction (default)")
    parser.add_argument("--no-file-reconstruction", action="store_false", 
                       dest="enable_file_reconstruction",
                       help="Disable file reconstruction")
    parser.add_argument("--verbose", "-v", action="store_true",
                       help="Enable verbose logging")
    
    args = parser.parse_args()
    
    # Setup logging
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Verify input file
    if not args.input.exists():
        print(f"Error: Input PCAP file not found: {args.input}")
        sys.exit(1)
    
    try:
        # Initialize automation
        automation = NativeZeekAutomation(
            zeek_path=args.zeek_path,
            workspace_dir=args.workspace
        )
        
        # Run analysis
        results = await automation.run_full_analysis(
            pcap_path=args.input,
            output_dir=args.output,
            enable_file_reconstruction=args.enable_file_reconstruction,
            custom_zeek_scripts=args.zeek_scripts
        )
        
        # Print summary
        print("\n" + "="*60)
        print("NATIVE ZEEK AUTOMATION COMPLETE")
        print("="*60)
        
        exec_summary = results.get("executive_summary", {})
        print(f"Risk Level: {exec_summary.get('risk_level', 'UNKNOWN')}")
        print(f"Risk Score: {exec_summary.get('risk_score', 0)}")
        print(f"Key Findings: {len(exec_summary.get('key_findings', []))}")
        print(f"Recommendations: {len(exec_summary.get('recommendations', []))}")
        
        zeek_summary = results.get("zeek_native_analysis", {}).get("summary", {})
        print(f"Ransomware Indicators: {len(results.get('zeek_native_analysis', {}).get('detailed_indicators', []))}")
        print(f"Zeek Notices: {len(results.get('zeek_native_analysis', {}).get('zeek_notices', []))}")
        print(f"Files Reconstructed: {results.get('file_reconstruction', {}).get('total_files', 0)}")
        
        print("\nTop Recommendations:")
        for i, rec in enumerate(exec_summary.get('recommendations', [])[:5], 1):
            print(f"  {i}. {rec}")
        
        print("="*60)
        
    except KeyboardInterrupt:
        print("\nAnalysis interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"Error during analysis: {e}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
