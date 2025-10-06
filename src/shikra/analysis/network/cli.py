import typer
from typing_extensions import Annotated
from pathlib import Path
import logging
import asyncio
from typing import Optional, List

from .analyse import NetworkAnalyzer
from .zeek_analyzer_native import ZeekAnalyzer
from .file_reconstructor import FileReconstructor
from .render import NetworkReportRenderer
from ...utils.logger import setup_logger
from ...utils.jsonio import save_json
from ...utils.vt import VT_API_KEY

app = typer.Typer(name="network", help="Analyze network PCAP files for malicious activity with optional Zeek integration.")

@app.command()
def analyze(
    pcap_path: Annotated[Path, typer.Argument(..., help="Path to the PCAP network capture file.", exists=True, readable=True)],
    json_output: Annotated[Path, typer.Option("--json-output", help="Path to save the JSON analysis report.")],
    output_dir: Annotated[Optional[Path], typer.Option("--output-dir", help="Directory to save all analysis artifacts and logs.")] = None,
    vt_api_key: Annotated[str, typer.Option(help="VirusTotal API key for threat intelligence.")] = VT_API_KEY,
    config_dir: Annotated[Path, typer.Option(help="Path to the configuration directory.")] = Path("config"),
    
    # Zeek Integration Options
    zeek: Annotated[bool, typer.Option("--zeek/--no-zeek", help="Enable native Zeek analysis with ransomware detection.")] = False,
    zeek_path: Annotated[str, typer.Option(help="Path to Zeek binary.")] = "zeek",
    zeek_scripts: Annotated[Optional[List[str]], typer.Option("--zeek-script", help="Additional Zeek scripts to load.")] = None,
    
    # Tool Paths
    tshark_path: Annotated[str, typer.Option(help="Path to tshark binary.")] = "tshark",
    
    # Analysis Options
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Enable verbose logging output.")] = False
):
    """
    Analyze network PCAP files with Zeek-focused ransomware detection:
    
    [bold]Basic Mode[/bold]: Traditional packet analysis with tshark
    
    [bold]Zeek Mode[/bold] (--zeek): Native Zeek integration with ransomware detection:
    • Protocol-based log analysis (DNS, HTTP, SSL, etc.)
    • Custom ransomware pattern detection via Zeek scripting
    • File extraction and analysis with YARA/VirusTotal
    • Cryptocurrency address identification
    • C2 communication analysis and beaconing detection
    • IOC extraction and threat intelligence correlation
    
    Examples:
    
    # Basic analysis with tshark
    shikra network analyze capture.pcap --json-output report.json
    
    # Zeek analysis with ransomware detection (recommended)
    shikra network analyze capture.pcap --json-output report.json --zeek
    
    # Zeek with custom output directory
    shikra network analyze capture.pcap --json-output report.json --zeek --output-dir /tmp/analysis
    """
    
    # Setup logging
    log_level = logging.DEBUG if verbose else logging.INFO
    logger = setup_logger("network_cli", level=log_level)
    
    # Handle API key
    if vt_api_key == "YOUR_VIRUSTOTAL_API_KEY_HERE":
        vt_api_key = None
        logger.info("VirusTotal API key not configured - running without VT integration")
    elif not vt_api_key:
        logger.info("No VirusTotal API key provided - running without VT integration")
    else:
        logger.info("VirusTotal API key configured - threat intelligence enabled")

    # Create output directory if specified
    if output_dir:
        output_dir.mkdir(parents=True, exist_ok=True)
        logger.info(f"Analysis artifacts will be saved to: {output_dir}")

    logger.info(f"Starting network analysis of {pcap_path}")
    logger.info(f"Zeek mode: {zeek}")
    
    try:
        if zeek:
            # Zeek analysis with file reconstruction
            logger.info("Running Zeek analysis with ransomware detection...")
            results = asyncio.run(_run_zeek_analysis(
                pcap_path, output_dir, zeek_path, zeek_scripts, vt_api_key, config_dir
            ))
        else:
            # Basic tshark analysis
            logger.info("Running basic network analysis with tshark...")
            results = _run_basic_analysis(pcap_path, vt_api_key, config_dir, tshark_path)
        
        # Save results
        save_json(results, json_output)
        logger.info(f"Analysis results saved to: {json_output}")
        
        # Display summary
        _display_analysis_summary(results, logger)
        
    except Exception as e:
        logger.error(f"Network analysis failed: {e}", exc_info=True)
        raise typer.Exit(code=1)


async def _run_zeek_analysis(pcap_path: Path, output_dir: Optional[Path],
                           zeek_path: str, zeek_scripts: Optional[List[str]],
                           vt_api_key: Optional[str], config_dir: Path) -> dict:
    """Run Zeek analysis with file reconstruction for ransomware detection."""
    
    if not output_dir:
        output_dir = Path("/tmp/shikra_zeek_analysis")
    
    # Create zeek output directory
    zeek_output_dir = output_dir / "zeek_logs"
    zeek_output_dir.mkdir(parents=True, exist_ok=True)
    
    # Initialize Zeek analyzer
    analyzer = ZeekAnalyzer(zeek_path=zeek_path)
    
    # Run Zeek analysis
    zeek_results = await analyzer.analyze_pcap(pcap_path, zeek_output_dir, zeek_scripts)
    
    # Initialize file reconstructor for extracted files
    if zeek_results and zeek_results.get("files"):
        file_output_dir = output_dir / "extracted_files"
        file_output_dir.mkdir(parents=True, exist_ok=True)
        
        reconstructor = FileReconstructor(
            output_dir=file_output_dir,
            vt_api_key=vt_api_key,
            yara_rules_dir=config_dir.parent / "data" / "yara_rules" if (config_dir.parent / "data" / "yara_rules").exists() else None
        )
        
        # Reconstruct files from Zeek logs
        file_results = await reconstructor.reconstruct_from_zeek_logs(zeek_output_dir)
        zeek_results["file_reconstruction"] = file_results
    
    # Add analysis metadata
    zeek_results["analysis_type"] = "zeek_ransomware_focused"
    zeek_results["zeek_configuration"] = {
        "zeek_path": zeek_path,
        "custom_scripts": zeek_scripts or [],
        "output_directory": str(output_dir),
        "focus": "ransomware_detection"
    }
    
    return zeek_results


def _run_basic_analysis(pcap_path: Path, vt_api_key: Optional[str], 
                       config_dir: Path, tshark_path: str) -> dict:
    """Run basic network analysis with tshark."""
    
    analyzer = NetworkAnalyzer(
        vt_api_key=vt_api_key, 
        config_dir=config_dir,
        tshark_path=tshark_path
    )
    results = analyzer.analyze(pcap_path)
    
    # Add analysis metadata
    results["analysis_type"] = "basic_tshark"
    results["tshark_configuration"] = {
        "tshark_path": tshark_path
    }
    
    return results


def _display_analysis_summary(results: dict, logger):
    """Display analysis summary to user."""
    
    analysis_type = results.get("analysis_type", "unknown")
    
    if analysis_type == "zeek_ransomware_focused":
        risk_assessment = results.get("risk_assessment", {})
        logger.info(f"=== Zeek Ransomware Analysis Summary ===")
        logger.info(f"Risk Level: {risk_assessment.get('risk_level', 'UNKNOWN')}")
        logger.info(f"Risk Score: {risk_assessment.get('risk_score', 0)}")
        logger.info(f"Ransomware Indicators: {len(results.get('ransomware_indicators', []))}")
        logger.info(f"Zeek Notices: {len(results.get('notice_log', []))}")
        logger.info(f"Intel Hits: {len(results.get('intel_log', []))}")
        
        # File reconstruction summary
        file_recon = results.get("file_reconstruction", {})
        if file_recon:
            summary = file_recon.get("analysis_summary", {})
            logger.info(f"Files Extracted: {summary.get('total_files_reconstructed', 0)}")
            logger.info(f"Malicious Files: {summary.get('malware_files_detected', 0)}")
        
    else:
        # Basic analysis
        logger.info(f"=== Basic Network Analysis Summary ===")
        metadata = results.get("metadata", {})
        logger.info(f"Total Packets: {metadata.get('statistics', {}).get('total_packets', 0)}")
        logger.info(f"Unique Flows: {metadata.get('statistics', {}).get('unique_flows', 0)}")
        
        # IOCs from basic analysis
        iocs = results.get("iocs", [])
        if iocs:
            logger.info(f"IOCs Found: {len(iocs)}")


def _combine_intelligence(zeek_results: dict, enhanced_results: dict) -> dict:
    """Combine intelligence from Zeek and enhanced analysis."""
    
    # Extract Zeek entities
    zeek_entities = zeek_results.get("key_entities", {})
    
    # Extract enhanced entities
    enhanced_intel = enhanced_results.get("combined_intelligence", {})
    
    # Merge and deduplicate
    combined = {
        "suspicious_ips": list(set(
            zeek_entities.get("suspicious_ips", []) + 
            enhanced_intel.get("suspicious_ips", [])
        )),
        "suspicious_domains": list(set(
            zeek_entities.get("suspicious_domains", []) + 
            enhanced_intel.get("suspicious_domains", [])
        )),
        "crypto_addresses": list(set(
            zeek_entities.get("crypto_addresses", [])
        )),
        "c2_servers": list(set(
            zeek_entities.get("c2_servers", [])
        )),
        "tor_nodes": list(set(
            zeek_entities.get("tor_nodes", [])
        )),
        "extracted_files": (
            zeek_entities.get("extracted_files", []) + 
            enhanced_intel.get("extracted_files", [])
        ),
        "zeek_indicators": zeek_results.get("ransomware_indicators", []),
        "zeek_notices": zeek_results.get("notice_log", []),
        "intel_hits": zeek_results.get("intel_log", [])
    }
    
    # Add counts
    combined["counts"] = {
        "total_suspicious_ips": len(combined["suspicious_ips"]),
        "total_suspicious_domains": len(combined["suspicious_domains"]),
        "total_crypto_addresses": len(combined["crypto_addresses"]),
        "total_c2_servers": len(combined["c2_servers"]),
        "total_tor_nodes": len(combined["tor_nodes"]),
        "total_extracted_files": len(combined["extracted_files"]),
        "zeek_indicators": len(combined["zeek_indicators"]),
        "zeek_notices": len(combined["zeek_notices"]),
        "intel_hits": len(combined["intel_hits"])
    }
    
    return combined


def _calculate_unified_risk(zeek_results: dict, enhanced_results: dict) -> dict:
    """Calculate unified risk assessment from both analyses."""
    
    zeek_risk = zeek_results.get("risk_assessment", {})
    enhanced_risk = enhanced_results.get("threat_assessment", {})
    
    # Combine risk scores
    zeek_score = zeek_risk.get("risk_score", 0)
    enhanced_score = enhanced_risk.get("overall_risk_score", 0)
    
    # Weight the scores (Zeek is more specialized for ransomware)
    unified_score = (zeek_score * 0.6) + (enhanced_score * 0.4)
    
    # Determine unified risk level
    if unified_score >= 100:
        risk_level = "CRITICAL"
    elif unified_score >= 75:
        risk_level = "HIGH"
    elif unified_score >= 50:
        risk_level = "MEDIUM"
    elif unified_score >= 25:
        risk_level = "LOW"
    else:
        risk_level = "MINIMAL"
    
    return {
        "unified_risk_score": unified_score,
        "unified_risk_level": risk_level,
        "component_scores": {
            "zeek_score": zeek_score,
            "enhanced_score": enhanced_score
        },
        "risk_factors": (
            zeek_risk.get("risk_factors", []) + 
            enhanced_risk.get("risk_factors", [])
        )
    }


def _display_analysis_summary(results: dict, logger):
    """Display analysis summary to user."""
    
    analysis_type = results.get("analysis_type", "unknown")
    
    if analysis_type == "zeek_native":
        risk_assessment = results.get("risk_assessment", {})
        logger.info(f"=== Zeek Native Analysis Summary ===")
        logger.info(f"Risk Level: {risk_assessment.get('risk_level', 'UNKNOWN')}")
        logger.info(f"Risk Score: {risk_assessment.get('risk_score', 0)}")
        logger.info(f"Ransomware Indicators: {len(results.get('ransomware_indicators', []))}")
        logger.info(f"Zeek Notices: {len(results.get('notice_log', []))}")
        logger.info(f"Intel Hits: {len(results.get('intel_log', []))}")
        
    elif analysis_type == "enhanced":
        threat_assessment = results.get("threat_assessment", {})
        logger.info(f"=== Enhanced Analysis Summary ===")
        logger.info(f"Threat Level: {threat_assessment.get('risk_level', 'UNKNOWN')}")
        logger.info(f"Risk Score: {threat_assessment.get('overall_risk_score', 0):.1f}/10")
        intelligence = results.get("combined_intelligence", {})
        if intelligence:
            logger.info(f"Extracted Files: {intelligence.get('extracted_files_count', 0)}")
            logger.info(f"Malicious Files: {intelligence.get('malicious_files_count', 0)}")
        
    elif analysis_type == "combined_zeek_enhanced":
        unified_risk = results.get("unified_risk_assessment", {})
        combined_intel = results.get("combined_intelligence", {})
        logger.info(f"=== Combined Zeek + Enhanced Analysis Summary ===")
        logger.info(f"Unified Risk Level: {unified_risk.get('unified_risk_level', 'UNKNOWN')}")
        logger.info(f"Unified Risk Score: {unified_risk.get('unified_risk_score', 0):.1f}")
        logger.info(f"Total Indicators: {combined_intel.get('counts', {}).get('zeek_indicators', 0)}")
        logger.info(f"Total Notices: {combined_intel.get('counts', {}).get('zeek_notices', 0)}")
        logger.info(f"Suspicious IPs: {combined_intel.get('counts', {}).get('total_suspicious_ips', 0)}")
        logger.info(f"Extracted Files: {combined_intel.get('counts', {}).get('total_extracted_files', 0)}")
        
    else:
        # Basic analysis
        logger.info(f"=== Basic Analysis Summary ===")
        stats = results.get("statistics", {})
        logger.info(f"Total Connections: {stats.get('total_connections', 0)}")
        logger.info(f"Suspicious Connections: {stats.get('suspicious_connections', 0)}")


@app.command()
def render(
    json_report_path: Annotated[Path, typer.Argument(..., help="Path to the network analysis JSON report.", exists=True, readable=True)],
    html_output: Annotated[Path, typer.Option("--html", help="Path to save the HTML report.")],
    pdf_output: Annotated[Optional[Path], typer.Option("--pdf", help="Path to save the PDF report.")] = None,
    template_dir: Annotated[Path, typer.Option(help="Directory containing Jinja2 templates.")] = Path("templates")
):
    """
    Render a network analysis JSON report into HTML and/or PDF format.
    """
    logger = setup_logger("network_render_cli")
    logger.info(f"Rendering network report from {json_report_path}...")

    try:
        renderer = NetworkReportRenderer(template_dir=str(template_dir))
        
        if html_output:
            renderer.render_html_from_file(json_report_path, html_output)
            logger.info(f"HTML report saved to: {html_output}")
        
        if pdf_output:
            renderer.render_pdf_from_file(json_report_path, pdf_output)
            logger.info(f"PDF report saved to: {pdf_output}")
            
    except Exception as e:
        logger.error(f"Failed to render network report: {e}", exc_info=True)
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
