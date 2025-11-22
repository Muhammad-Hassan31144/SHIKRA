import typer
from typing_extensions import Annotated
from pathlib import Path
import logging
import asyncio
from typing import Optional

from .analyse import DiskAnalyzer
from .render import DiskReportRenderer
from ...utils.logger import setup_logger
from ...utils.jsonio import save_json

app = typer.Typer(name="disk", help="Analyze disk images for ransomware behavior using QCOW2 snapshot comparison and virt-diff.")

@app.command()
def analyze(
    before_disk: Annotated[Path, typer.Argument(..., help="Path to the 'before' disk image (baseline snapshot).", exists=True, readable=True)],
    after_disk: Annotated[Path, typer.Argument(..., help="Path to the 'after' disk image (post-infection snapshot).", exists=True, readable=True)],
    json_output: Annotated[Path, typer.Option("--json-output", help="Path to save the JSON analysis report.")],
    vt_api_key: Annotated[Optional[str], typer.Option(help="VirusTotal API key for enriching file hashes.")] = None,
    config_dir: Annotated[Path, typer.Option(help="Path to the configuration directory.")] = Path("config"),
    output_dir: Annotated[Optional[Path], typer.Option("--output-dir", help="Directory to save analysis artifacts and temporary files.")] = None,
    
    # Tool paths for libguestfs and virt-diff
    virt_diff_path: Annotated[str, typer.Option(help="Path to virt-diff binary.")] = "virt-diff",
    guestmount_path: Annotated[str, typer.Option(help="Path to guestmount binary.")] = "guestmount", 
    guestunmount_path: Annotated[str, typer.Option(help="Path to guestunmount binary.")] = "guestunmount",
    qemu_img_path: Annotated[str, typer.Option(help="Path to qemu-img binary.")] = "qemu-img",
    
    # Analysis options
    analysis_id: Annotated[Optional[str], typer.Option(help="Custom analysis identifier for reports.")] = None,
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Enable verbose logging output.")] = False
):
    """
    Analyze disk images to detect ransomware activity by comparing before/after snapshots.
    
    This command performs comprehensive disk analysis including:
    
    [bold]QCOW2 Snapshot Comparison[/bold]: Uses virt-diff to identify high-level changes
    
    [bold]File System Analysis[/bold]: Mounts disk images using libguestfs to analyze:
    • Files added, removed, or modified
    • Mass file encryption detection
    • Ransom note identification
    • Suspicious file extensions
    • Registry changes (Windows)
    
    [bold]Ransomware Detection[/bold]: Identifies specific indicators:
    • Cryptocurrency addresses in ransom notes
    • Mass file encryption patterns
    • Dropped executables
    • High entropy files (potential encryption)
    • Registry persistence mechanisms
    
    [bold]File Hash Analysis[/bold]: Calculates MD5, SHA1, and SHA256 hashes for changed files
    
    Examples:
    
    # Basic disk comparison
    ransomkit disk analyze before.qcow2 after.qcow2 --json-output report.json
    
    # With VirusTotal enrichment
    ransomkit disk analyze before.qcow2 after.qcow2 --json-output report.json --vt-api-key YOUR_KEY
    
    # Custom output directory and analysis ID
    ransomkit disk analyze before.qcow2 after.qcow2 --json-output report.json --output-dir /tmp/analysis --analysis-id infection_test_001
    
    # Verbose logging with custom tool paths
    ransomkit disk analyze before.qcow2 after.qcow2 --json-output report.json --verbose --virt-diff-path /usr/local/bin/virt-diff
    """
    
    # Setup logging
    log_level = logging.DEBUG if verbose else logging.INFO
    logger = setup_logger("disk_cli", level=log_level)
    
    # Handle API key
    if vt_api_key == "YOUR_VIRUSTOTAL_API_KEY_HERE":
        vt_api_key = None
        logger.info("VirusTotal API key not configured - running without VT integration")
    elif not vt_api_key:
        logger.info("No VirusTotal API key provided - running without VT integration")
    else:
        logger.info("VirusTotal API key configured - file hash enrichment enabled")

    # Create output directory if specified
    if output_dir:
        output_dir.mkdir(parents=True, exist_ok=True)
        logger.info(f"Analysis artifacts will be saved to: {output_dir}")

    logger.info(f"Starting disk analysis comparison")
    logger.info(f"Before disk: {before_disk}")
    logger.info(f"After disk: {after_disk}")
    
    try:
        analyzer = DiskAnalyzer(
            vt_api_key=vt_api_key,
            config_dir=config_dir,
            output_dir=str(output_dir) if output_dir else None,
            virt_diff_path=virt_diff_path,
            guestmount_path=guestmount_path,
            guestunmount_path=guestunmount_path,
            qemu_img_path=qemu_img_path
        )
        
        # The analyze method is async due to potential VT lookups and file operations
        report = asyncio.run(analyzer.analyze(before_disk, after_disk, analysis_id))
        
        save_json(report, json_output)
        logger.info(f"Disk analysis complete. JSON report saved to {json_output}")
        
        # Display summary
        _display_analysis_summary(report, logger)
        
    except FileNotFoundError as e:
        logger.error(f"Required file not found: {e}")
        raise typer.Exit(code=1)
    except Exception as e:
        logger.error(f"Disk analysis failed: {e}", exc_info=True)
        raise typer.Exit(code=1)


def _display_analysis_summary(results: dict, logger):
    """Display disk analysis summary to user."""
    
    # Basic statistics
    statistics = results.get("statistics", {})
    logger.info(f"=== Disk Analysis Summary ===")
    logger.info(f"Total Files Changed: {statistics.get('total_files_changed', 0)}")
    logger.info(f"Files Added: {statistics.get('files_added', 0)}")
    logger.info(f"Files Removed: {statistics.get('files_removed', 0)}")
    logger.info(f"Files Modified: {statistics.get('files_modified', 0)}")
    
    # Registry changes
    registry_changes = results.get("registry_changes", {})
    if registry_changes.get("changes_detected"):
        logger.info(f"Registry Changes: {statistics.get('registry_changes', 0)}")
    
    # Ransomware indicators
    indicators = results.get("ransomware_indicators", [])
    if indicators:
        logger.info(f"Ransomware Indicators: {len(indicators)}")
        
        # Show critical indicators
        critical_indicators = [i for i in indicators if i.get("severity") == "critical"]
        if critical_indicators:
            logger.warning(f"CRITICAL INDICATORS DETECTED: {len(critical_indicators)}")
            for indicator in critical_indicators[:3]:  # Show first 3
                logger.warning(f"  - {indicator.get('description', 'Unknown')}")
    
    # Suspicious activity
    logger.info(f"Encrypted Files Detected: {statistics.get('encrypted_files_detected', 0)}")
    logger.info(f"Ransom Notes Found: {statistics.get('ransom_notes_found', 0)}")
    
    # Risk assessment
    risk_assessment = results.get("risk_assessment", {})
    risk_level = risk_assessment.get("risk_level", "UNKNOWN")
    risk_score = risk_assessment.get("risk_score", 0)
    
    logger.info(f"Risk Level: {risk_level}")
    logger.info(f"Risk Score: {risk_score}/100")
    
    # Risk factors
    risk_factors = risk_assessment.get("risk_factors", [])
    if risk_factors:
        logger.info("Key Risk Factors:")
        for factor in risk_factors[:5]:  # Show first 5
            logger.info(f"  - {factor}")


@app.command()
def render(
    json_report_path: Annotated[Path, typer.Argument(..., help="Path to the disk analysis JSON report.", exists=True, readable=True)],
    html_output: Annotated[Path, typer.Option("--html", help="Path to save the HTML report.")],
    pdf_output: Annotated[Optional[Path], typer.Option("--pdf", help="Path to save the PDF report.")] = None,
    template_dir: Annotated[Path, typer.Option(help="Directory containing Jinja2 templates.")] = Path("templates")
):
    """
    Render a disk analysis JSON report into a human-readable HTML and/or PDF file.
    
    The rendered report includes:
    • Executive summary with risk assessment
    • Detailed file system changes
    • Ransomware indicators and evidence
    • Registry modifications (Windows)
    • File hash analysis and VirusTotal results
    • Timeline of detected changes
    """
    logger = setup_logger("disk_render_cli")
    logger.info(f"Rendering disk analysis report from {json_report_path}...")

    try:
        renderer = DiskReportRenderer(template_dir=str(template_dir))
        
        if html_output:
            renderer.render_html_from_file(json_report_path, html_output)
            logger.info(f"HTML report saved to: {html_output}")
        
        if pdf_output:
            renderer.render_pdf_from_file(json_report_path, pdf_output)
            logger.info(f"PDF report saved to: {pdf_output}")
            
    except Exception as e:
        logger.error(f"Failed to render disk report: {e}", exc_info=True)
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
