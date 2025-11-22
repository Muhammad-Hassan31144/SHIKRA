import typer
from typing_extensions import Annotated
from typing import Optional
from pathlib import Path
import logging

# Note: We are importing the cli modules themselves, not the analyzer classes.
# This keeps the main CLI clean and delegates logic to the sub-commands.
from .analysis.procmon import cli as procmon_cli
from .analysis.memory import cli as memory_cli
from .analysis.network import cli as network_cli
from .analysis.disk import cli as disk_cli
from .analysis import cli as analysis_cli
from .engage import cli as engage_cli
from .hunt import cli as hunt_cli
from .timeline import cli as timeline_cli
from . import combine
from .render import overview as render_overview
from .export import ioc as export_ioc, timesketch as export_timesketch
from .utils.logger import setup_logger
from .utils.jsonio import load_json, save_json



# --- FIX: Restore clean UI and move examples to a dedicated command ---
app = typer.Typer(
    name="Shikra",
    help="[bold]Shikra[/bold]: A modular toolkit for ransomware behavior analysis.",
    rich_markup_mode="markdown",
    context_settings={"help_option_names": ["-h", "--help"]},
    add_completion=False,
    no_args_is_help=True
)

# Add sub-commands from other modules with more descriptive help text
app.add_typer(procmon_cli.app, name="procmon", help="Analyze Procmon CSV logs.")
app.add_typer(memory_cli.app, name="memory", help="Analyze memory dumps using Volatility 3.")
app.add_typer(network_cli.app, name="network", help="Analyze network PCAP files.")
app.add_typer(disk_cli.app, name="disk", help="Analyze disk images for ransomware behavior.")
app.add_typer(analysis_cli.app, name="analysis", help="Analysis modules for comprehensive malware forensics.")
app.add_typer(engage_cli.app, name="engage", help="🚀 Enhanced malware analysis with commercial-grade evasion detection and behavioral monitoring.")
app.add_typer(hunt_cli.app, name="hunt", help="Threat hunting and static analysis for malware samples.")

@app.command(
    help="Combine analysis reports from multiple SHIKRA modules into a comprehensive assessment."
)
def combine_reports(
    output_path: Annotated[Path, typer.Option("--output", help="Path for the combined JSON output.", rich_help_panel="Output")],
    procmon_report_path: Annotated[Optional[Path], typer.Option("--procmon-report", help="Path to Procmon JSON report.", exists=True, readable=True, rich_help_panel="Input Reports")] = None,
    memory_report_path: Annotated[Optional[Path], typer.Option("--memory-report", help="Path to Memory JSON report.", exists=True, readable=True, rich_help_panel="Input Reports")] = None,
    network_report_path: Annotated[Optional[Path], typer.Option("--network-report", help="Path to Network JSON report.", exists=True, readable=True, rich_help_panel="Input Reports")] = None,
    disk_report_path: Annotated[Optional[Path], typer.Option("--disk-report", help="Path to Disk analysis JSON report.", exists=True, readable=True, rich_help_panel="Input Reports")] = None,
    
    timeline_report_path: Annotated[Optional[Path], typer.Option("--timeline-report", help="Path to Timeline correlation JSON report.", exists=True, readable=True, rich_help_panel="Input Reports")] = None,
    config_dir: Annotated[Path, typer.Option("--config", help="Configuration directory.")] = Path("config")
):
    """
    Combine analysis reports from multiple SHIKRA modules into a single comprehensive assessment.
    At least one analysis report must be provided.
    """
    logger = setup_logger("shikra_combiner")
    logger.info("Starting comprehensive SHIKRA report combination...")
    
    # Validate that at least one report is provided
    reports_provided = [procmon_report_path, memory_report_path, network_report_path, 
                       disk_report_path, timeline_report_path]
    if not any(reports_provided):
        logger.error("At least one analysis report must be provided")
        raise typer.Exit(code=1)
    
    # Log which modules are being combined
    modules_to_combine = []
    if procmon_report_path: modules_to_combine.append("procmon")
    if memory_report_path: modules_to_combine.append("memory") 
    if network_report_path: modules_to_combine.append("network")
    if disk_report_path: modules_to_combine.append("disk")
    if timeline_report_path: modules_to_combine.append("timeline")
    
    logger.info(f"Combining reports from modules: {', '.join(modules_to_combine)}")
    
    try:
        combiner = combine.ReportCombiner(config_dir=config_dir)
        combined_report = combiner.combine(
            procmon_path=procmon_report_path,
            memory_path=memory_report_path,
            network_path=network_report_path,
            disk_path=disk_report_path,
            timeline_path=timeline_report_path
        )
        
        save_json(combined_report, output_path)
        logger.info(f"Successfully combined reports and saved to {output_path}")
        
        # Display summary
        threat_assessment = combined_report.get("threat_assessment", {})
        logger.info(f"Overall Risk Level: {threat_assessment.get('risk_level', 'unknown')}")
        logger.info(f"Risk Score: {threat_assessment.get('overall_risk_score', 0):.2f}/10")
        logger.info(f"Confidence Score: {threat_assessment.get('confidence_score', 0):.2f}/10")
        
        # Display key findings
        reporting = combined_report.get("reporting", {})
        executive_summary = reporting.get("executive_summary", {})
        key_findings = executive_summary.get("key_findings", [])
        if key_findings:
            logger.info("Key Findings:")
            for finding in key_findings[:3]:  # Show top 3 findings
                logger.info(f"  - {finding}")
                
    except Exception as e:
        logger.error(f"Failed to combine reports: {e}", exc_info=True)
        raise typer.Exit(code=1)

# Create a new typer app for rendering
render_app = typer.Typer(name="render", help="Render final reports from combined data.", no_args_is_help=True)
app.add_typer(render_app)

@render_app.command("overview", help="Render a final, combined report in HTML and/or PDF format.")
def render_combined_report(
    combined_report_path: Annotated[Path, typer.Argument(..., help="Path to the combined JSON report.", exists=True, readable=True)],
    html_output: Annotated[Path, typer.Option("--html", help="Path for the final HTML report output.")],
    pdf_output: Annotated[Optional[Path], typer.Option("--pdf", help="Path for the final PDF report output.")] = None,
    template_dir: Annotated[Path, typer.Option(help="Directory containing Jinja2 templates.")] = Path("templates")
):
    logger = setup_logger("combined_renderer")
    logger.info(f"Rendering report from {combined_report_path}")
    
    renderer = render_overview.CombinedReportRenderer(template_dir=str(template_dir))
    
    if html_output:
        try:
            renderer.render_html(combined_report_path, html_output)
        except Exception as e:
            logger.error(f"Failed to render HTML report: {e}", exc_info=True)
            raise typer.Exit(code=1)
            
    if pdf_output:
        try:
            renderer.render_pdf(combined_report_path, pdf_output)
        except Exception as e:
            logger.error(f"Failed to render PDF report: {e}", exc_info=True)
            raise typer.Exit(code=1)
            
    logger.info("Report rendering complete.")


# Create a new typer app for exporting
export_app = typer.Typer(name="export", help="Export Indicators of Compromise (IOCs) and timelines.", no_args_is_help=True)
app.add_typer(export_app)

@export_app.command("ioc", help="Export IOCs (YARA, Sigma, etc.) from a combined report.")
def export_iocs(
    combined_report_path: Annotated[Path, typer.Argument(..., help="Path to the combined JSON report.", exists=True, readable=True)],
    output_dir: Annotated[Path, typer.Option("--output-dir", help="Directory to save exported IOC files.")]
):
    logger = setup_logger("ioc_exporter")
    logger.info(f"Exporting IOCs from {combined_report_path} to {output_dir}")
    
    try:
        exporter = export_ioc.IOCExporter()
        exporter.export(combined_report_path, output_dir)
    except Exception as e:
        logger.error(f"Failed to export IOCs: {e}", exc_info=True)
        raise typer.Exit(code=1)

@export_app.command("timesketch", help="Export the combined timeline to a Timesketch-compatible CSV file.")
def export_to_timesketch(
    combined_report_path: Annotated[Path, typer.Argument(..., help="Path to the combined JSON report.", exists=True, readable=True)],
    output_path: Annotated[Path, typer.Option("--output", help="Path for the Timesketch CSV output.")]
):
    logger = setup_logger("timesketch_exporter")
    logger.info(f"Exporting timeline from {combined_report_path} to {output_path}")
    
    try:
        exporter = export_timesketch.TimesketchExporter()
        exporter.export(combined_report_path, output_path)
    except Exception as e:
        logger.error(f"Failed to export for Timesketch: {e}", exc_info=True)
        raise typer.Exit(code=1)

# --- FIX: Create a dedicated command to show examples ---
@app.command(name="examples", help="Show detailed examples of a full analysis workflow.")
def show_examples():
    """
    Prints a beautifully formatted guide on how to use ransomkit for a full analysis.
    """
    from rich.console import Console
    from rich.panel import Panel
    from rich.text import Text

    console = Console()

    # Create a panel with a title and border style
    panel_content = Text()
    panel_content.append("1. Analyze individual artifacts first:\n", style="bold")
    panel_content.append("   # First, analyze the Procmon CSV log\n", style="dim")
    panel_content.append("   $ ransomkit procmon analyze C:\\captures\\procmon.csv --json-output procmon.json\n\n", style="green")
    panel_content.append("   # Next, analyze the memory dump\n", style="dim")
    panel_content.append("   $ ransomkit memory analyze C:\\captures\\memdump.raw --json-output memory.json\n\n", style="green")
    panel_content.append("   # Finally, analyze the network capture\n", style="dim")
    panel_content.append("   $ ransomkit network analyze C:\\captures\\net.pcap --json-output network.json\n\n", style="green")

    panel_content.append("2. Combine the results into a single master report:\n", style="bold")
    panel_content.append("   $ ransomkit combine-reports --procmon-report procmon.json --memory-report memory.json --network-report network.json --output combined.json\n\n", style="green")

    panel_content.append("3. Render the final HTML/PDF report:\n", style="bold")
    panel_content.append("   $ ransomkit render overview combined.json --html final_report.html --pdf final_report.pdf\n\n", style="green")
    
    panel_content.append("4. Export IOCs for your security tools:\n", style="bold")
    panel_content.append("   $ ransomkit export ioc combined.json --output-dir ./iocs\n", style="green")

    console.print(
        Panel(
            panel_content,
            title="[bold cyan]Full Analysis Workflow Example[/bold cyan]",
            border_style="blue",
            expand=False
        )
    )
# --- END FIX ---

if __name__ == "__main__":
    app()
