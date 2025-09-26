import typer
from typing_extensions import Annotated
from pathlib import Path
import logging
import asyncio
from typing import Optional

from .analyse import ProcmonAnalyzer
from .render import ReportRenderer
from ...utils.logger import setup_logger
from ...utils.jsonio import save_json
from ...utils.vt import VT_API_KEY

app = typer.Typer(name="procmon", help="Analyze Procmon CSV logs for ransomware behavior.")

@app.command()
def analyze(
    csv_path: Annotated[Path, typer.Argument(..., help="Path to the Procmon CSV log file.", exists=True, readable=True)],
    json_output: Annotated[Path, typer.Option("--json-output", help="Path to save the JSON analysis report.")],
    vt_api_key: Annotated[Optional[str], typer.Option(help="VirusTotal API key. If not provided, enrichment is skipped.")] = None,
    config_dir: Annotated[Path, typer.Option(help="Path to the configuration directory.")] = Path("config")
):
    """
    Parse a Procmon CSV log, analyze it for suspicious behavior, and save the results to a JSON file.
    """
    logger = setup_logger("procmon_cli")
    
    # --- FIX: Removed the mandatory check for the VT API key. ---
    # The ProcmonAnalyzer class now handles the optional nature of the key.
    # We will pass the key (or None) directly to it.
    
    logger.info(f"Starting analysis of {csv_path}...")
    
    try:
        # Pass the (now optional) API key to the analyzer
        analyzer = ProcmonAnalyzer(vt_api_key=vt_api_key, config_dir=config_dir)
        
        # Run the async analysis function
        report = asyncio.run(analyzer.analyze(csv_path))
        
        save_json(report, json_output)
        logger.info(f"Analysis complete. JSON report saved to {json_output}")
    except FileNotFoundError as e:
        logger.error(f"A required file was not found: {e}")
        raise typer.Exit(code=1)
    except Exception as e:
        logger.error(f"An unexpected error occurred during analysis: {e}", exc_info=True)
        raise typer.Exit(code=1)

@app.command()
def render(
    json_report_path: Annotated[Path, typer.Argument(..., help="Path to the analysis JSON report.", exists=True, readable=True)],
    html_output: Annotated[Path, typer.Option("--html", help="Path to save the HTML report.")],
    pdf_output: Annotated[Path, typer.Option("--pdf", help="Path to save the PDF report.")] = None,
    template_dir: Annotated[Path, typer.Option(help="Directory containing Jinja2 templates.")] = Path("templates")
):
    """
    Render a JSON analysis report into a human-readable HTML and/or PDF file.
    """
    logger = setup_logger("procmon_render_cli")
    logger.info(f"Rendering report from {json_report_path}...")

    try:
        renderer = ReportRenderer(template_dir=str(template_dir))
        
        if html_output:
            renderer.render_html_from_file(json_report_path, html_output)
        
        if pdf_output:
            renderer.render_pdf_from_file(json_report_path, pdf_output)
            
    except Exception as e:
        logger.error(f"Failed to render report: {e}", exc_info=True)
        raise typer.Exit(code=1)

if __name__ == "__main__":
    app()
