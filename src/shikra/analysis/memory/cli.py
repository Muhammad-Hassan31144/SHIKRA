import typer
from typing_extensions import Annotated
from pathlib import Path
import logging
from typing import Optional
import asyncio

from .analyse import MemoryAnalyzer
from .render import MemoryReportRenderer
from ...utils.logger import setup_logger
from ...utils.jsonio import save_json

app = typer.Typer(name="memory", help="Analyze memory dumps for ransomware behavior using Volatility 3.")

@app.command()
def analyze(
    memory_path: Annotated[Path, typer.Argument(..., help="Path to the memory dump file (e.g., .raw, .vmem).", exists=True, readable=True)],
    json_output: Annotated[Path, typer.Option("--json-output", help="Path to save the JSON analysis report.")],
    vt_api_key: Annotated[Optional[str], typer.Option(help="VirusTotal API key for enriching carved files.")] = None,
    config_dir: Annotated[Path, typer.Option(help="Path to the configuration directory.")] = Path("config"),
    optimize: Annotated[bool, typer.Option("--optimize", help="Enable output optimization to filter and prioritize malicious/suspicious entries.")] = True,
    add_on: Annotated[Optional[Path], typer.Option("--add-on", help="Path to additional plugins configuration file (.shikra format).")] = None
):
    """
    Analyze a memory dump with Volatility 3, carve files, and save the results to a JSON file.
    """
    logger = setup_logger("memory_cli")
    
    logger.info(f"Starting memory analysis of {memory_path}...")
    
    try:
        # Set up addon plugins file path with default
        addon_plugins_file = str(add_on) if add_on else None
        
        analyzer = MemoryAnalyzer(
            vt_api_key=vt_api_key, 
            config_dir=config_dir,
            optimize_output=optimize,
            addon_plugins_file=addon_plugins_file
        )
        # The analyze method is async due to potential VT lookups for carved files
        report = asyncio.run(analyzer.analyze(memory_path))
        
        save_json(report, json_output)
        logger.info(f"Memory analysis complete. JSON report saved to {json_output}")
        if optimize:
            logger.info("Output was optimized to prioritize malicious/suspicious entries.")
        else:
            logger.info("Full JSON output provided (no optimization applied).")
    except FileNotFoundError as e:
        logger.error(f"A required file was not found: {e}")
        raise typer.Exit(code=1)
    except Exception as e:
        logger.error(f"An unexpected error occurred during memory analysis: {e}", exc_info=True)
        raise typer.Exit(code=1)

@app.command()
def render(
    json_report_path: Annotated[Path, typer.Argument(..., help="Path to the memory analysis JSON report.", exists=True, readable=True)],
    html_output: Annotated[Path, typer.Option("--html", help="Path to save the HTML report.")],
    pdf_output: Annotated[Path, typer.Option("--pdf", help="Path to save the PDF report.")] = None,
    template_dir: Annotated[Path, typer.Option(help="Directory containing Jinja2 templates.")] = Path("templates")
):
    """
    Render a memory analysis JSON report into a human-readable HTML and/or PDF file.
    """
    logger = setup_logger("memory_render_cli")
    logger.info(f"Rendering memory report from {json_report_path}...")

    try:
        renderer = MemoryReportRenderer(template_dir=str(template_dir))
        
        if html_output:
            renderer.render_html_from_file(json_report_path, html_output)
        
        if pdf_output:
            renderer.render_pdf_from_file(json_report_path, pdf_output)
            
    except Exception as e:
        logger.error(f"Failed to render memory report: {e}", exc_info=True)
        raise typer.Exit(code=1)

if __name__ == "__main__":
    app()
