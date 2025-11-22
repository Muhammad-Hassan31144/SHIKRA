from pathlib import Path
import jinja2
from weasyprint import HTML
from typing import Dict, Any
import logging

from ...utils.logger import setup_logger
from ...utils.jsonio import load_json

class NetworkReportRenderer:
    """
    Renders a network analysis JSON report into HTML and PDF formats.
    """
    def __init__(self, template_dir: str = "templates"):
        self.template_dir = Path(template_dir)
        self.logger = setup_logger("NetworkReportRenderer")
        
        try:
            self.env = jinja2.Environment(
                loader=jinja2.FileSystemLoader(self.template_dir),
                autoescape=jinja2.select_autoescape(['html', 'xml'])
            )
        except Exception as e:
            self.logger.error(f"Failed to initialize Jinja2 environment from {template_dir}: {e}")
            raise
            
    def render_html(self, report: Dict[str, Any], output_path: Path):
        """Renders the given report data to an HTML file."""
        self.logger.info(f"Rendering network HTML report to {output_path}")
        try:
            template = self.env.get_template("network_report.html.j2")
            html_content = template.render(report=report)
            
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            self.logger.info(f"HTML report successfully generated at {output_path}")
        except jinja2.TemplateNotFound:
            self.logger.error(f"Template 'network_report.html.j2' not found in {self.template_dir}")
            raise
        except Exception as e:
            self.logger.error(f"An error occurred during HTML rendering: {e}", exc_info=True)
            raise

    def render_pdf(self, report: Dict[str, Any], output_path: Path):
        """Renders the given report data to a PDF file."""
        self.logger.info(f"Rendering network PDF report to {output_path}")
        try:
            template = self.env.get_template("network_report.html.j2")
            html_content = template.render(report=report)
            
            HTML(string=html_content, base_url=str(self.template_dir)).write_pdf(output_path)
            self.logger.info(f"PDF report successfully generated at {output_path}")
        except jinja2.TemplateNotFound:
            self.logger.error(f"Template 'network_report.html.j2' not found in {self.template_dir}")
            raise
        except Exception as e:
            self.logger.error(f"An error occurred during PDF rendering: {e}", exc_info=True)
            raise

    def render_html_from_file(self, json_path: Path, output_path: Path):
        """Loads a JSON report from a file and renders it to HTML."""
        report = load_json(json_path)
        self.render_html(report, output_path)

    def render_pdf_from_file(self, json_path: Path, output_path: Path):
        """Loads a JSON report from a file and renders it to PDF."""
        report = load_json(json_path)
        self.render_pdf(report, output_path)
