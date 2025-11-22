from pathlib import Path
import jinja2
from weasyprint import HTML
from typing import Dict, Any
import logging

from ..utils.logger import setup_logger
from ..utils.jsonio import load_json

class CombinedReportRenderer:
    """
    Renders the final, combined analysis report into HTML and PDF.
    """
    def __init__(self, template_dir: str = "templates"):
        self.template_dir = Path(template_dir)
        self.logger = setup_logger("CombinedReportRenderer")
        
        try:
            self.env = jinja2.Environment(
                loader=jinja2.FileSystemLoader(self.template_dir),
                autoescape=jinja2.select_autoescape(['html', 'xml'])
            )
        except Exception as e:
            self.logger.error(f"Failed to initialize Jinja2 environment from {template_dir}: {e}")
            raise
            
    def render_html(self, combined_report_path: Path, output_path: Path):
        """Renders the combined report to a single HTML file."""
        self.logger.info(f"Rendering combined HTML report to {output_path}")
        try:
            report = load_json(combined_report_path)
            template = self.env.get_template("combined_report.html.j2")
            html_content = template.render(report=report)
            
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            self.logger.info(f"Combined HTML report successfully generated at {output_path}")
        except jinja2.TemplateNotFound:
            self.logger.error(f"Template 'combined_report.html.j2' not found in {self.template_dir}")
            raise
        except Exception as e:
            self.logger.error(f"An error occurred during combined HTML rendering: {e}", exc_info=True)
            raise

    def render_pdf(self, combined_report_path: Path, output_path: Path):
        """Renders the combined report to a single PDF file."""
        self.logger.info(f"Rendering combined PDF report to {output_path}")
        try:
            report = load_json(combined_report_path)
            template = self.env.get_template("combined_report.html.j2")
            html_content = template.render(report=report)
            
            HTML(string=html_content, base_url=str(self.template_dir)).write_pdf(output_path)
            self.logger.info(f"Combined PDF report successfully generated at {output_path}")
        except jinja2.TemplateNotFound:
            self.logger.error(f"Template 'combined_report.html.j2' not found in {self.template_dir}")
            raise
        except Exception as e:
            self.logger.error(f"An error occurred during combined PDF rendering: {e}", exc_info=True)
            raise
