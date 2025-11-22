from pathlib import Path
import jinja2
from weasyprint import HTML
from typing import Dict, Any
import logging
from datetime import datetime

from ...utils.logger import setup_logger
from ...utils.jsonio import load_json

class MemoryReportRenderer:
    """
    Renders a memory analysis JSON report into HTML and PDF formats.
    """
    def __init__(self, template_dir: str = "templates"):
        self.logger = setup_logger("MemoryReportRenderer")
        
        base_path = Path(__file__).parent.parent 
        absolute_template_dir = base_path / template_dir
        
        if not absolute_template_dir.exists():
            project_root = base_path.parent.parent
            absolute_template_dir = project_root / template_dir
            if not absolute_template_dir.exists():
                 raise FileNotFoundError(f"Templates directory not found at expected paths.")

        self.template_dir = absolute_template_dir
        
        try:
            self.env = jinja2.Environment(
                loader=jinja2.FileSystemLoader(self.template_dir),
                autoescape=jinja2.select_autoescape(['html', 'xml'])
            )
            
            def datetimeformat(value, format='%Y-%m-%d %H:%M:%S'):
                if not isinstance(value, str):
                    return value
                try:
                    dt_obj = datetime.fromisoformat(value)
                    return dt_obj.strftime(format)
                except (ValueError, TypeError):
                    return value
            
            self.env.filters['datetimeformat'] = datetimeformat

        except Exception as e:
            self.logger.error(f"Failed to initialize Jinja2 environment from {self.template_dir}: {e}")
            raise
            
    def render_html(self, report: Dict[str, Any], output_path: Path):
        """Renders the given report data to an HTML file."""
        self.logger.info(f"Rendering memory HTML report to {output_path}")
        try:
            template = self.env.get_template("memory_report.html.j2")
            html_content = template.render(report=report)
            
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            self.logger.info(f"HTML report successfully generated at {output_path}")
        except jinja2.TemplateNotFound:
            self.logger.error(f"Template 'memory_report.html.j2' not found in {self.template_dir}")
            raise
        except Exception as e:
            self.logger.error(f"An error occurred during HTML rendering: {e}", exc_info=True)
            raise

    def render_pdf(self, report: Dict[str, Any], output_path: Path):
        """Renders the given report data to a PDF file."""
        self.logger.info(f"Rendering memory PDF report to {output_path}")
        try:
            template = self.env.get_template("memory_report.html.j2")
            html_content = template.render(report=report)
            
            HTML(string=html_content, base_url=str(self.template_dir)).write_pdf(output_path)
            self.logger.info(f"PDF report successfully generated at {output_path}")
        except jinja2.TemplateNotFound:
            self.logger.error(f"Template 'memory_report.html.j2' not found in {self.template_dir}")
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
