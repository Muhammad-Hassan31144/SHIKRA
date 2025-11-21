import csv
from pathlib import Path
from typing import Dict, Any, List
import logging

from ..utils.logger import setup_logger
from ..utils.jsonio import load_json

class TimesketchExporter:
    """
    Exports the combined event timeline to a CSV format compatible
    with Timesketch for advanced timeline analysis.
    """
    def __init__(self):
        self.logger = setup_logger("TimesketchExporter")

    def export(self, combined_path: Path, output_path: Path):
        """
        Writes the timeline data to a CSV file.
        """
        self.logger.info(f"Exporting timeline to Timesketch CSV at {output_path}")
        combined = load_json(combined_path)
        timeline = combined.get("summary", {}).get("timeline", [])
        
        if not timeline:
            self.logger.warning("No timeline data found in the report. Skipping export.")
            return

        try:
            with open(output_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                # Write header
                writer.writerow(["datetime", "timestamp_desc", "message", "source", "tag"])
                
                # Write events
                for event in timeline:
                    writer.writerow([
                        event.get("timestamp"),
                        "RansomKit Event",
                        event.get("event"),
                        event.get("source"),
                        "ransomware_analysis" # A generic tag
                    ])
            self.logger.info("Timesketch CSV export complete.")
        except IOError as e:
            self.logger.error(f"Failed to write to Timesketch CSV file {output_path}: {e}")
            raise
