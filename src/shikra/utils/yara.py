import yara
import os
from pathlib import Path
from typing import Dict, List, Any
import logging

from .logger import setup_logger

class YaraScanner:
    """
    A scanner that uses YARA rules to scan files and memory buffers.
    """
    def __init__(self, rules_dir: str = "data/yara_rules"):
        self.rules_dir = Path(rules_dir)
        self.logger = setup_logger("YaraScanner")
        self.rules = self._compile_rules()

    def _compile_rules(self) -> yara.Rules:
        """
        Compiles all .yar and .yara files in the specified directory.
        Returns an empty Rules object if the directory is empty or doesn't exist.
        """
        if not self.rules_dir.exists():
            self.logger.warning(f"YARA rules directory not found: {self.rules_dir}. Scanner will find no matches.")
            # Create directory to prevent repeated warnings
            os.makedirs(self.rules_dir, exist_ok=True)
            return yara.compile(source='rule dummy_rule { condition: false }')

        filepaths = {}
        rule_files = list(self.rules_dir.glob('*.yar')) + list(self.rules_dir.glob('*.yara'))
        
        if not rule_files:
            self.logger.warning(f"No YARA rule files (.yar, .yara) found in {self.rules_dir}.")
            return yara.compile(source='rule dummy_rule { condition: false }')

        for file in rule_files:
            # Use the filename as the namespace
            filepaths[file.stem] = str(file)
        
        self.logger.info(f"Compiling {len(filepaths)} YARA rule files.")
        try:
            return yara.compile(filepaths=filepaths)
        except yara.Error as e:
            self.logger.error(f"Failed to compile YARA rules: {e}")
            # Return a non-functional rule object to prevent crashes
            return yara.compile(source='rule compile_error { condition: false }')

    def scan_file(self, file_path: Path) -> List[Dict[str, Any]]:
        """
        Scans a single file with the compiled YARA rules.
        """
        if not file_path.exists() or not file_path.is_file():
            return []
        
        try:
            matches = self.rules.match(str(file_path))
            return self._format_matches(matches)
        except yara.Error as e:
            self.logger.error(f"YARA scan error on file {file_path}: {e}")
            return []

    def scan_memory(self, buffer: bytes) -> List[Dict[str, Any]]:
        """
        Scans a memory buffer (bytes) with the compiled YARA rules.
        """
        if not buffer:
            return []
            
        try:
            matches = self.rules.match(data=buffer)
            return self._format_matches(matches)
        except yara.Error as e:
            self.logger.error(f"YARA scan error on memory buffer: {e}")
            return []

    def _format_matches(self, matches: List) -> List[Dict[str, Any]]:
        """Formats YARA match objects into a serializable list of dicts."""
        results = []
        for match in matches:
            results.append({
                "rule": match.rule,
                "tags": match.tags,
                "meta": match.meta,
                "strings": [
                    {
                        "offset": s[0],
                        "identifier": s[1],
                        "data": s[2].decode('utf-8', 'ignore')
                    } for s in match.strings
                ]
            })
        return results
