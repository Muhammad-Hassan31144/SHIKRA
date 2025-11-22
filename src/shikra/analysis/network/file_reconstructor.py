"""
Advanced File Reconstruction Module for RansomKit

This module provides comprehensive file reconstruction capabilities
from network traffic, including HTTP downloads, email attachments,
FTP transfers, and other protocols.
"""

import logging
import hashlib
import magic
import yara
import math
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple, Set
from datetime import datetime
import asyncio
import subprocess
import tempfile
import shutil
import struct
import binascii
import re

from ...utils.logger import setup_logger
from ...utils.jsonio import save_json
from ...utils.vt import VTEnricher


class FileReconstructor:
    """
    Reconstructs files from network traffic using multiple techniques.
    """
    
    def __init__(self, 
                 output_dir: Path,
                 vt_api_key: Optional[str] = None,
                 yara_rules_dir: Optional[Path] = None,
                 enable_deep_scan: bool = True):
        """
        Initialize the file reconstructor.
        
        Args:
            output_dir: Directory to store reconstructed files
            vt_api_key: VirusTotal API key for file analysis
            yara_rules_dir: Directory containing YARA rules
            enable_deep_scan: Enable deep file analysis
        """
        self.logger = setup_logger("FileReconstructor")
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        self.vt_enricher = VTEnricher(vt_api_key) if vt_api_key else None
        self.enable_deep_scan = enable_deep_scan
        
        # Initialize file magic
        try:
            self.magic = magic.Magic(mime=True)
            self.magic_detailed = magic.Magic()
        except Exception as e:
            self.logger.warning(f"Failed to initialize libmagic: {e}")
            self.magic = None
            self.magic_detailed = None
        
        # Load YARA rules
        self.yara_rules = None
        if yara_rules_dir and yara_rules_dir.exists():
            try:
                self._load_yara_rules(yara_rules_dir)
            except Exception as e:
                self.logger.warning(f"Failed to load YARA rules: {e}")
        
        # File signature patterns for carving
        self.file_signatures = {
            'exe': [b'MZ'],
            'pdf': [b'%PDF-'],
            'zip': [b'PK\x03\x04', b'PK\x05\x06'],
            'rar': [b'Rar!\x1a\x07\x00', b'Rar!\x1a\x07\x01\x00'],
            'jpg': [b'\xff\xd8\xff'],
            'png': [b'\x89PNG\r\n\x1a\n'],
            'gif': [b'GIF87a', b'GIF89a'],
            'doc': [b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'],
            'rtf': [b'{\\rtf1'],
            'html': [b'<html', b'<!DOCTYPE html'],
            'xml': [b'<?xml'],
            'script': [b'#!', b'@echo off']
        }

    def _load_yara_rules(self, rules_dir: Path):
        """Load YARA rules from directory."""
        try:
            rule_files = {}
            for rule_file in rules_dir.glob("*.yar"):
                rule_files[str(rule_file)] = str(rule_file)
            
            if rule_files:
                self.yara_rules = yara.compile(filepaths=rule_files)
                self.logger.info(f"Loaded {len(rule_files)} YARA rule files")
        except Exception as e:
            self.logger.error(f"Failed to compile YARA rules: {e}")
            self.yara_rules = None

    async def reconstruct_from_zeek_logs(self, zeek_output_dir: Path) -> Dict[str, Any]:
        """
        Reconstruct files from Zeek analysis output.
        
        Args:
            zeek_output_dir: Directory containing Zeek output logs
            
        Returns:
            Dict containing reconstruction results
        """
        self.logger.info(f"Starting file reconstruction from Zeek logs in {zeek_output_dir}")
        
        results = {
            "meta": {
                "reconstructor": "FileReconstructor",
                "zeek_output_dir": str(zeek_output_dir),
                "analysis_timestamp": datetime.utcnow().isoformat(),
                "output_directory": str(self.output_dir)
            },
            "zeek_extracted_files": [],
            "http_reconstructed_files": [],
            "email_attachments": [],
            "ftp_transfers": [],
            "carved_files": [],
            "analysis_summary": {}
        }
        
        # Process Zeek extracted files
        extract_files_dir = zeek_output_dir / "extract_files"
        if extract_files_dir.exists():
            results["zeek_extracted_files"] = await self._process_zeek_extracted_files(extract_files_dir)
        
        # Reconstruct HTTP downloads
        http_log = zeek_output_dir / "http.log"
        if http_log.exists():
            results["http_reconstructed_files"] = await self._reconstruct_http_files(http_log)
        
        # Process email attachments
        smtp_log = zeek_output_dir / "smtp.log"
        if smtp_log.exists():
            results["email_attachments"] = await self._reconstruct_email_attachments(smtp_log)
        
        # Process FTP transfers
        ftp_log = zeek_output_dir / "ftp.log"
        if ftp_log.exists():
            results["ftp_transfers"] = await self._reconstruct_ftp_transfers(ftp_log)
        
        # Perform file carving on any remaining data
        if self.enable_deep_scan:
            results["carved_files"] = await self._perform_file_carving(zeek_output_dir)
        
        # Generate analysis summary
        results["analysis_summary"] = self._generate_analysis_summary(results)
        
        # Save results
        results_file = self.output_dir / "file_reconstruction_results.json"
        save_json(results, results_file)
        
        self.logger.info("File reconstruction completed")
        return results

    async def _process_zeek_extracted_files(self, extract_dir: Path) -> List[Dict[str, Any]]:
        """Process files already extracted by Zeek."""
        self.logger.info("Processing Zeek extracted files...")
        
        processed_files = []
        
        for file_path in extract_dir.glob("*"):
            if file_path.is_file():
                file_info = await self._analyze_single_file(file_path, "zeek_extracted")
                processed_files.append(file_info)
        
        return processed_files

    async def _reconstruct_http_files(self, http_log_path: Path) -> List[Dict[str, Any]]:
        """Reconstruct files from HTTP traffic analysis."""
        self.logger.info("Reconstructing files from HTTP traffic...")
        
        reconstructed_files = []
        
        try:
            # Parse HTTP log to find file downloads
            with open(http_log_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if line.startswith('#') or not line:
                        continue
                    
                    # Parse HTTP log entry
                    # Implementation depends on specific HTTP log analysis
                    # This is a placeholder for the actual implementation
                    pass
                    
        except Exception as e:
            self.logger.error(f"Error processing HTTP log: {e}")
        
        return reconstructed_files

    async def _reconstruct_email_attachments(self, smtp_log_path: Path) -> List[Dict[str, Any]]:
        """Reconstruct email attachments from SMTP traffic."""
        self.logger.info("Reconstructing email attachments...")
        
        attachments = []
        
        try:
            # Parse SMTP log to find email attachments
            with open(smtp_log_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if line.startswith('#') or not line:
                        continue
                    
                    # Implementation for SMTP attachment reconstruction
                    pass
                    
        except Exception as e:
            self.logger.error(f"Error processing SMTP log: {e}")
        
        return attachments

    async def _reconstruct_ftp_transfers(self, ftp_log_path: Path) -> List[Dict[str, Any]]:
        """Reconstruct files from FTP transfers."""
        self.logger.info("Reconstructing FTP transfers...")
        
        ftp_files = []
        
        try:
            # Parse FTP log to find file transfers
            with open(ftp_log_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if line.startswith('#') or not line:
                        continue
                    
                    # Implementation for FTP file reconstruction
                    pass
                    
        except Exception as e:
            self.logger.error(f"Error processing FTP log: {e}")
        
        return ftp_files

    async def _perform_file_carving(self, zeek_output_dir: Path) -> List[Dict[str, Any]]:
        """Perform file carving on network data."""
        self.logger.info("Performing file carving on network data...")
        
        carved_files = []
        
        # Look for any binary data files in Zeek output
        for data_file in zeek_output_dir.glob("*.dat"):
            if data_file.is_file():
                carved = await self._carve_files_from_data(data_file)
                carved_files.extend(carved)
        
        return carved_files

    async def _carve_files_from_data(self, data_file: Path) -> List[Dict[str, Any]]:
        """Carve files from binary data using file signatures."""
        carved_files = []
        
        try:
            with open(data_file, 'rb') as f:
                data = f.read()
            
            # Search for file signatures
            for file_type, signatures in self.file_signatures.items():
                for signature in signatures:
                    offset = 0
                    while True:
                        pos = data.find(signature, offset)
                        if pos == -1:
                            break
                        
                        # Extract potential file
                        carved_file = await self._extract_file_from_offset(
                            data, pos, file_type, data_file.name
                        )
                        if carved_file:
                            carved_files.append(carved_file)
                        
                        offset = pos + len(signature)
                        
        except Exception as e:
            self.logger.error(f"Error carving files from {data_file}: {e}")
        
        return carved_files

    async def _extract_file_from_offset(self, data: bytes, offset: int, file_type: str, source: str) -> Optional[Dict[str, Any]]:
        """Extract a file from binary data at given offset."""
        try:
            # Simple file extraction - in practice, this would need
            # more sophisticated logic to determine file boundaries
            max_size = min(10485760, len(data) - offset)  # 10MB max
            extracted_data = data[offset:offset + max_size]
            
            # Create output file
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            filename = f"carved_{file_type}_{timestamp}_{offset}.{file_type}"
            output_path = self.output_dir / filename
            
            with open(output_path, 'wb') as f:
                f.write(extracted_data)
            
            # Analyze the carved file
            file_info = await self._analyze_single_file(output_path, "carved")
            file_info["source_file"] = source
            file_info["source_offset"] = offset
            
            return file_info
            
        except Exception as e:
            self.logger.error(f"Error extracting file at offset {offset}: {e}")
            return None

    async def _analyze_single_file(self, file_path: Path, source_type: str) -> Dict[str, Any]:
        """Perform comprehensive analysis of a single file."""
        try:
            stat = file_path.stat()
            
            # Calculate hashes
            with open(file_path, 'rb') as f:
                content = f.read()
                md5_hash = hashlib.md5(content).hexdigest()
                sha1_hash = hashlib.sha1(content).hexdigest()
                sha256_hash = hashlib.sha256(content).hexdigest()
            
            # Determine file type
            mime_type = self._get_mime_type(file_path)
            file_description = self._get_file_description(file_path)
            
            # Calculate entropy (for packed/encrypted file detection)
            entropy = self._calculate_entropy(content)
            
            file_info = {
                "file_path": str(file_path),
                "file_name": file_path.name,
                "source_type": source_type,
                "size_bytes": stat.st_size,
                "md5": md5_hash,
                "sha1": sha1_hash,
                "sha256": sha256_hash,
                "mime_type": mime_type,
                "file_description": file_description,
                "entropy": entropy,
                "created_time": datetime.fromtimestamp(stat.st_ctime).isoformat(),
                "modified_time": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                "yara_matches": [],
                "virustotal_results": None,
                "risk_indicators": []
            }
            
            # YARA scanning
            if self.yara_rules:
                try:
                    matches = self.yara_rules.match(str(file_path))
                    file_info["yara_matches"] = [
                        {
                            "rule_name": match.rule,
                            "tags": list(match.tags),
                            "meta": dict(match.meta) if match.meta else {}
                        }
                        for match in matches
                    ]
                except Exception as e:
                    self.logger.warning(f"YARA scanning failed for {file_path}: {e}")
            
            # VirusTotal lookup
            if self.vt_enricher:
                try:
                    vt_results = await self.vt_enricher.enrich_hash_async(sha256_hash)
                    file_info["virustotal_results"] = vt_results
                except Exception as e:
                    self.logger.warning(f"VirusTotal lookup failed for {file_path}: {e}")
            
            # Risk assessment
            file_info["risk_indicators"] = self._assess_file_risk(file_info)
            
            return file_info
            
        except Exception as e:
            self.logger.error(f"Error analyzing file {file_path}: {e}")
            return {
                "file_path": str(file_path),
                "error": str(e),
                "source_type": source_type
            }

    def _get_mime_type(self, file_path: Path) -> str:
        """Get MIME type of file."""
        if self.magic:
            try:
                return self.magic.from_file(str(file_path))
            except Exception:
                pass
        return "unknown"

    def _get_file_description(self, file_path: Path) -> str:
        """Get detailed file description."""
        if self.magic_detailed:
            try:
                return self.magic_detailed.from_file(str(file_path))
            except Exception:
                pass
        return "unknown"

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of file data."""
        if not data:
            return 0.0
        
        # Count byte frequencies
        freq = [0] * 256
        for byte in data:
            freq[byte] += 1
        
        # Calculate entropy
        entropy = 0.0
        length = len(data)
        
        for count in freq:
            if count > 0:
                probability = count / length
                entropy -= probability * math.log2(probability)
        
        return entropy

    def _assess_file_risk(self, file_info: Dict[str, Any]) -> List[str]:
        """Assess risk indicators for a file."""
        risk_indicators = []
        
        # High entropy (potentially packed/encrypted)
        if file_info.get("entropy", 0) > 7.5:
            risk_indicators.append("HIGH_ENTROPY")
        
        # Executable files
        if "executable" in file_info.get("file_description", "").lower():
            risk_indicators.append("EXECUTABLE_FILE")
        
        # YARA matches
        if file_info.get("yara_matches"):
            risk_indicators.append("YARA_MATCH")
        
        # VirusTotal detections
        vt_results = file_info.get("virustotal_results", {})
        if vt_results and vt_results.get("positives", 0) > 0:
            risk_indicators.append("MALWARE_DETECTED")
        
        # Suspicious file extensions
        file_path = Path(file_info["file_path"])
        suspicious_extensions = {'.exe', '.dll', '.bat', '.cmd', '.scr', '.vbs', '.js', '.jar'}
        if file_path.suffix.lower() in suspicious_extensions:
            risk_indicators.append("SUSPICIOUS_EXTENSION")
        
        return risk_indicators

    def _generate_analysis_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate summary of file reconstruction analysis."""
        total_files = (
            len(results.get("zeek_extracted_files", [])) +
            len(results.get("http_reconstructed_files", [])) +
            len(results.get("email_attachments", [])) +
            len(results.get("ftp_transfers", [])) +
            len(results.get("carved_files", []))
        )
        
        # Count risk indicators across all files
        risk_counts = {}
        malware_count = 0
        
        for file_list in [results.get(k, []) for k in 
                         ["zeek_extracted_files", "http_reconstructed_files", 
                          "email_attachments", "ftp_transfers", "carved_files"]]:
            for file_info in file_list:
                if isinstance(file_info, dict):
                    # Count risk indicators
                    for indicator in file_info.get("risk_indicators", []):
                        risk_counts[indicator] = risk_counts.get(indicator, 0) + 1
                    
                    # Count malware
                    vt_results = file_info.get("virustotal_results", {})
                    if vt_results and vt_results.get("positives", 0) > 0:
                        malware_count += 1
        
        return {
            "total_files_reconstructed": total_files,
            "malware_files_detected": malware_count,
            "risk_indicator_counts": risk_counts,
            "file_type_distribution": self._get_file_type_distribution(results),
            "largest_file_size": self._get_largest_file_size(results)
        }

    def _get_file_type_distribution(self, results: Dict[str, Any]) -> Dict[str, int]:
        """Get distribution of file types."""
        type_counts = {}
        
        for file_list in [results.get(k, []) for k in 
                         ["zeek_extracted_files", "http_reconstructed_files", 
                          "email_attachments", "ftp_transfers", "carved_files"]]:
            for file_info in file_list:
                if isinstance(file_info, dict):
                    mime_type = file_info.get("mime_type", "unknown")
                    type_counts[mime_type] = type_counts.get(mime_type, 0) + 1
        
        return type_counts

    def _get_largest_file_size(self, results: Dict[str, Any]) -> int:
        """Get the size of the largest reconstructed file."""
        max_size = 0
        
        for file_list in [results.get(k, []) for k in 
                         ["zeek_extracted_files", "http_reconstructed_files", 
                          "email_attachments", "ftp_transfers", "carved_files"]]:
            for file_info in file_list:
                if isinstance(file_info, dict):
                    size = file_info.get("size_bytes", 0)
                    max_size = max(max_size, size)
        
        return max_size

    async def reconstruct_from_zeek_extract(self, 
                                           extracted_path: Path,
                                           zeek_file_metadata: Dict[str, Any],
                                           output_dir: Path) -> Optional[Dict[str, Any]]:
        """
        Reconstruct and analyze a file extracted by Zeek.
        
        Args:
            extracted_path: Path to file extracted by Zeek
            zeek_file_metadata: Metadata from Zeek's files.log
            output_dir: Directory to save reconstructed file
            
        Returns:
            Dictionary with file analysis results or None if failed
        """
        try:
            if not extracted_path.exists():
                self.logger.warning(f"Zeek extracted file not found: {extracted_path}")
                return None
            
            # Create output directory if needed
            output_dir.mkdir(parents=True, exist_ok=True)
            
            # Generate filename based on Zeek metadata
            original_filename = zeek_file_metadata.get('filename', 'unknown')
            if original_filename == '-' or not original_filename:
                # Generate filename from FUID and mime type
                fuid = zeek_file_metadata.get('fuid', 'unknown')
                mime_type = zeek_file_metadata.get('mime_type', 'application/octet-stream')
                extension = self._get_extension_from_mime(mime_type)
                original_filename = f"zeek_extracted_{fuid}{extension}"
            
            # Copy and analyze the extracted file
            reconstructed_path = output_dir / f"reconstructed_{original_filename}"
            shutil.copy2(extracted_path, reconstructed_path)
            
            # Perform file analysis
            file_info = await self._analyze_file(reconstructed_path)
            
            # Add Zeek metadata
            file_info.update({
                'source': 'zeek_extraction',
                'original_filename': original_filename,
                'zeek_fuid': zeek_file_metadata.get('fuid'),
                'zeek_mime_type': zeek_file_metadata.get('mime_type'),
                'zeek_source': zeek_file_metadata.get('source'),
                'zeek_size': zeek_file_metadata.get('seen_bytes', 0),
                'zeek_md5': zeek_file_metadata.get('md5'),
                'zeek_sha1': zeek_file_metadata.get('sha1'),
                'zeek_sha256': zeek_file_metadata.get('sha256'),
                'transmission_hosts': {
                    'tx_hosts': zeek_file_metadata.get('tx_hosts', []),
                    'rx_hosts': zeek_file_metadata.get('rx_hosts', [])
                },
                'reconstructed_path': str(reconstructed_path)
            })
            
            # Check if file is suspicious based on analysis
            is_suspicious = await self._is_file_suspicious(file_info)
            file_info['is_suspicious'] = is_suspicious
            
            if is_suspicious:
                self.logger.warning(f"Suspicious file detected: {original_filename}")
            
            return file_info
            
        except Exception as e:
            self.logger.error(f"Failed to reconstruct file from Zeek extract: {e}")
            return None
    
    def _get_extension_from_mime(self, mime_type: str) -> str:
        """Get file extension from MIME type."""
        mime_to_ext = {
            'application/pdf': '.pdf',
            'application/zip': '.zip',
            'application/x-dosexec': '.exe',
            'application/x-executable': '.exe',
            'image/jpeg': '.jpg',
            'image/png': '.png',
            'image/gif': '.gif',
            'text/html': '.html',
            'text/plain': '.txt',
            'application/json': '.json',
            'application/xml': '.xml',
            'application/javascript': '.js',
            'application/vnd.ms-office': '.doc',
            'application/vnd.openxmlformats-officedocument': '.docx',
            'application/vnd.ms-excel': '.xls',
            'video/mp4': '.mp4',
            'audio/mpeg': '.mp3',
            'application/octet-stream': '.bin'
        }
        
        for mime_prefix, ext in mime_to_ext.items():
            if mime_type.startswith(mime_prefix):
                return ext
        
        return '.unknown'

    async def cleanup(self):
        """Clean up temporary files and resources."""
        try:
            # Cleanup any temporary files created during analysis
            temp_files = self.output_dir.glob("temp_*")
            for temp_file in temp_files:
                if temp_file.is_file():
                    temp_file.unlink()
                elif temp_file.is_dir():
                    shutil.rmtree(temp_file)
        except Exception as e:
            self.logger.warning(f"Error during cleanup: {e}")
