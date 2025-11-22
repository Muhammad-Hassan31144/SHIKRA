import logging
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime
import hashlib
import subprocess
import json
import os
import tempfile
import shutil
import xml.etree.ElementTree as ET
from collections import defaultdict

from ...utils import jsonio, VTEnricher, GeoIPLookup
from ...utils.logger import setup_logger

class DiskAnalyzer:
    """
    Analyzes disk images using QCOW2 snapshot comparison, virt-diff automation,
    file system mounting (libguestfs), registry change detection, and file hash calculation.
    """
    
    def __init__(self, vt_api_key: Optional[str] = None, config_dir: Path = Path("config"),
                 output_dir: Optional[str] = None, virt_diff_path: str = "virt-diff",
                 guestmount_path: str = "guestmount", guestunmount_path: str = "guestunmount",
                 qemu_img_path: str = "qemu-img"):
        self.logger = setup_logger("DiskAnalyzer")
        
        # Make config directory handling more robust
        if config_dir.is_absolute():
            absolute_config_dir = config_dir
        else:
            # Look for config relative to current working directory first
            absolute_config_dir = Path.cwd() / config_dir
            if not absolute_config_dir.exists():
                # Fallback to relative to script location
                project_root = Path(__file__).resolve().parent.parent.parent.parent
                absolute_config_dir = project_root / config_dir
        
        if not absolute_config_dir.exists():
            raise FileNotFoundError(f"Configuration directory not found at: {absolute_config_dir}")
        
        config_dir = absolute_config_dir
        
        # Set configurable parameters
        self.virt_diff_path = virt_diff_path
        self.guestmount_path = guestmount_path
        self.guestunmount_path = guestunmount_path
        self.qemu_img_path = qemu_img_path
        self.output_dir = Path(output_dir) if output_dir else Path.cwd() / "output" / "disk"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize enrichers
        self.vt_enricher = VTEnricher(vt_api_key) if vt_api_key else None
        self.geo_lookup = GeoIPLookup(config_dir)
        
        # Load configuration
        self.config = self._load_config(config_dir)
        
        # Initialize statistics
        self.statistics = {
            "total_files_changed": 0,
            "files_added": 0,
            "files_removed": 0,
            "files_modified": 0,
            "registry_changes": 0,
            "suspicious_changes": 0,
            "encrypted_files_detected": 0,
            "ransom_notes_found": 0
        }
    
    def _load_config(self, config_dir: Path) -> Dict[str, Any]:
        """Load disk analysis configuration."""
        config_file = config_dir / "disk_config.json"
        
        default_config = {
            "suspicious_file_extensions": [
                ".encrypted", ".locked", ".crypto", ".crypt", ".enc", ".ecc",
                ".ezz", ".exx", ".zzz", ".aaa", ".abc", ".xyz", ".bnfd",
                ".cerber", ".locky", ".zepto", ".thor", ".odin", ".loki"
            ],
            "ransom_note_patterns": [
                "decrypt", "ransom", "bitcoin", "payment", "restore",
                "files encrypted", "recover files", "unlock files",
                "your files have been", "contact us", "tor browser"
            ],
            "suspicious_registry_keys": [
                "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
                "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
            ],
            "monitored_directories": [
                "/Users", "/home", "/Documents", "/Desktop", "/Pictures",
                "/Videos", "/Music", "/Downloads", "C:\\Users", "C:\\Documents and Settings"
            ],
            "max_file_size_mb": 100,
            "hash_algorithms": ["md5", "sha1", "sha256"]
        }
        
        if config_file.exists():
            try:
                with open(config_file, 'r') as f:
                    user_config = json.load(f)
                default_config.update(user_config)
            except Exception as e:
                self.logger.warning(f"Failed to load config file {config_file}: {e}. Using defaults.")
        
        return default_config
    
    async def analyze(self, before_disk: Path, after_disk: Path, analysis_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Perform comprehensive disk analysis comparing before and after disk images.
        
        Args:
            before_disk: Path to the "before" disk image (baseline)
            after_disk: Path to the "after" disk image (post-infection)
            analysis_id: Optional analysis identifier
            
        Returns:
            Dictionary containing analysis results
        """
        analysis_start_time = datetime.now()
        
        if analysis_id is None:
            analysis_id = f"disk_analysis_{analysis_start_time.strftime('%Y%m%d_%H%M%S')}"
        
        self.logger.info(f"Starting disk analysis: {analysis_id}")
        self.logger.info(f"Before disk: {before_disk}")
        self.logger.info(f"After disk: {after_disk}")
        
        # Validate disk images
        self._validate_disk_images(before_disk, after_disk)
        
        results = {
            "analysis_id": analysis_id,
            "analysis_start_time": analysis_start_time.isoformat(),
            "before_disk": str(before_disk),
            "after_disk": str(after_disk),
            "disk_comparison": {},
            "file_changes": {},
            "registry_changes": {},
            "suspicious_activity": {},
            "ransomware_indicators": [],
            "file_hashes": {},
            "statistics": {},
            "risk_assessment": {}
        }
        
        try:
            # 1. Run virt-diff for high-level comparison
            self.logger.info("Running virt-diff comparison...")
            results["disk_comparison"] = await self._run_virt_diff(before_disk, after_disk)
            
            # 2. Mount disk images and perform detailed analysis
            self.logger.info("Mounting disk images for detailed analysis...")
            with self._mount_disk_images(before_disk, after_disk) as (before_mount, after_mount):
                
                # 3. Analyze file system changes
                self.logger.info("Analyzing file system changes...")
                results["file_changes"] = await self._analyze_file_changes(before_mount, after_mount)
                
                # 4. Detect ransomware indicators
                self.logger.info("Detecting ransomware indicators...")
                results["ransomware_indicators"] = await self._detect_ransomware_indicators(
                    before_mount, after_mount
                )
                
                # 5. Calculate file hashes for changed files
                self.logger.info("Calculating file hashes...")
                results["file_hashes"] = await self._calculate_file_hashes(
                    results["file_changes"], after_mount
                )
                
                # 6. Analyze registry changes (Windows-specific)
                self.logger.info("Analyzing registry changes...")
                results["registry_changes"] = await self._analyze_registry_changes(
                    before_mount, after_mount
                )
            
            # 7. Generate statistics and risk assessment
            results["statistics"] = self._generate_statistics()
            results["risk_assessment"] = self._assess_risk(results)
            
            # 8. VirusTotal enrichment if API key provided
            if self.vt_enricher:
                self.logger.info("Enriching results with VirusTotal data...")
                results = await self._enrich_with_virustotal(results)
            
            analysis_end_time = datetime.now()
            results["analysis_end_time"] = analysis_end_time.isoformat()
            results["analysis_duration"] = str(analysis_end_time - analysis_start_time)
            
            self.logger.info(f"Disk analysis completed: {analysis_id}")
            return results
            
        except Exception as e:
            self.logger.error(f"Disk analysis failed: {e}", exc_info=True)
            raise
    
    def _validate_disk_images(self, before_disk: Path, after_disk: Path):
        """Validate that disk images exist and are accessible."""
        if not before_disk.exists():
            raise FileNotFoundError(f"Before disk image not found: {before_disk}")
        if not after_disk.exists():
            raise FileNotFoundError(f"After disk image not found: {after_disk}")
        
        # Check if files are readable
        try:
            with open(before_disk, 'rb') as f:
                f.read(512)  # Read first 512 bytes
            with open(after_disk, 'rb') as f:
                f.read(512)
        except Exception as e:
            raise ValueError(f"Cannot read disk images: {e}")
    
    async def _run_virt_diff(self, before_disk: Path, after_disk: Path) -> Dict[str, Any]:
        """Run virt-diff to compare disk images."""
        try:
            cmd = [
                self.virt_diff_path,
                "--format", "json",
                str(before_disk),
                str(after_disk)
            ]
            
            self.logger.debug(f"Running command: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            
            if result.returncode != 0:
                self.logger.warning(f"virt-diff returned non-zero exit code: {result.returncode}")
                self.logger.warning(f"stderr: {result.stderr}")
                return {"error": f"virt-diff failed: {result.stderr}"}
            
            # Parse virt-diff output
            try:
                diff_data = json.loads(result.stdout) if result.stdout.strip() else {}
            except json.JSONDecodeError:
                # Fallback to parsing text output
                diff_data = self._parse_virt_diff_text(result.stdout)
            
            return {
                "virt_diff_output": diff_data,
                "command_executed": ' '.join(cmd),
                "execution_time": datetime.now().isoformat()
            }
            
        except subprocess.TimeoutExpired:
            self.logger.error("virt-diff command timed out")
            return {"error": "virt-diff command timed out"}
        except Exception as e:
            self.logger.error(f"Failed to run virt-diff: {e}")
            return {"error": f"virt-diff execution failed: {str(e)}"}
    
    def _parse_virt_diff_text(self, output: str) -> Dict[str, Any]:
        """Parse text output from virt-diff when JSON is not available."""
        lines = output.strip().split('\n')
        parsed = {
            "files_added": [],
            "files_removed": [],
            "files_modified": []
        }
        
        for line in lines:
            if line.startswith('+'):
                parsed["files_added"].append(line[1:].strip())
            elif line.startswith('-'):
                parsed["files_removed"].append(line[1:].strip())
            elif line.startswith('~') or line.startswith('M'):
                parsed["files_modified"].append(line[1:].strip())
        
        return parsed
    
    def _mount_disk_images(self, before_disk: Path, after_disk: Path):
        """Context manager for mounting disk images."""
        return DiskMountContext(
            before_disk, after_disk, 
            self.guestmount_path, self.guestunmount_path,
            self.logger
        )
    
    async def _analyze_file_changes(self, before_mount: Path, after_mount: Path) -> Dict[str, Any]:
        """Analyze detailed file system changes between mounted disk images."""
        changes = {
            "files_added": [],
            "files_removed": [],
            "files_modified": [],
            "directories_added": [],
            "directories_removed": [],
            "summary": {}
        }
        
        try:
            # Get file lists from both mounts
            before_files = self._get_file_list(before_mount)
            after_files = self._get_file_list(after_mount)
            
            # Find added files
            added_files = after_files - before_files
            for file_path in added_files:
                full_path = after_mount / file_path
                if full_path.is_file():
                    file_info = self._get_file_info(full_path, file_path)
                    changes["files_added"].append(file_info)
                elif full_path.is_dir():
                    changes["directories_added"].append(str(file_path))
            
            # Find removed files
            removed_files = before_files - after_files
            for file_path in removed_files:
                full_path = before_mount / file_path
                if full_path.exists() and full_path.is_file():
                    changes["files_removed"].append(str(file_path))
                elif full_path.exists() and full_path.is_dir():
                    changes["directories_removed"].append(str(file_path))
            
            # Find modified files
            common_files = before_files & after_files
            for file_path in common_files:
                before_file = before_mount / file_path
                after_file = after_mount / file_path
                
                if (before_file.is_file() and after_file.is_file() and
                    self._files_different(before_file, after_file)):
                    file_info = self._get_file_info(after_file, file_path)
                    file_info["before_size"] = before_file.stat().st_size
                    file_info["size_change"] = file_info["size"] - file_info["before_size"]
                    changes["files_modified"].append(file_info)
            
            # Update statistics
            self.statistics["files_added"] = len(changes["files_added"])
            self.statistics["files_removed"] = len(changes["files_removed"])
            self.statistics["files_modified"] = len(changes["files_modified"])
            self.statistics["total_files_changed"] = (
                self.statistics["files_added"] + 
                self.statistics["files_removed"] + 
                self.statistics["files_modified"]
            )
            
            changes["summary"] = {
                "total_changes": self.statistics["total_files_changed"],
                "files_added_count": self.statistics["files_added"],
                "files_removed_count": self.statistics["files_removed"],
                "files_modified_count": self.statistics["files_modified"]
            }
            
        except Exception as e:
            self.logger.error(f"Failed to analyze file changes: {e}")
            changes["error"] = str(e)
        
        return changes
    
    def _get_file_list(self, mount_point: Path) -> set:
        """Get a set of all files and directories relative to mount point."""
        file_set = set()
        try:
            for root, dirs, files in os.walk(mount_point):
                rel_root = Path(root).relative_to(mount_point)
                
                # Add directories
                for dir_name in dirs:
                    file_set.add(rel_root / dir_name)
                
                # Add files
                for file_name in files:
                    file_set.add(rel_root / file_name)
                    
        except Exception as e:
            self.logger.error(f"Failed to get file list from {mount_point}: {e}")
        
        return file_set
    
    def _get_file_info(self, file_path: Path, relative_path: Path) -> Dict[str, Any]:
        """Get detailed information about a file."""
        try:
            stat = file_path.stat()
            return {
                "path": str(relative_path),
                "size": stat.st_size,
                "modified_time": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                "created_time": datetime.fromtimestamp(stat.st_ctime).isoformat(),
                "extension": file_path.suffix.lower(),
                "is_suspicious": self._is_suspicious_file(file_path)
            }
        except Exception as e:
            return {
                "path": str(relative_path),
                "error": str(e)
            }
    
    def _files_different(self, file1: Path, file2: Path) -> bool:
        """Check if two files are different by comparing size and modification time."""
        try:
            stat1 = file1.stat()
            stat2 = file2.stat()
            
            # Compare size first (quick check)
            if stat1.st_size != stat2.st_size:
                return True
            
            # Compare modification time
            if abs(stat1.st_mtime - stat2.st_mtime) > 1:  # 1 second tolerance
                return True
            
            # If still uncertain, compare a sample of bytes
            if stat1.st_size > 0 and stat1.st_size < 1024 * 1024:  # Files smaller than 1MB
                with open(file1, 'rb') as f1, open(file2, 'rb') as f2:
                    return f1.read() != f2.read()
            
            return False
            
        except Exception:
            return True  # Assume different if we can't compare
    
    def _is_suspicious_file(self, file_path: Path) -> bool:
        """Check if a file is suspicious based on extension and patterns."""
        extension = file_path.suffix.lower()
        filename = file_path.name.lower()
        
        # Check suspicious extensions
        if extension in self.config["suspicious_file_extensions"]:
            return True
        
        # Check ransom note patterns
        for pattern in self.config["ransom_note_patterns"]:
            if pattern.lower() in filename:
                return True
        
        return False
    
    async def _detect_ransomware_indicators(self, before_mount: Path, after_mount: Path) -> List[Dict[str, Any]]:
        """Detect specific ransomware indicators."""
        indicators = []
        
        try:
            # Look for ransom notes
            ransom_notes = self._find_ransom_notes(after_mount)
            for note in ransom_notes:
                indicators.append({
                    "type": "ransom_note",
                    "severity": "high",
                    "description": f"Potential ransom note found: {note['path']}",
                    "file_path": note["path"],
                    "content_preview": note.get("content_preview", "")
                })
            
            # Look for mass file encryption
            encrypted_files = self._find_encrypted_files(after_mount)
            if len(encrypted_files) > 10:  # Threshold for mass encryption
                indicators.append({
                    "type": "mass_encryption",
                    "severity": "critical",
                    "description": f"Mass file encryption detected: {len(encrypted_files)} files",
                    "encrypted_files_count": len(encrypted_files),
                    "sample_files": encrypted_files[:10]
                })
            
            # Look for dropped executables
            new_executables = self._find_new_executables(before_mount, after_mount)
            for exe in new_executables:
                indicators.append({
                    "type": "dropped_executable",
                    "severity": "medium",
                    "description": f"New executable found: {exe['path']}",
                    "file_path": exe["path"],
                    "file_size": exe["size"]
                })
            
            self.statistics["encrypted_files_detected"] = len(encrypted_files)
            self.statistics["ransom_notes_found"] = len(ransom_notes)
            self.statistics["suspicious_changes"] = len(indicators)
            
        except Exception as e:
            self.logger.error(f"Failed to detect ransomware indicators: {e}")
            indicators.append({
                "type": "detection_error",
                "severity": "low",
                "description": f"Error during indicator detection: {str(e)}"
            })
        
        return indicators
    
    def _find_ransom_notes(self, mount_point: Path) -> List[Dict[str, Any]]:
        """Find potential ransom notes."""
        ransom_notes = []
        
        # Common ransom note filenames
        ransom_filenames = [
            "readme.txt", "how_to_decrypt.txt", "restore_files.txt",
            "decrypt_instruction.txt", "recovery_instructions.txt",
            "your_files_are_encrypted.txt", "ransom_note.txt"
        ]
        
        try:
            for root, dirs, files in os.walk(mount_point):
                for file in files:
                    file_path = Path(root) / file
                    relative_path = file_path.relative_to(mount_point)
                    
                    # Check filename patterns
                    if (file.lower() in ransom_filenames or 
                        any(pattern in file.lower() for pattern in self.config["ransom_note_patterns"])):
                        
                        try:
                            # Try to read content preview
                            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read(500)  # First 500 characters
                            
                            ransom_notes.append({
                                "path": str(relative_path),
                                "filename": file,
                                "content_preview": content,
                                "size": file_path.stat().st_size
                            })
                        except Exception:
                            ransom_notes.append({
                                "path": str(relative_path),
                                "filename": file,
                                "content_preview": "",
                                "size": file_path.stat().st_size if file_path.exists() else 0
                            })
        
        except Exception as e:
            self.logger.error(f"Failed to find ransom notes: {e}")
        
        return ransom_notes
    
    def _find_encrypted_files(self, mount_point: Path) -> List[str]:
        """Find files that appear to be encrypted."""
        encrypted_files = []
        
        try:
            for root, dirs, files in os.walk(mount_point):
                for file in files:
                    file_path = Path(root) / file
                    relative_path = file_path.relative_to(mount_point)
                    
                    # Check suspicious extensions
                    if file_path.suffix.lower() in self.config["suspicious_file_extensions"]:
                        encrypted_files.append(str(relative_path))
                    
                    # Check for files with high entropy (potentially encrypted)
                    elif self._has_high_entropy(file_path):
                        encrypted_files.append(str(relative_path))
        
        except Exception as e:
            self.logger.error(f"Failed to find encrypted files: {e}")
        
        return encrypted_files
    
    def _has_high_entropy(self, file_path: Path) -> bool:
        """Check if a file has high entropy (potentially encrypted)."""
        try:
            if file_path.stat().st_size > self.config["max_file_size_mb"] * 1024 * 1024:
                return False  # Skip very large files
            
            with open(file_path, 'rb') as f:
                data = f.read(8192)  # Read first 8KB
            
            if len(data) < 100:
                return False  # Skip very small files
            
            # Calculate entropy
            entropy = self._calculate_entropy(data)
            return entropy > 7.5  # High entropy threshold
            
        except Exception:
            return False
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data."""
        if not data:
            return 0
        
        # Count byte frequencies
        freq = [0] * 256
        for byte in data:
            freq[byte] += 1
        
        # Calculate entropy
        length = len(data)
        entropy = 0
        for count in freq:
            if count > 0:
                p = count / length
                entropy -= p * (p.bit_length() - 1)
        
        return entropy
    
    def _find_new_executables(self, before_mount: Path, after_mount: Path) -> List[Dict[str, Any]]:
        """Find newly added executable files."""
        new_executables = []
        executable_extensions = ['.exe', '.dll', '.bat', '.cmd', '.scr', '.com', '.pif']
        
        try:
            before_files = self._get_file_list(before_mount)
            after_files = self._get_file_list(after_mount)
            
            added_files = after_files - before_files
            
            for file_path in added_files:
                full_path = after_mount / file_path
                if (full_path.is_file() and 
                    full_path.suffix.lower() in executable_extensions):
                    
                    new_executables.append({
                        "path": str(file_path),
                        "size": full_path.stat().st_size,
                        "extension": full_path.suffix.lower()
                    })
        
        except Exception as e:
            self.logger.error(f"Failed to find new executables: {e}")
        
        return new_executables
    
    async def _calculate_file_hashes(self, file_changes: Dict[str, Any], after_mount: Path) -> Dict[str, Any]:
        """Calculate hashes for changed files."""
        hashes = {}
        
        try:
            # Hash added files
            for file_info in file_changes.get("files_added", []):
                if not file_info.get("error"):
                    file_path = after_mount / file_info["path"]
                    hashes[file_info["path"]] = self._calculate_file_hash(file_path)
            
            # Hash modified files (subset)
            modified_files = file_changes.get("files_modified", [])[:50]  # Limit to first 50
            for file_info in modified_files:
                if not file_info.get("error"):
                    file_path = after_mount / file_info["path"]
                    hashes[file_info["path"]] = self._calculate_file_hash(file_path)
        
        except Exception as e:
            self.logger.error(f"Failed to calculate file hashes: {e}")
            hashes["error"] = str(e)
        
        return hashes
    
    def _calculate_file_hash(self, file_path: Path) -> Dict[str, str]:
        """Calculate multiple hashes for a file."""
        hashes = {}
        
        try:
            if file_path.stat().st_size > self.config["max_file_size_mb"] * 1024 * 1024:
                return {"error": "File too large for hashing"}
            
            hash_objects = {}
            for algorithm in self.config["hash_algorithms"]:
                hash_objects[algorithm] = hashlib.new(algorithm)
            
            with open(file_path, 'rb') as f:
                while chunk := f.read(8192):
                    for hash_obj in hash_objects.values():
                        hash_obj.update(chunk)
            
            for algorithm, hash_obj in hash_objects.items():
                hashes[algorithm] = hash_obj.hexdigest()
        
        except Exception as e:
            hashes["error"] = str(e)
        
        return hashes
    
    async def _analyze_registry_changes(self, before_mount: Path, after_mount: Path) -> Dict[str, Any]:
        """Analyze Windows registry changes."""
        registry_changes = {
            "changes_detected": False,
            "modified_keys": [],
            "suspicious_changes": [],
            "error": None
        }
        
        try:
            # Look for Windows registry hives
            registry_files = [
                "Windows/System32/config/SOFTWARE",
                "Windows/System32/config/SYSTEM",
                "Windows/System32/config/SECURITY",
                "Users/*/NTUSER.DAT"
            ]
            
            for reg_pattern in registry_files:
                before_reg = list(before_mount.glob(reg_pattern))
                after_reg = list(after_mount.glob(reg_pattern))
                
                if before_reg and after_reg:
                    for before_file, after_file in zip(before_reg, after_reg):
                        if self._files_different(before_file, after_file):
                            registry_changes["modified_keys"].append({
                                "registry_file": str(before_file.relative_to(before_mount)),
                                "before_size": before_file.stat().st_size,
                                "after_size": after_file.stat().st_size,
                                "modified": True
                            })
            
            if registry_changes["modified_keys"]:
                registry_changes["changes_detected"] = True
                self.statistics["registry_changes"] = len(registry_changes["modified_keys"])
        
        except Exception as e:
            self.logger.error(f"Failed to analyze registry changes: {e}")
            registry_changes["error"] = str(e)
        
        return registry_changes
    
    async def _enrich_with_virustotal(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich results with VirusTotal data."""
        if not self.vt_enricher:
            return results
        
        try:
            # Enrich file hashes
            file_hashes = results.get("file_hashes", {})
            for file_path, hash_data in file_hashes.items():
                if isinstance(hash_data, dict) and "sha256" in hash_data:
                    vt_result = await self.vt_enricher.check_hash(hash_data["sha256"])
                    if vt_result:
                        hash_data["virustotal"] = vt_result
        
        except Exception as e:
            self.logger.error(f"VirusTotal enrichment failed: {e}")
            results["virustotal_error"] = str(e)
        
        return results
    
    def _generate_statistics(self) -> Dict[str, Any]:
        """Generate comprehensive statistics."""
        return {
            **self.statistics,
            "analysis_timestamp": datetime.now().isoformat(),
            "configuration": {
                "virt_diff_path": self.virt_diff_path,
                "guestmount_path": self.guestmount_path,
                "output_directory": str(self.output_dir)
            }
        }
    
    def _assess_risk(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Assess overall risk based on analysis results."""
        risk_score = 0
        risk_factors = []
        
        # Ransomware indicators
        indicators = results.get("ransomware_indicators", [])
        for indicator in indicators:
            if indicator.get("severity") == "critical":
                risk_score += 40
                risk_factors.append(f"Critical indicator: {indicator.get('description', 'Unknown')}")
            elif indicator.get("severity") == "high":
                risk_score += 25
                risk_factors.append(f"High risk indicator: {indicator.get('description', 'Unknown')}")
            elif indicator.get("severity") == "medium":
                risk_score += 10
                risk_factors.append(f"Medium risk indicator: {indicator.get('description', 'Unknown')}")
        
        # File changes
        file_changes = results.get("file_changes", {})
        files_added = len(file_changes.get("files_added", []))
        files_modified = len(file_changes.get("files_modified", []))
        
        if files_added > 100:
            risk_score += 20
            risk_factors.append(f"Large number of files added: {files_added}")
        elif files_added > 10:
            risk_score += 10
            risk_factors.append(f"Moderate number of files added: {files_added}")
        
        if files_modified > 1000:
            risk_score += 30
            risk_factors.append(f"Mass file modification: {files_modified}")
        elif files_modified > 100:
            risk_score += 15
            risk_factors.append(f"Large number of files modified: {files_modified}")
        
        # Registry changes
        registry_changes = results.get("registry_changes", {})
        if registry_changes.get("changes_detected"):
            risk_score += 15
            risk_factors.append("Registry modifications detected")
        
        # Determine risk level
        if risk_score >= 75:
            risk_level = "CRITICAL"
        elif risk_score >= 50:
            risk_level = "HIGH"
        elif risk_score >= 25:
            risk_level = "MEDIUM"
        elif risk_score >= 10:
            risk_level = "LOW"
        else:
            risk_level = "MINIMAL"
        
        return {
            "risk_score": min(risk_score, 100),  # Cap at 100
            "risk_level": risk_level,
            "risk_factors": risk_factors,
            "assessment_time": datetime.now().isoformat()
        }


class DiskMountContext:
    """Context manager for mounting and unmounting disk images."""
    
    def __init__(self, before_disk: Path, after_disk: Path, 
                 guestmount_path: str, guestunmount_path: str, logger):
        self.before_disk = before_disk
        self.after_disk = after_disk
        self.guestmount_path = guestmount_path
        self.guestunmount_path = guestunmount_path
        self.logger = logger
        self.before_mount = None
        self.after_mount = None
        self.temp_dir = None
    
    def __enter__(self) -> Tuple[Path, Path]:
        """Mount both disk images."""
        try:
            # Create temporary directories
            self.temp_dir = tempfile.mkdtemp(prefix="ransomkit_disk_")
            self.before_mount = Path(self.temp_dir) / "before"
            self.after_mount = Path(self.temp_dir) / "after"
            
            self.before_mount.mkdir(parents=True, exist_ok=True)
            self.after_mount.mkdir(parents=True, exist_ok=True)
            
            # Mount before disk
            self._mount_disk(self.before_disk, self.before_mount)
            
            # Mount after disk
            self._mount_disk(self.after_disk, self.after_mount)
            
            return self.before_mount, self.after_mount
            
        except Exception as e:
            self._cleanup()
            raise e
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Unmount disk images and cleanup."""
        self._cleanup()
    
    def _mount_disk(self, disk_path: Path, mount_point: Path):
        """Mount a single disk image."""
        try:
            cmd = [
                self.guestmount_path,
                "-a", str(disk_path),
                "-i",  # Inspect and mount automatically
                "--ro",  # Read-only
                str(mount_point)
            ]
            
            self.logger.debug(f"Mounting {disk_path} at {mount_point}")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode != 0:
                raise RuntimeError(f"Failed to mount {disk_path}: {result.stderr}")
            
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"Mount timeout for {disk_path}")
        except Exception as e:
            raise RuntimeError(f"Mount failed for {disk_path}: {str(e)}")
    
    def _unmount_disk(self, mount_point: Path):
        """Unmount a single disk image."""
        try:
            cmd = [self.guestunmount_path, str(mount_point)]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode != 0:
                self.logger.warning(f"Failed to unmount {mount_point}: {result.stderr}")
            
        except Exception as e:
            self.logger.warning(f"Unmount error for {mount_point}: {e}")
    
    def _cleanup(self):
        """Cleanup mounted disks and temporary directories."""
        if self.before_mount and self.before_mount.exists():
            self._unmount_disk(self.before_mount)
        
        if self.after_mount and self.after_mount.exists():
            self._unmount_disk(self.after_mount)
        
        if self.temp_dir and Path(self.temp_dir).exists():
            try:
                shutil.rmtree(self.temp_dir)
            except Exception as e:
                self.logger.warning(f"Failed to cleanup temp directory {self.temp_dir}: {e}")
