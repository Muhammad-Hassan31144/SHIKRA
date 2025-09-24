"""
Shikra Static Analysis Module - Safe Pre-Execution Analysis
Runs BEFORE dynamic analysis to assess risk and extract IoCs
"""

import os
import sys
import hashlib
import logging
import json
import tempfile
import subprocess
import resource
import signal
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime
from contextlib import contextmanager
import threading
import queue

logger = logging.getLogger(__name__)

# Safety limits
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB max
ANALYSIS_TIMEOUT = 60  # 60 seconds max per tool
MAX_MEMORY = 512 * 1024 * 1024  # 512MB memory limit

class SafetyError(Exception):
    """Raised when safety checks fail"""
    pass

class StaticAnalyzer:
    """
    Safe static analysis orchestrator
    Runs multiple tools in sandboxed environment
    """
    
    def __init__(self, config: Dict = None):
        self.config = config or self._load_config()
        self.results = {}
        self.sample_path = None
        self.sample_hash = None
        self.temp_dir = None
        
        # Tool availability
        self.tools_available = self._check_tools()
        
    def _load_config(self) -> Dict:
        """Load configuration from files"""
        project_root = Path(__file__).parent.parent.parent.parent
        config_dir = project_root / "config" / "static"
        
        # Default configuration
        default_config = {
            "capa_rules": project_root / "data" / "capa",
            "yara_rules": project_root / "data" / "yara_rules",
            "tools": {
                "capa": {"enabled": True, "timeout": 45},
                "pefile": {"enabled": True, "timeout": 30},
                "yara": {"enabled": True, "timeout": 30},
                "strings": {"enabled": True, "timeout": 30},
                "exiftool": {"enabled": True, "timeout": 15},
                "ssdeep": {"enabled": True, "timeout": 15}
            }
        }
        
        # Try to load from config file
        try:
            config_file = config_dir / "config.json"
            if config_file.exists():
                with open(config_file, 'r') as f:
                    file_config = json.load(f)
                    
                    # Convert relative paths to absolute Path objects
                    if "capa_rules" in file_config:
                        if not os.path.isabs(file_config["capa_rules"]):
                            file_config["capa_rules"] = project_root / file_config["capa_rules"]
                        else:
                            file_config["capa_rules"] = Path(file_config["capa_rules"])
                    
                    if "yara_rules" in file_config:
                        if not os.path.isabs(file_config["yara_rules"]):
                            file_config["yara_rules"] = project_root / file_config["yara_rules"]
                        else:
                            file_config["yara_rules"] = Path(file_config["yara_rules"])
                    
                    # Merge with defaults
                    default_config.update(file_config)
                    logger.info(f"Loaded config from {config_file}")
            else:
                logger.info("Using default configuration")
        except Exception as e:
            logger.warning(f"Failed to load config file: {e}, using defaults")
            
        return default_config
        
    def _check_tools(self) -> Dict[str, bool]:
        """Check which analysis tools are available"""
        tools = {
            "capa": self._check_capa(),
            "pefile": self._check_pefile(),
            "yara": self._check_yara(),
            "strings": self._check_strings(),
            "exiftool": self._check_exiftool(),
            "ssdeep": self._check_ssdeep()
        }
        
        logger.info(f"Available tools: {[k for k,v in tools.items() if v]}")
        return tools
    
    def _check_capa(self) -> bool:
        try:
            import capa
            return True
        except ImportError:
            return False
    
    def _check_pefile(self) -> bool:
        try:
            import pefile
            return True
        except ImportError:
            return False
    
    def _check_yara(self) -> bool:
        try:
            import yara
            return True
        except ImportError:
            return False
    
    def _check_strings(self) -> bool:
        try:
            result = subprocess.run(["strings", "--version"], 
                                  capture_output=True, timeout=5)
            return result.returncode == 0
        except:
            return False
    
    def _check_exiftool(self) -> bool:
        try:
            result = subprocess.run(["exiftool", "-ver"], 
                                  capture_output=True, timeout=5)
            return result.returncode == 0
        except:
            return False
    
    def _check_ssdeep(self) -> bool:
        try:
            import ssdeep
            return True
        except ImportError:
            return False
    
    @contextmanager
    def _safe_execution_context(self, timeout: int = ANALYSIS_TIMEOUT):
        """
        Context manager for safe execution with resource limits
        """
        def timeout_handler(signum, frame):
            raise TimeoutError("Analysis timeout exceeded")
        
        # Set resource limits (Unix only)
        if hasattr(resource, 'RLIMIT_AS'):
            old_limit = resource.getrlimit(resource.RLIMIT_AS)
            resource.setrlimit(resource.RLIMIT_AS, (MAX_MEMORY, old_limit[1]))
        
        # Set timeout
        old_handler = signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(timeout)
        
        try:
            yield
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, old_handler)
            
            if hasattr(resource, 'RLIMIT_AS'):
                resource.setrlimit(resource.RLIMIT_AS, old_limit)
    
    def analyze_sample(self, sample_path: str, 
                      output_dir: str = None,
                      skip_expensive: bool = False) -> Dict:
        """
        Main analysis entry point - SAFE execution guaranteed
        
        Args:
            sample_path: Path to sample file
            output_dir: Output directory for results
            skip_expensive: Skip expensive operations for quick triage
            
        Returns:
            Analysis results dictionary
        """
        sample_path = Path(sample_path)
        
        # Safety checks
        if not sample_path.exists():
            raise FileNotFoundError(f"Sample not found: {sample_path}")
        
        file_size = sample_path.stat().st_size
        if file_size > MAX_FILE_SIZE:
            raise SafetyError(f"File too large: {file_size} bytes")
        
        if file_size == 0:
            raise SafetyError("File is empty")
        
        # Create temporary working directory
        self.temp_dir = tempfile.mkdtemp(prefix="shikra_static_")
        logger.info(f"Working directory: {self.temp_dir}")
        
        try:
            # Initialize results
            self.results = {
                "sample_path": str(sample_path),
                "analysis_time": datetime.now().isoformat(),
                "file_info": self._get_file_info(sample_path),
                "risk_assessment": {},
                "capabilities": {},
                "indicators": {},
                "recommendations": {}
            }
            
            # Calculate hashes (always safe)
            self.results["hashes"] = self._calculate_hashes(sample_path)
            self.sample_hash = self.results["hashes"]["sha256"]
            
            # Run analysis tools
            if not skip_expensive:
                self._run_strings_analysis(sample_path)
            
            if self.tools_available["pefile"]:
                self._run_pefile_analysis(sample_path)
            
            if self.tools_available["capa"]:
                self._run_capa_analysis(sample_path)
            
            if self.tools_available["yara"]:
                self._run_yara_analysis(sample_path)
            
            if self.tools_available["exiftool"]:
                self._run_exiftool_analysis(sample_path)
            
            if self.tools_available["ssdeep"] and not skip_expensive:
                self._run_ssdeep_analysis(sample_path)
            
            # Risk assessment based on findings
            self._assess_risk()
            
            # Generate recommendations
            self._generate_recommendations()
            
            # Save results
            if output_dir:
                self._save_results(output_dir)
            
            return self.results
            
        except Exception as e:
            logger.error(f"Analysis failed: {e}")
            self.results["error"] = str(e)
            return self.results
            
        finally:
            # Cleanup
            if self.temp_dir and Path(self.temp_dir).exists():
                import shutil
                shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def _get_file_info(self, sample_path: Path) -> Dict:
        """Get basic file information"""
        stat = sample_path.stat()
        return {
            "name": sample_path.name,
            "size": stat.st_size,
            "created": datetime.fromtimestamp(stat.st_ctime).isoformat(),
            "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
            "extension": sample_path.suffix.lower()
        }
    
    def _calculate_hashes(self, sample_path: Path) -> Dict:
        """Calculate file hashes safely"""
        hashes = {}
        
        with open(sample_path, 'rb') as f:
            content = f.read()
            hashes["md5"] = hashlib.md5(content).hexdigest()
            hashes["sha1"] = hashlib.sha1(content).hexdigest()
            hashes["sha256"] = hashlib.sha256(content).hexdigest()
            
        logger.info(f"SHA256: {hashes['sha256']}")
        return hashes
    
    def _run_strings_analysis(self, sample_path: Path):
        """Extract strings safely"""
        try:
            with self._safe_execution_context(timeout=30):
                result = subprocess.run(
                    ["strings", "-n", "6", str(sample_path)],
                    capture_output=True,
                    text=True,
                    timeout=20
                )
                
                if result.returncode == 0:
                    strings = result.stdout.splitlines()
                    
                    # Analyze strings for IoCs
                    self.results["strings"] = {
                        "total": len(strings),
                        "urls": self._extract_urls(strings),
                        "ips": self._extract_ips(strings),
                        "emails": self._extract_emails(strings),
                        "file_paths": self._extract_paths(strings),
                        "registry_keys": self._extract_registry(strings),
                        "interesting": self._find_interesting_strings(strings)
                    }
                    
        except Exception as e:
            logger.warning(f"Strings analysis failed: {e}")
    
    def _run_pefile_analysis(self, sample_path: Path):
        """Analyze PE structure safely"""
        try:
            import pefile
            
            with self._safe_execution_context(timeout=30):
                pe = pefile.PE(str(sample_path), fast_load=True)
                
                self.results["pe_info"] = {
                    "machine": hex(pe.FILE_HEADER.Machine),
                    "timestamp": datetime.fromtimestamp(
                        pe.FILE_HEADER.TimeDateStamp).isoformat(),
                    "sections": [],
                    "imports": {},
                    "exports": [],
                    "resources": [],
                    "anomalies": []
                }
                
                # Sections
                for section in pe.sections:
                    sect_info = {
                        "name": section.Name.decode('utf-8', errors='ignore').strip('\x00'),
                        "virtual_size": section.Misc_VirtualSize,
                        "raw_size": section.SizeOfRawData,
                        "entropy": section.get_entropy(),
                        "suspicious": section.get_entropy() > 7.0
                    }
                    self.results["pe_info"]["sections"].append(sect_info)
                
                # Check for packers
                if any(s["entropy"] > 7.0 for s in self.results["pe_info"]["sections"]):
                    self.results["pe_info"]["anomalies"].append("High entropy - possibly packed")
                
                # Imports (limited for safety)
                pe.parse_data_directories(directories=[
                    pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']
                ])
                
                if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                    for entry in pe.DIRECTORY_ENTRY_IMPORT[:20]:  # Limit imports
                        dll_name = entry.dll.decode('utf-8', errors='ignore')
                        imports = []
                        for imp in entry.imports[:50]:  # Limit functions per DLL
                            if imp.name:
                                imports.append(imp.name.decode('utf-8', errors='ignore'))
                        
                        self.results["pe_info"]["imports"][dll_name] = imports
                
                pe.close()
                
        except Exception as e:
            logger.warning(f"PE analysis failed: {e}")
    
    def _run_capa_analysis(self, sample_path: Path):
        """Run capa for capability detection using capa 9.2 API"""
        try:
            logger.debug("Starting capa analysis")
            import capa.main
            import capa.rules
            import capa.loader
            import capa.engine
            from pathlib import Path as CapaPath
            
            # Get rules directory from config
            rules_path = self.config.get("capa_rules", "")
            if not rules_path:
                # Try default locations
                default_paths = [
                    CapaPath(__file__).parent.parent.parent.parent / "data" / "capa",
                    CapaPath.home() / ".config" / "capa" / "rules",
                    CapaPath(__file__).parent.parent.parent.parent / "config" / "capa" / "rules",
                    CapaPath(__file__).parent.parent.parent.parent / "capa_source" / "rules"
                ]
                
                for path in default_paths:
                    if path.exists():
                        rules_path = str(path)
                        break
                        
            if not rules_path or not CapaPath(rules_path).exists():
                logger.warning(f"Capa rules not found, skipping capa analysis")
                logger.debug(f"Tried: {rules_path}")
                return

            logger.info(f"Using capa rules from: {rules_path}")

            with self._safe_execution_context(timeout=45):
                # Load rules using the direct API
                rules = capa.rules.get_rules([CapaPath(rules_path)])
                
                # Get extractor using the direct API
                extractor = capa.loader.get_extractor(
                    input_path=CapaPath(sample_path),
                    input_format="pe",
                    os_="windows", 
                    backend="vivisect",
                    sigpaths=[],
                    should_save_workspace=False,
                    disable_progress=True
                )
                
                if not extractor:
                    logger.warning("Could not create extractor for sample")
                    return
                    
                # Find capabilities using capa.main.find_capabilities
                capabilities = capa.main.find_capabilities(rules, extractor)
                
                self.results["capabilities"] = {
                    "matched_rules": [],
                    "attack_techniques": [],
                    "malware_families": [],
                    "mbc_objectives": [],
                    "namespaces": []
                }

                if capabilities and capabilities.matches:
                    logger.info(f"Found {len(capabilities.matches)} capability matches")
                    
                    for rule_name, matches in capabilities.matches.items():
                        # Get the rule object to access metadata from the rules collection
                        rule = rules.rules.get(rule_name)
                        if rule:
                            rule_info = {
                                "name": rule_name,
                                "namespace": getattr(rule, 'namespace', ''),
                                "attack": [],
                                "mbc": [],
                                "description": getattr(rule, 'meta', {}).get('description', '')
                            }
                            
                            # Extract ATT&CK techniques from rule metadata
                            if hasattr(rule, 'meta') and rule.meta:
                                attack_list = rule.meta.get('att&ck', [])
                                if isinstance(attack_list, list):
                                    rule_info["attack"] = attack_list
                                    # Add to global list
                                    for attack in attack_list:
                                        if attack not in self.results["capabilities"]["attack_techniques"]:
                                            self.results["capabilities"]["attack_techniques"].append(attack)
                                
                                # Extract MBC objectives 
                                mbc_list = rule.meta.get('mbc', [])
                                if isinstance(mbc_list, list):
                                    rule_info["mbc"] = mbc_list
                                    for mbc in mbc_list:
                                        if mbc not in self.results["capabilities"]["mbc_objectives"]:
                                            self.results["capabilities"]["mbc_objectives"].append(mbc)
                            
                            # Add namespace to global list
                            if rule_info["namespace"] and rule_info["namespace"] not in self.results["capabilities"]["namespaces"]:
                                self.results["capabilities"]["namespaces"].append(rule_info["namespace"])
                                
                            self.results["capabilities"]["matched_rules"].append(rule_info)
                        else:
                            # Fallback if rule object not accessible
                            self.results["capabilities"]["matched_rules"].append({"name": rule_name})
                
                logger.info(f"Capa analysis completed: {len(self.results['capabilities']['matched_rules'])} rules matched")

        except ImportError as e:
            logger.warning(f"Capa import failed: {e}")
            logger.debug("Make sure capa is properly installed: pip install flare-capa")
        except Exception as e:
            logger.warning(f"Capa analysis failed: {e}")
            logger.debug(f"Capa error details: {type(e).__name__}: {str(e)}")
    
    def _run_yara_analysis(self, sample_path: Path):
        """Run YARA rules safely"""
        try:
            import yara
            
            with self._safe_execution_context(timeout=30):
                # Load rules from config directory 
                project_root = Path(__file__).parent.parent.parent.parent
                rules_path = self.config.get("yara_rules", 
                    project_root / "data" / "yara_rules")
                rules_path = Path(rules_path)

                if not rules_path.exists():
                    logger.warning(f"YARA rules directory not found at {rules_path}")
                    return
                
                index_file = rules_path / "index.yar"
                if not index_file.exists():
                    logger.warning(f"YARA index file not found at {index_file}")
                    return
                
                logger.info(f"Loading YARA rules from: {index_file}")
                
                try:
                    # Compile rules from index file
                    rules = yara.compile(filepath=str(index_file))
                    logger.info("YARA rules compiled successfully")
                    
                    # Match against sample
                    matches = rules.match(str(sample_path))
                    
                    self.results["yara_matches"] = []
                    
                    if matches:
                        logger.info(f"YARA found {len(matches)} rule matches")
                        
                        for match in matches:
                            try:
                                match_info = {
                                    "rule": match.rule,
                                    "namespace": getattr(match, 'namespace', 'default'),
                                    "tags": list(match.tags) if match.tags else [],
                                    "strings": []
                                }
                                # Handle string matches for both tuple and object APIs
                                if hasattr(match, 'strings') and match.strings:
                                    for sm in match.strings[:20]:  # Limit strings
                                        try:
                                            if isinstance(sm, tuple) and len(sm) >= 3:
                                                # Old API: (offset, identifier, data)
                                                offset, identifier, data = sm[0], sm[1], sm[2]
                                                content_bytes = data if isinstance(data, (bytes, bytearray)) else bytes(str(data), 'utf-8', errors='ignore')
                                                match_info["strings"].append({
                                                    "offset": int(offset),
                                                    "identifier": identifier,
                                                    "content": content_bytes[:100].decode('utf-8', errors='ignore')
                                                })
                                            else:
                                                # New API: object with attributes
                                                content_bytes = getattr(sm, 'matched_data', None)
                                                if content_bytes is None:
                                                    content_bytes = getattr(sm, 'data', b'')
                                                match_info["strings"].append({
                                                    "offset": int(getattr(sm, 'offset', -1)),
                                                    "identifier": getattr(sm, 'identifier', ''),
                                                    "content": (content_bytes or b'')[:100].decode('utf-8', errors='ignore')
                                                })
                                        except Exception as e:
                                            logger.debug(f"Error processing string match: {e}")
                                
                                self.results["yara_matches"].append(match_info)
                                
                            except Exception as e:
                                logger.debug(f"Error processing YARA match {match.rule}: {e}")
                    else:
                        logger.info("No YARA rule matches found")
                        
                except yara.Error as e:
                    logger.warning(f"YARA compilation error: {e}")
                except Exception as e:
                    logger.warning(f"YARA analysis error: {e}")
                
        except ImportError:
            logger.warning("YARA module not available")
        except Exception as e:
            logger.warning(f"YARA analysis failed: {e}")
            logger.debug(f"YARA error details: {type(e).__name__}: {str(e)}")
    
    def _run_exiftool_analysis(self, sample_path: Path):
        """Extract metadata safely"""
        try:
            with self._safe_execution_context(timeout=15):
                result = subprocess.run(
                    ["exiftool", "-j", str(sample_path)],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                
                if result.returncode == 0:
                    metadata = json.loads(result.stdout)[0]
                    
                    # Filter sensitive fields
                    safe_metadata = {
                        k: v for k, v in metadata.items()
                        if not k.startswith("System:")
                    }
                    
                    self.results["metadata"] = safe_metadata
                    
        except Exception as e:
            logger.warning(f"Metadata extraction failed: {e}")
    
    def _run_ssdeep_analysis(self, sample_path: Path):
        """Calculate fuzzy hash"""
        try:
            import ssdeep
            
            with self._safe_execution_context(timeout=15):
                fuzzy_hash = ssdeep.hash_from_file(str(sample_path))
                self.results["fuzzy_hash"] = fuzzy_hash
                
                # Compare with known samples if available
                known_samples = self.config.get("known_fuzzy_hashes", {})
                similarities = []
                
                for name, known_hash in known_samples.items():
                    score = ssdeep.compare(fuzzy_hash, known_hash)
                    if score > 30:  # 30% similarity threshold
                        similarities.append({
                            "sample": name,
                            "similarity": score
                        })
                
                if similarities:
                    self.results["similar_samples"] = similarities
                    
        except Exception as e:
            logger.warning(f"Fuzzy hashing failed: {e}")
    
    def _extract_urls(self, strings: List[str]) -> List[str]:
        """Extract URLs from strings"""
        import re
        url_pattern = re.compile(
            r'https?://[^\s<>"{}|\\^`\[\]]+|'
            r'ftp://[^\s<>"{}|\\^`\[\]]+'
        )
        
        urls = []
        for s in strings:
            matches = url_pattern.findall(s)
            urls.extend(matches)
        
        return list(set(urls))[:50]  # Limit to 50 unique URLs
    
    def _extract_ips(self, strings: List[str]) -> List[str]:
        """Extract IP addresses"""
        import re
        ip_pattern = re.compile(
            r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        )
        
        ips = []
        for s in strings:
            matches = ip_pattern.findall(s)
            ips.extend(matches)
        
        # Filter out common local IPs
        filtered = [ip for ip in ips 
                   if not ip.startswith(('127.', '0.', '255.'))]
        
        return list(set(filtered))[:50]
    
    def _extract_emails(self, strings: List[str]) -> List[str]:
        """Extract email addresses"""
        import re
        email_pattern = re.compile(
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        )
        
        emails = []
        for s in strings:
            matches = email_pattern.findall(s)
            emails.extend(matches)
        
        return list(set(emails))[:20]
    
    def _extract_paths(self, strings: List[str]) -> List[str]:
        """Extract file paths"""
        paths = []
        for s in strings:
            if (':\\' in s or '\\\\' in s) and len(s) > 10:
                paths.append(s)
        
        return paths[:50]
    
    def _extract_registry(self, strings: List[str]) -> List[str]:
        """Extract registry keys"""
        reg_keys = []
        reg_prefixes = ['HKEY_', 'HKLM\\', 'HKCU\\', 'Software\\', 'System\\']
        
        for s in strings:
            if any(prefix in s for prefix in reg_prefixes):
                reg_keys.append(s)
        
        return reg_keys[:30]
    
    def _find_interesting_strings(self, strings: List[str]) -> List[str]:
        """Find interesting/suspicious strings with improved accuracy"""
        interesting = []
        
        # More specific suspicious terms with context requirements
        high_confidence_terms = [
            'ransomware', 'keylogger', 'backdoor', 'rootkit', 'bootkit'
        ]
        
        medium_confidence_terms = [
            'bitcoin', 'cryptocurrency', 'tor.exe', 'payload', 
            'privilege escalation', 'process injection'
        ]
        
        # Context-dependent terms (need longer strings to avoid false positives)
        context_terms = [
            ('encrypt', 10),  # At least 10 chars
            ('decrypt', 10),
            ('password', 15),
            ('screenshot', 12),
            ('webcam', 8),
            ('steal', 12),
            ('inject', 15),
            ('hook', 12),
            ('persistence', 15)
        ]
        
        # Check high confidence terms
        for s in strings:
            s_lower = s.lower()
            for term in high_confidence_terms:
                if term in s_lower and len(s) > 5:
                    interesting.append(f"[HIGH] {s}")
                    break
        
        # Check medium confidence terms  
        for s in strings:
            s_lower = s.lower()
            for term in medium_confidence_terms:
                if term in s_lower and len(s) > 8:
                    interesting.append(f"[MED] {s}")
                    break
        
        # Check context-dependent terms
        for s in strings:
            s_lower = s.lower()
            for term, min_len in context_terms:
                if term in s_lower and len(s) >= min_len:
                    # Additional context checks
                    if ('file' in s_lower or 'data' in s_lower or 
                        'user' in s_lower or 'system' in s_lower):
                        interesting.append(f"[CTX] {s}")
                        break
        
        # Anti-analysis strings (more specific)
        anti_analysis = [
            'VirtualBox', 'VMware', 'QEMU', 'Xen',
            'Sandboxie', 'Cuckoo', 'Joe Sandbox',
            'Wireshark', 'ProcessMonitor', 'Procmon',
            'IDA Pro', 'OllyDbg', 'x64dbg', 'Immunity Debugger',
            'Virtual Machine', 'VM detected'
        ]
        
        for s in strings:
            for term in anti_analysis:
                if term in s and len(s) > len(term):
                    interesting.append(f"[Anti-Analysis] {s}")
                    break
        
        # Remove duplicates and limit results
        unique_interesting = []
        seen = set()
        for item in interesting:
            if item not in seen:
                seen.add(item)
                unique_interesting.append(item)
        
        return unique_interesting[:30]  # Reduced limit
    
    def _assess_risk(self):
        """Assess risk level based on findings with improved accuracy"""
        risk_score = 0
        risk_factors = []
        
        # Check PE anomalies (moderate impact)
        if "pe_info" in self.results:
            if self.results["pe_info"].get("anomalies"):
                risk_score += 15  # Reduced from 20
                risk_factors.append("PE anomalies detected")
            
            # Check for suspicious imports (be more selective)
            imports = self.results["pe_info"].get("imports", {})
            dangerous_imports = {
                "kernel32.dll": ["VirtualAlloc", "VirtualAllocEx", "WriteProcessMemory", 
                               "CreateRemoteThread", "OpenProcess", "ReadProcessMemory"],
                "ntdll.dll": ["NtCreateSection", "NtMapViewOfSection", "NtUnmapViewOfSection",
                             "NtCreateProcess", "NtCreateThread"],
                "advapi32.dll": ["AdjustTokenPrivileges", "LookupPrivilegeValue", 
                                "OpenProcessToken", "CreateService"],
                "user32.dll": ["SetWindowsHookEx", "GetAsyncKeyState", "RegisterHotKey"]
            }
            
            dangerous_count = 0
            for dll, funcs in imports.items():
                dll_lower = dll.lower()
                if dll_lower in dangerous_imports:
                    for func in funcs:
                        if func in dangerous_imports[dll_lower]:
                            dangerous_count += 1
                            if dangerous_count <= 3:  # Only report first few
                                risk_factors.append(f"Dangerous import: {dll}!{func}")
            
            # Scale risk based on number of dangerous imports
            if dangerous_count >= 5:
                risk_score += 25
            elif dangerous_count >= 3:
                risk_score += 15
            elif dangerous_count >= 1:
                risk_score += 8
        
        # Check capabilities (capa findings are generally reliable)
        if "capabilities" in self.results:
            attack_techniques = self.results["capabilities"].get("attack_techniques", [])
            matched_rules = self.results["capabilities"].get("matched_rules", [])
            
            # Weight by technique severity
            critical_techniques = ["T1055", "T1027", "T1082", "T1083", "T1012"]  # Process injection, obfuscation, etc.
            critical_count = sum(1 for tech in attack_techniques if tech in critical_techniques)
            
            risk_score += critical_count * 15  # Critical techniques
            risk_score += (len(attack_techniques) - critical_count) * 8  # Other techniques
            
            if attack_techniques:
                risk_factors.append(f"{len(attack_techniques)} ATT&CK techniques detected")
                if critical_count > 0:
                    risk_factors.append(f"{critical_count} critical techniques")
        
        # Check YARA matches (weight by rule type)
        if "yara_matches" in self.results and self.results["yara_matches"]:
            high_confidence_rules = 0
            for match in self.results["yara_matches"]:
                rule_name = match.get("rule", "").lower()
                # Count high-confidence rule patterns
                if any(pattern in rule_name for pattern in ["malware", "trojan", "backdoor", "ransomware"]):
                    high_confidence_rules += 1
            
            risk_score += high_confidence_rules * 20  # High confidence matches
            risk_score += (len(self.results["yara_matches"]) - high_confidence_rules) * 8  # Other matches
            
            risk_factors.append(f"{len(self.results['yara_matches'])} YARA rule matches")
            if high_confidence_rules > 0:
                risk_factors.append(f"{high_confidence_rules} high-confidence matches")
        
        # Check strings (be much more conservative)
        if "strings" in self.results:
            interesting_strings = self.results["strings"].get("interesting", [])
            if interesting_strings:
                # Weight by string categories
                high_risk_count = sum(1 for s in interesting_strings if s.startswith("[HIGH]"))
                medium_risk_count = sum(1 for s in interesting_strings if s.startswith("[MED]"))
                context_count = sum(1 for s in interesting_strings if s.startswith("[CTX]"))
                anti_analysis_count = sum(1 for s in interesting_strings if s.startswith("[Anti-Analysis]"))
                
                risk_score += high_risk_count * 12
                risk_score += medium_risk_count * 6
                risk_score += context_count * 3
                risk_score += anti_analysis_count * 8
                
                if interesting_strings:
                    categories = []
                    if high_risk_count > 0:
                        categories.append(f"{high_risk_count} high-risk")
                    if medium_risk_count > 0:
                        categories.append(f"{medium_risk_count} medium-risk")
                    if anti_analysis_count > 0:
                        categories.append(f"{anti_analysis_count} anti-analysis")
                    
                    risk_factors.append(f"Suspicious strings: {', '.join(categories)}")
        
        # Determine risk level with adjusted thresholds
        if risk_score >= 100:
            risk_level = "CRITICAL"
        elif risk_score >= 70:
            risk_level = "HIGH"
        elif risk_score >= 45:
            risk_level = "MEDIUM"
        elif risk_score >= 20:
            risk_level = "LOW"
        else:
            risk_level = "MINIMAL"
        
        self.results["risk_assessment"] = {
            "score": risk_score,
            "level": risk_level,
            "factors": risk_factors
        }
    
    def _generate_recommendations(self):
        """Generate comprehensive analysis recommendations based on findings"""
        recommendations = {
            # VM Configuration
            "vm_profile": "default",
            "vm_snapshots": ["pre_execution", "post_execution"],
            "vm_resources": {"ram_mb": 2048, "cpu_cores": 2},
            
            # Analysis Settings
            "analysis_duration": 300,
            "analysis_phases": ["static", "behavioral", "network"],
            "priority": "MEDIUM",
            
            # Security Settings
            "network_isolation": False,
            "internet_access": False,
            "host_interaction": False,
            
            # Monitoring Focus
            "monitoring_focus": [],
            "behavioral_hooks": [],
            "network_monitoring": [],
            
            # Additional Tools
            "additional_tools": [],
            "unpacking_tools": [],
            "decryption_tools": [],
            
            # Safety Measures
            "safety_measures": [],
            "risk_mitigations": [],
            
            # Analysis Strategy
            "strategy": "standard",
            "automation_level": "medium",
            
            # Reporting
            "report_format": ["json", "pdf"],
            "alert_thresholds": {},
            
            # Reasoning (for transparency)
            "reasoning": []
        }
        
        # Get analysis results for decision making
        risk_level = self.results["risk_assessment"]["level"]
        risk_score = self.results["risk_assessment"]["score"]
        risk_factors = self.results["risk_assessment"]["factors"]
        
        # Base recommendations by risk level
        self._apply_risk_based_recommendations(recommendations, risk_level, risk_score)
        
        # PE-specific recommendations
        if "pe_info" in self.results:
            self._apply_pe_recommendations(recommendations)
        
        # Capability-based recommendations
        if "capabilities" in self.results:
            self._apply_capability_recommendations(recommendations)
        
        # YARA-based recommendations
        if "yara_matches" in self.results:
            self._apply_yara_recommendations(recommendations)
        
        # String-based recommendations
        if "strings" in self.results:
            self._apply_string_recommendations(recommendations)
        
        # File type specific recommendations
        self._apply_filetype_recommendations(recommendations)
        
        # Validate and optimize recommendations
        self._optimize_recommendations(recommendations)
        
        self.results["recommendations"] = recommendations
    
    def _apply_risk_based_recommendations(self, recommendations, risk_level, risk_score):
        """Apply recommendations based on overall risk assessment"""
        if risk_level == "CRITICAL":
            recommendations["vm_profile"] = "maximum_security"
            recommendations["analysis_duration"] = 900  # 15 minutes
            recommendations["priority"] = "CRITICAL"
            recommendations["network_isolation"] = True
            recommendations["host_interaction"] = False
            recommendations["vm_resources"]["ram_mb"] = 4096
            recommendations["vm_snapshots"].append("mid_execution")
            recommendations["safety_measures"].extend([
                "isolated_network", "encrypted_storage", "auto_revert"
            ])
            recommendations["automation_level"] = "high"
            recommendations["reasoning"].append(f"Critical risk (score: {risk_score}) requires maximum security")
            
        elif risk_level == "HIGH":
            recommendations["vm_profile"] = "evasive_malware"
            recommendations["analysis_duration"] = 600  # 10 minutes
            recommendations["priority"] = "HIGH"
            recommendations["network_isolation"] = True
            recommendations["internet_access"] = True  # Controlled internet for C2 detection
            recommendations["vm_resources"]["ram_mb"] = 3072
            recommendations["safety_measures"].extend([
                "network_monitoring", "behavior_analysis"
            ])
            recommendations["reasoning"].append(f"High risk (score: {risk_score}) needs enhanced monitoring")
            
        elif risk_level == "MEDIUM":
            recommendations["vm_profile"] = "standard_analysis"
            recommendations["analysis_duration"] = 450
            recommendations["priority"] = "MEDIUM"
            recommendations["internet_access"] = True
            recommendations["safety_measures"].append("behavior_monitoring")
            recommendations["reasoning"].append(f"Medium risk (score: {risk_score}) requires standard analysis")
            
        elif risk_level == "LOW":
            recommendations["analysis_duration"] = 300
            recommendations["priority"] = "LOW"
            recommendations["automation_level"] = "high"
            recommendations["reasoning"].append(f"Low risk (score: {risk_score}) suitable for automated analysis")
            
        else:  # MINIMAL
            recommendations["analysis_duration"] = 180
            recommendations["priority"] = "LOW"
            recommendations["automation_level"] = "high"
            recommendations["strategy"] = "quick_scan"
            recommendations["reasoning"].append(f"Minimal risk (score: {risk_score}) needs basic analysis only")
    
    def _apply_pe_recommendations(self, recommendations):
        """Apply PE-specific recommendations"""
        pe_info = self.results["pe_info"]
        
        # Check for packing/obfuscation
        high_entropy_sections = [s for s in pe_info.get("sections", []) 
                               if s.get("entropy", 0) > 7.0]
        
        if high_entropy_sections:
            recommendations["additional_tools"].extend(["upx", "vmunprot", "generic_unpacker"])
            recommendations["unpacking_tools"].extend(["upx", "aspack", "mpress"])
            recommendations["monitoring_focus"].extend([
                "process_injection", "memory_allocation", "dynamic_loading"
            ])
            recommendations["behavioral_hooks"].extend([
                "VirtualAlloc", "VirtualAllocEx", "WriteProcessMemory"
            ])
            recommendations["analysis_duration"] += 120  # Extra time for unpacking
            recommendations["reasoning"].append(
                f"Detected {len(high_entropy_sections)} high-entropy sections - likely packed"
            )
        
        # Check imports for specific behaviors
        imports = pe_info.get("imports", {})
        
        # Crypto-related imports
        crypto_dlls = ["advapi32.dll", "bcrypt.dll", "ncrypt.dll"]
        crypto_functions = ["CryptGenKey", "CryptEncrypt", "CryptDecrypt", "BCryptGenerateSymmetricKey"]
        
        has_crypto = False
        for dll, funcs in imports.items():
            if dll.lower() in crypto_dlls:
                for func in funcs:
                    if any(cf in func for cf in crypto_functions):
                        has_crypto = True
                        break
        
        if has_crypto:
            recommendations["monitoring_focus"].extend([
                "file_encryption", "registry_encryption", "crypto_operations"
            ])
            recommendations["decryption_tools"].append("ransomware_decryptor")
            recommendations["reasoning"].append("Cryptographic imports detected - possible encryption capability")
        
        # Anti-analysis imports
        anti_analysis_funcs = ["IsDebuggerPresent", "CheckRemoteDebuggerPresent", "GetTickCount"]
        has_anti_analysis = any(
            any(func in funcs for func in anti_analysis_funcs)
            for funcs in imports.values()
        )
        
        if has_anti_analysis:
            recommendations["vm_profile"] = "evasive_malware"
            recommendations["additional_tools"].append("anti_anti_debug")
            recommendations["monitoring_focus"].append("evasion_techniques")
            recommendations["reasoning"].append("Anti-analysis functions detected - evasive behavior expected")
    
    def _apply_capability_recommendations(self, recommendations):
        """Apply capa capability-based recommendations"""
        capabilities = self.results["capabilities"]
        attack_techniques = capabilities.get("attack_techniques", [])
        matched_rules = capabilities.get("matched_rules", [])
        
        # Map ATT&CK techniques to specific recommendations
        technique_mapping = {
            "T1055": {  # Process Injection
                "monitoring": ["process_injection", "memory_modification"],
                "hooks": ["CreateRemoteThread", "WriteProcessMemory", "VirtualAllocEx"],
                "tools": ["process_monitor"],
                "reason": "Process injection techniques detected"
            },
            "T1027": {  # Obfuscated Files or Information
                "tools": ["unpacker", "deobfuscator"],
                "monitoring": ["file_decryption", "string_decoding"],
                "reason": "Obfuscation capabilities detected"
            },
            "T1082": {  # System Information Discovery
                "monitoring": ["system_enumeration", "hardware_detection"],
                "vm_profile": "realistic_environment",
                "reason": "System discovery capabilities - may detect analysis environment"
            },
            "T1083": {  # File and Directory Discovery
                "monitoring": ["file_enumeration", "directory_scanning"],
                "reason": "File discovery capabilities detected"
            },
            "T1012": {  # Query Registry
                "monitoring": ["registry_access", "registry_enumeration"],
                "hooks": ["RegQueryValue", "RegEnumKey"],
                "reason": "Registry query capabilities detected"
            },
            "T1486": {  # Data Encrypted for Impact (Ransomware)
                "vm_profile": "ransomware_analysis",
                "monitoring": ["file_encryption", "shadow_deletion", "volume_operations"],
                "hooks": ["DeleteFile", "CryptEncrypt", "vssadmin"],
                "additional_duration": 300,
                "safety": "maximum_isolation",
                "reason": "Ransomware capabilities detected - high impact potential"
            }
        }
        
        for technique in attack_techniques:
            if technique in technique_mapping:
                mapping = technique_mapping[technique]
                
                if "monitoring" in mapping:
                    recommendations["monitoring_focus"].extend(mapping["monitoring"])
                
                if "hooks" in mapping:
                    recommendations["behavioral_hooks"].extend(mapping["hooks"])
                
                if "tools" in mapping:
                    recommendations["additional_tools"].extend(mapping["tools"])
                
                if "vm_profile" in mapping:
                    recommendations["vm_profile"] = mapping["vm_profile"]
                
                if "additional_duration" in mapping:
                    recommendations["analysis_duration"] += mapping["additional_duration"]
                
                if "safety" in mapping:
                    recommendations["safety_measures"].append(mapping["safety"])
                
                recommendations["reasoning"].append(mapping["reason"])
        
        # Special handling for ransomware
        ransomware_indicators = [
            "encrypt", "ransom", "bitcoin", "payment", "decrypt", "key"
        ]
        
        rule_names = [rule.get("name", "").lower() for rule in matched_rules]
        if any(indicator in " ".join(rule_names) for indicator in ransomware_indicators):
            recommendations["vm_profile"] = "ransomware_analysis"
            recommendations["priority"] = "CRITICAL"
            recommendations["network_isolation"] = True
            recommendations["monitoring_focus"].extend([
                "file_encryption", "shadow_deletion", "backup_deletion"
            ])
            recommendations["safety_measures"].append("offline_analysis")
            recommendations["reasoning"].append("Ransomware indicators in capability analysis")
    
    def _apply_yara_recommendations(self, recommendations):
        """Apply YARA rule-based recommendations"""
        yara_matches = self.results["yara_matches"]
        
        # Analyze rule matches for specific malware families
        rule_names = [match.get("rule", "").lower() for match in yara_matches]
        
        # APT-related rules
        apt_keywords = ["apt", "lazarus", "carbanak", "fin", "cozy", "fancy"]
        if any(keyword in name for name in rule_names for keyword in apt_keywords):
            recommendations["priority"] = "CRITICAL"
            recommendations["analysis_duration"] = 1200  # 20 minutes
            recommendations["vm_profile"] = "apt_analysis"
            recommendations["monitoring_focus"].extend([
                "persistence_mechanisms", "lateral_movement", "data_exfiltration"
            ])
            recommendations["reasoning"].append("APT-related YARA rules matched")
        
        # Banking Trojans
        banking_keywords = ["banker", "banking", "financial", "zeus", "dridex"]
        if any(keyword in name for name in rule_names for keyword in banking_keywords):
            recommendations["monitoring_focus"].extend([
                "browser_hooks", "form_grabbing", "certificate_theft"
            ])
            recommendations["network_monitoring"].extend([
                "https_interception", "banking_domains"
            ])
            recommendations["reasoning"].append("Banking trojan signatures detected")
        
        # Stealer malware
        stealer_keywords = ["stealer", "infostealer", "credential", "password"]
        if any(keyword in name for name in rule_names for keyword in stealer_keywords):
            recommendations["monitoring_focus"].extend([
                "credential_theft", "browser_data", "keylogging"
            ])
            recommendations["reasoning"].append("Information stealer patterns detected")
    
    def _apply_string_recommendations(self, recommendations):
        """Apply string analysis-based recommendations"""
        strings_info = self.results["strings"]
        
        # Check for C2 infrastructure
        urls = strings_info.get("urls", [])
        ips = strings_info.get("ips", [])
        
        if urls or ips:
            recommendations["network_monitoring"].extend([
                "dns_queries", "http_requests", "suspicious_domains"
            ])
            recommendations["internet_access"] = True  # Allow controlled internet for C2 analysis
            
            if len(urls) > 5 or len(ips) > 3:
                recommendations["analysis_duration"] += 180  # Extra time for network analysis
                recommendations["reasoning"].append(
                    f"Multiple network indicators ({len(urls)} URLs, {len(ips)} IPs)"
                )
        
        # Check for interesting strings
        interesting = strings_info.get("interesting", [])
        high_risk_strings = [s for s in interesting if s.startswith("[HIGH]")]
        anti_analysis_strings = [s for s in interesting if s.startswith("[Anti-Analysis]")]
        
        if anti_analysis_strings:
            recommendations["vm_profile"] = "evasive_malware"
            recommendations["additional_tools"].append("anti_evasion")
            recommendations["reasoning"].append(
                f"Anti-analysis strings detected: {len(anti_analysis_strings)}"
            )
    
    def _apply_filetype_recommendations(self, recommendations):
        """Apply file type-specific recommendations"""
        file_info = self.results["file_info"]
        extension = file_info.get("extension", "").lower()
        file_size = file_info.get("size", 0)
        
        # Large files need more resources
        if file_size > 50 * 1024 * 1024:  # 50MB+
            recommendations["vm_resources"]["ram_mb"] = max(
                recommendations["vm_resources"]["ram_mb"], 4096
            )
            recommendations["analysis_duration"] += 120
            recommendations["reasoning"].append(f"Large file size ({file_size // (1024*1024)}MB)")
        
        # Specific file types
        if extension in [".scr", ".pif", ".com"]:
            recommendations["monitoring_focus"].append("masquerading")
            recommendations["reasoning"].append(f"Suspicious extension: {extension}")
        
        if extension in [".docm", ".xlsm", ".pptm"]:
            recommendations["additional_tools"].extend(["oletools", "macro_analysis"])
            recommendations["monitoring_focus"].append("macro_execution")
            recommendations["reasoning"].append("Macro-enabled Office document")
        
        if extension == ".pdf":
            recommendations["additional_tools"].extend(["pdf_analysis", "js_analysis"])
            recommendations["monitoring_focus"].append("pdf_exploits")
            recommendations["reasoning"].append("PDF document - potential exploit vector")
    
    def _optimize_recommendations(self, recommendations):
        """Optimize and validate recommendations"""
        # Remove duplicates
        for key in ["monitoring_focus", "behavioral_hooks", "additional_tools", 
                   "safety_measures", "network_monitoring"]:
            recommendations[key] = list(set(recommendations[key]))
        
        # Ensure reasonable duration limits
        recommendations["analysis_duration"] = min(recommendations["analysis_duration"], 1800)  # Max 30 min
        recommendations["analysis_duration"] = max(recommendations["analysis_duration"], 120)   # Min 2 min
        
        # Validate VM profile consistency
        if recommendations["priority"] == "CRITICAL" and recommendations["vm_profile"] == "default":
            recommendations["vm_profile"] = "maximum_security"
            recommendations["reasoning"].append("Upgraded VM profile for critical priority")
        
        # Ensure network settings are consistent
        if recommendations["network_isolation"] and recommendations["internet_access"]:
            recommendations["internet_access"] = False
            recommendations["reasoning"].append("Disabled internet access due to network isolation")
        
        # Add summary
        recommendations["summary"] = self._generate_recommendation_summary(recommendations)
    
    def _generate_recommendation_summary(self, recommendations):
        """Generate human-readable summary of recommendations"""
        summary_parts = []
        
        # Risk and priority
        risk_level = self.results["risk_assessment"]["level"]
        priority = recommendations["priority"]
        summary_parts.append(f"{risk_level} risk sample requiring {priority} priority analysis")
        
        # Analysis approach
        vm_profile = recommendations["vm_profile"]
        duration_min = recommendations["analysis_duration"] // 60
        summary_parts.append(f"Use {vm_profile} VM profile for {duration_min} minutes")
        
        # Security measures
        security_measures = []
        if recommendations["network_isolation"]:
            security_measures.append("network isolation")
        if not recommendations["host_interaction"]:
            security_measures.append("no host interaction")
        if recommendations["safety_measures"]:
            security_measures.extend(recommendations["safety_measures"][:2])  # Top 2
        
        if security_measures:
            summary_parts.append(f"Security: {', '.join(security_measures)}")
        
        # Key monitoring areas
        if recommendations["monitoring_focus"]:
            top_monitoring = recommendations["monitoring_focus"][:3]  # Top 3
            summary_parts.append(f"Monitor: {', '.join(top_monitoring)}")
        
        # Additional tools
        if recommendations["additional_tools"]:
            summary_parts.append(f"Tools: {', '.join(recommendations['additional_tools'][:3])}")
        
        return ". ".join(summary_parts) + "."
    
    def _save_results(self, output_dir: str):
        """Save analysis results"""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        result_file = output_path / f"static_analysis_{self.sample_hash}.json"
        
        with open(result_file, 'w') as f:
            json.dump(self.results, f, indent=2, default=str)
        
        logger.info(f"Results saved to: {result_file}")


# Integration functions
def analyze_sample_safe(sample_path: str, 
                        config: Dict = None,
                        quick: bool = False) -> Dict:
    """
    Safe wrapper for static analysis
    
    Args:
        sample_path: Path to sample
        config: Configuration
        quick: Quick triage mode
        
    Returns:
        Analysis results
    """
    analyzer = StaticAnalyzer(config)
    return analyzer.analyze_sample(sample_path, skip_expensive=quick)


def assess_sample_risk(sample_path: str) -> Tuple[str, int]:
    """
    Quick risk assessment
    
    Returns:
        (risk_level, risk_score)
    """
    analyzer = StaticAnalyzer()
    results = analyzer.analyze_sample(sample_path, skip_expensive=True)
    
    risk = results.get("risk_assessment", {})
    return risk.get("level", "UNKNOWN"), risk.get("score", 0)

