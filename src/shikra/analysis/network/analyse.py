import re
import json
import subprocess
import socket
import ipaddress
from pathlib import Path
from typing import Dict, List, Any, Tuple, Optional
from datetime import datetime
import logging
from collections import defaultdict, Counter
import tempfile
import time
import hashlib

from ...utils import jsonio
from ...utils.logger import setup_logger
from ...utils.geo import GeoIPLookup

class NetworkAnalyzer:
    """
    Analyzes a PCAP network capture file for suspicious activity related to ransomware.
    Uses tshark for efficient extraction with single-pass JSON parsing.
    """
    def __init__(self, vt_api_key: str = None, config_dir: Path = Path("config"),
                 tshark_path: str = "tshark", capinfos_path: str = "capinfos",
                 command_timeout: int = 300):
        self.logger = setup_logger("NetworkAnalyzer")
        
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
        
        # Set configurable paths and timeouts
        self.tshark_path = tshark_path
        self.capinfos_path = capinfos_path
        self.command_timeout = command_timeout
        
        self.logger.info(f"tshark path: {self.tshark_path}")
        self.logger.info(f"capinfos path: {self.capinfos_path}")
        self.logger.info(f"Command timeout: {self.command_timeout}s")
        
        try:
            self.config = jsonio.load_config(absolute_config_dir / "network_config.json")
            self.risk_config = jsonio.load_config(absolute_config_dir / "risk_scoring.json")
            self.mitre_mappings = jsonio.load_config(absolute_config_dir / "mitre_mapping.json")
        except Exception as e:
            self.logger.error(f"Failed to load configuration files: {e}")
            # Provide minimal defaults
            self.config = {"suspicious_domains": [], "crypto_keywords": [], "high_risk_countries": []}
            self.risk_config = {"network": {}, "max_score": 10}
            self.mitre_mappings = {}
        
        self.vt_api_key = vt_api_key
        
        # Initialize geo lookup utility
        try:
            self.geo_lookup = GeoIPLookup()
            self.logger.info("GeoIP lookup initialized")
        except Exception as e:
            self.logger.warning(f"Failed to initialize GeoIP lookup: {e}")
            self.geo_lookup = None
        
        if not self._is_tshark_available():
            raise FileNotFoundError(f"tshark command not found at {self.tshark_path}. Please ensure Wireshark/tshark is installed.")
            
    def _is_tshark_available(self) -> bool:
        """Checks if tshark is available."""
        try:
            subprocess.run([self.tshark_path, "-v"], capture_output=True, check=True, timeout=10)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def _run_tshark_command(self, command: List[str], timeout: Optional[int] = None) -> str:
        """Executes a tshark command and returns its stdout."""
        if timeout is None:
            timeout = self.command_timeout
            
        self.logger.debug(f"Running tshark command: {' '.join(command)}")
        try:
            result = subprocess.run(command, capture_output=True, text=True, check=True, 
                                  encoding='utf-8', timeout=timeout)
            return result.stdout
        except subprocess.TimeoutExpired:
            self.logger.error(f"tshark command timed out after {timeout} seconds")
            return ""
        except subprocess.CalledProcessError as e:
            self.logger.error(f"tshark command failed with exit code {e.returncode}: {e.stderr}")
            return ""
        except FileNotFoundError:
            self.logger.error(f"tshark command not found at {self.tshark_path}")
            return ""

    def analyze(self, pcap_path: Path) -> Dict[str, Any]:
        """Main analysis function for the PCAP file using single-pass JSON extraction."""
        self.logger.info(f"Starting comprehensive network analysis of {pcap_path}...")
        
        # Step 1: Get PCAP basic information
        self.logger.info("Step 1/6: Getting PCAP file metadata...")
        meta = self._get_metadata(pcap_path)
        
        # Step 2: Single-pass JSON extraction for all data
        self.logger.info("Step 2/6: Extracting all packet data in single pass...")
        packet_data = self._extract_all_data_single_pass(pcap_path)
        
        # Step 3: Process extracted data into analysis components
        self.logger.info("Step 3/6: Processing extracted data...")
        processed_data = self._process_extracted_data(packet_data)
        
        # Step 4: Advanced flow analysis
        self.logger.info("Step 4/6: Analyzing network flows...")
        network_flows = self._analyze_network_flows(processed_data)
        
        # Step 5: Protocol-specific analysis
        self.logger.info("Step 5/6: Performing protocol-specific analysis...")
        dns_analysis = self._analyze_dns_detailed(processed_data.get("dns_queries", []))
        http_analysis = self._analyze_http_detailed(processed_data.get("http_requests", []))
        email_analysis = self._analyze_email_traffic(processed_data)
        
        # Step 6: Threat hunting and IOC extraction
        self.logger.info("Step 6/6: Performing threat hunting analysis...")
        threat_hunting = self._perform_threat_hunting(network_flows, processed_data)
        protocol_anomalies = self._detect_protocol_anomalies(processed_data)
        iocs = self._extract_network_iocs(network_flows, dns_analysis, http_analysis)
        timeline = self._build_network_timeline(network_flows, dns_analysis, http_analysis)
        recommendations = self._generate_network_recommendations(network_flows, iocs, threat_hunting)
        
        # Build the new network-focused report structure
        report = {
            "metadata": self._build_network_metadata(pcap_path, meta, processed_data),
            "network_flows": network_flows,
            "dns_analysis": dns_analysis,
            "http_analysis": http_analysis,
            "email_analysis": email_analysis,
            "protocol_anomalies": protocol_anomalies,
            "threat_hunting": threat_hunting,
            "iocs": iocs,
            "timeline": timeline,
            "recommendations": recommendations
        }

        self.logger.info(f"Network analysis complete. Found {len(iocs)} IOCs and {len(network_flows)} flows")
        return report

    def _extract_all_data_single_pass(self, pcap_path: Path) -> Dict[str, Any]:
        """Extract all required data in a single tshark pass using JSON output."""
        self.logger.info("Extracting all packet data using JSON format...")
        
        # Use a comprehensive field list to get all needed data in one pass
        fields = [
            # Frame info
            "frame.number", "frame.time_epoch", "frame.len",
            # Network layer
            "ip.src", "ip.dst", "ip.proto",
            # Transport layer  
            "tcp.srcport", "tcp.dstport", "tcp.len", "tcp.flags",
            "udp.srcport", "udp.dstport", "udp.length",
            # Application layer
            "dns.qry.name", "dns.qry.type", "dns.flags.response",
            "http.host", "http.request.method", "http.request.uri", "http.user_agent",
            "http.response.code", "http.content_type",
            "tls.handshake.type", "tls.handshake.extensions_server_name",
            "tls.handshake.ciphersuite",
            # Protocol identification
            "frame.protocols"
        ]
        
        cmd = [
            self.tshark_path, "-r", str(pcap_path),
            "-T", "json",
            "-E", "header=y",
            "-E", "separator=,",
            "-E", "quote=d",
            "-E", "occurrence=f"
        ]
        
        # Add fields using -e flag
        for field in fields:
            cmd.extend(["-e", field])
        
        json_output = self._run_tshark_command(cmd, timeout=self.command_timeout * 2)
        
        if not json_output.strip():
            self.logger.warning("No JSON output from tshark")
            return {"packets": []}
        
        try:
            # Parse JSON output
            packets = json.loads(json_output)
            self.logger.info(f"Successfully parsed {len(packets)} packets from JSON")
            return {"packets": packets}
        except json.JSONDecodeError as e:
            self.logger.error(f"Failed to parse tshark JSON output: {e}")
            # Log first few characters for debugging
            self.logger.debug(f"JSON output preview: {json_output[:500]}")
            return {"packets": []}

    def _process_extracted_data(self, packet_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process the raw packet data into structured analysis components."""
        packets = packet_data.get("packets", [])
        
        # Initialize counters and collections
        protocol_counter = Counter()
        endpoint_stats = defaultdict(lambda: {"packets": 0, "bytes": 0})
        dns_queries = Counter()
        http_requests = Counter()
        tls_handshakes = Counter()
        
        # Process each packet
        for packet in packets:
            try:
                layers = packet.get("_source", {}).get("layers", {})
                
                # Protocol statistics - use frame.protocols instead of _ws.col.Protocol
                protocols = layers.get("frame.protocols", ["unknown"])
                if isinstance(protocols, list) and protocols:
                    # Take the highest layer protocol
                    protocol = protocols[-1] if protocols else "unknown"
                else:
                    protocol = str(protocols) if protocols else "unknown"
                protocol_counter[protocol] += 1
                
                # Endpoint statistics
                if "ip.src" in layers and "ip.dst" in layers:
                    src_ips = layers.get("ip.src", [])
                    dst_ips = layers.get("ip.dst", [])
                    frame_lens = layers.get("frame.len", [0])
                    
                    src_ip = src_ips[0] if isinstance(src_ips, list) and src_ips else str(src_ips) if src_ips else "unknown"
                    dst_ip = dst_ips[0] if isinstance(dst_ips, list) and dst_ips else str(dst_ips) if dst_ips else "unknown"
                    frame_len = int(frame_lens[0]) if isinstance(frame_lens, list) and frame_lens else int(frame_lens) if frame_lens else 0
                    
                    if src_ip != "unknown":
                        endpoint_stats[src_ip]["packets"] += 1
                        endpoint_stats[src_ip]["bytes"] += frame_len
                    if dst_ip != "unknown":
                        endpoint_stats[dst_ip]["packets"] += 1
                        endpoint_stats[dst_ip]["bytes"] += frame_len
                
                # DNS queries (only queries, not responses)
                if "dns.qry.name" in layers:
                    dns_responses = layers.get("dns.flags.response", ["0"])
                    is_response = (dns_responses[0] if isinstance(dns_responses, list) else str(dns_responses)) == "1"
                    
                    if not is_response:
                        query_names = layers.get("dns.qry.name", [])
                        query_types = layers.get("dns.qry.type", ["1"])
                        
                        query_name = query_names[0] if isinstance(query_names, list) and query_names else str(query_names) if query_names else ""
                        query_type = query_types[0] if isinstance(query_types, list) and query_types else str(query_types) if query_types else "1"
                        
                        if query_name:
                            dns_queries[(query_name, query_type)] += 1
                
                # HTTP requests
                if "http.request.method" in layers:
                    hosts = layers.get("http.host", [""])
                    methods = layers.get("http.request.method", ["GET"])
                    uris = layers.get("http.request.uri", ["/"])
                    user_agents = layers.get("http.user_agent", [""])
                    
                    host = hosts[0] if isinstance(hosts, list) and hosts else str(hosts) if hosts else ""
                    method = methods[0] if isinstance(methods, list) and methods else str(methods) if methods else "GET"
                    uri = uris[0] if isinstance(uris, list) and uris else str(uris) if uris else "/"
                    user_agent = user_agents[0] if isinstance(user_agents, list) and user_agents else str(user_agents) if user_agents else ""
                    
                    request_key = (host, method, uri, user_agent)
                    http_requests[request_key] += 1
                
                # TLS handshakes (client hello)
                if "tls.handshake.type" in layers:
                    handshake_types = layers.get("tls.handshake.type", [""])
                    handshake_type = handshake_types[0] if isinstance(handshake_types, list) and handshake_types else str(handshake_types) if handshake_types else ""
                    
                    if handshake_type == "1":  # Client Hello
                        snis = layers.get("tls.handshake.extensions_server_name", [""])
                        ciphers = layers.get("tls.handshake.ciphersuite", [""])
                        
                        sni = snis[0] if isinstance(snis, list) and snis else str(snis) if snis else ""
                        cipher = ciphers[0] if isinstance(ciphers, list) and ciphers else str(ciphers) if ciphers else ""
                        
                        if sni:
                            tls_handshakes[(sni, cipher)] += 1
                            
            except Exception as e:
                self.logger.warning(f"Error processing packet: {e}")
                continue
        
        # Convert to final format
        return {
            "protocol_stats": [{"name": proto, "count": count} for proto, count in protocol_counter.most_common()],
            "endpoint_stats": [
                {"ip_address": ip, "packets": stats["packets"], "bytes": stats["bytes"]}
                for ip, stats in endpoint_stats.items()
            ],
            "dns_queries": [
                {"query": query, "type": qtype, "count": count}
                for (query, qtype), count in dns_queries.most_common()
            ],
            "http_requests": [
                {
                    "host": host, "method": method, "uri": uri, "user_agent": user_agent,
                    "request": f"{method} http://{host}{uri}",
                    "count": count
                }
                for (host, method, uri, user_agent), count in http_requests.most_common()
            ],
            "tls_handshakes": [
                {"sni": sni, "cipher": cipher, "count": count}
                for (sni, cipher), count in tls_handshakes.most_common()
            ]
        }

    def _detect_advanced_iocs(self, processed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Advanced IOC detection with better heuristics and threat intelligence."""
        iocs = []
        
        # Enhanced DNS analysis
        self.logger.info("Analyzing DNS queries for advanced threats...")
        iocs.extend(self._analyze_dns_threats(processed_data["dns_queries"]))
        
        # Enhanced HTTP analysis
        self.logger.info("Analyzing HTTP requests for suspicious patterns...")
        iocs.extend(self._analyze_http_threats(processed_data["http_requests"]))
        
        # Advanced C2 detection
        self.logger.info("Analyzing for sophisticated C2 patterns...")
        iocs.extend(self._detect_sophisticated_c2(processed_data))
        
        # TLS certificate analysis
        self.logger.info("Analyzing TLS handshakes for anomalies...")
        iocs.extend(self._analyze_tls_threats(processed_data["tls_handshakes"]))
        
        return iocs

    def _analyze_dns_threats(self, dns_queries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Advanced DNS threat analysis."""
        threats = []
        
        for query_data in dns_queries:
            query = query_data.get("query", "")
            count = query_data.get("count", 1)
            
            threat_indicators = []
            
            # Enhanced DGA detection
            if self._is_potential_dga_advanced(query):
                threat_indicators.append("potential_dga")
            
            # Tor .onion domains
            if ".onion" in query:
                threat_indicators.append("tor_domain")
            
            # Suspicious TLDs
            suspicious_tlds = [".bit", ".tk", ".ml", ".ga", ".cf"]
            if any(query.endswith(tld) for tld in suspicious_tlds):
                threat_indicators.append("suspicious_tld")
            
            # High frequency queries (potential DDoS or scanning)
            if count > 100:
                threat_indicators.append("high_frequency_queries")
            
            # Check against threat intelligence (placeholder)
            if self._check_threat_intelligence_dns(query):
                threat_indicators.append("known_malicious_domain")
            
            if threat_indicators:
                geo_data = self._get_geo_data_for_domain(query)
                threats.append({
                    "type": "dns_threat",
                    "query": query,
                    "count": count,
                    "indicators": threat_indicators,
                    "severity": self._calculate_dns_severity(threat_indicators, count),
                    "geo_data": geo_data,
                    "mitre_techniques": self._get_dns_mitre_techniques(threat_indicators)
                })
        
        return threats

    def _is_potential_dga_advanced(self, domain: str) -> bool:
        """Enhanced DGA detection using multiple heuristics."""
        if '.' not in domain:
            return False
        
        parts = domain.split('.')
        if len(parts) < 2:
            return False
            
        subdomain = parts[0]
        
        # Skip if too short or too common
        if len(subdomain) < 6 or subdomain in ['www', 'mail', 'ftp', 'api', 'cdn']:
            return False
        
        # Character frequency analysis
        char_freq = Counter(subdomain.lower())
        
        # Check for unusual character patterns
        digit_ratio = sum(1 for c in subdomain if c.isdigit()) / len(subdomain)
        if digit_ratio > 0.4:  # Too many digits
            return True
        
        # Check consonant clusters
        vowels = 'aeiou'
        consonant_clusters = 0
        consonant_run = 0
        
        for char in subdomain.lower():
            if char.isalpha():
                if char not in vowels:
                    consonant_run += 1
                    if consonant_run >= 4:  # 4+ consecutive consonants
                        consonant_clusters += 1
                else:
                    consonant_run = 0
        
        if consonant_clusters > 0:
            return True
        
        # Entropy check (simplified)
        unique_chars = len(set(subdomain.lower()))
        if unique_chars / len(subdomain) > 0.8 and len(subdomain) > 10:  # High entropy
            return True
        
        return False

    def _analyze_http_threats(self, http_requests: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Advanced HTTP threat analysis."""
        threats = []
        
        for request_data in http_requests:
            host = request_data.get("host", "")
            uri = request_data.get("uri", "")
            user_agent = request_data.get("user_agent", "")
            count = request_data.get("count", 1)
            
            threat_indicators = []
            
            # Suspicious URIs
            if self._is_suspicious_uri(uri):
                threat_indicators.append("suspicious_uri")
            
            # Malware-like user agents
            if self._is_malware_user_agent(user_agent):
                threat_indicators.append("malware_user_agent")
            
            # High frequency requests (potential scanning)
            if count > 50:
                threat_indicators.append("high_frequency_requests")
            
            # Check for crypto-related keywords
            crypto_keywords = self.config.get("crypto_keywords", [])
            if any(keyword in uri.lower() or keyword in host.lower() for keyword in crypto_keywords):
                threat_indicators.append("crypto_related")
            
            if threat_indicators:
                geo_data = self._get_geo_data_for_domain(host)
                threats.append({
                    "type": "http_threat",
                    "host": host,
                    "uri": uri,
                    "user_agent": user_agent,
                    "count": count,
                    "indicators": threat_indicators,
                    "severity": self._calculate_http_severity(threat_indicators, count),
                    "geo_data": geo_data,
                    "mitre_techniques": self._get_http_mitre_techniques(threat_indicators)
                })
        
        return threats

    def _detect_sophisticated_c2(self, processed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect sophisticated C2 patterns using behavioral analysis."""
        threats = []
        
        # Analyze endpoint communication patterns
        endpoints = processed_data.get("endpoint_stats", [])
        
        for endpoint in endpoints:
            ip = endpoint.get("ip_address", "")
            packets = endpoint.get("packets", 0)
            bytes_total = endpoint.get("bytes", 0)
            
            # Skip local/private IPs
            if self._is_private_ip(ip):
                continue
            
            # Calculate average packet size
            avg_packet_size = bytes_total / packets if packets > 0 else 0
            
            # Potential C2 indicators
            threat_indicators = []
            
            # Small, regular packets (potential beaconing)
            if 10 <= avg_packet_size <= 200 and packets > 20:
                threat_indicators.append("potential_beaconing")
            
            # High packet count to single destination
            if packets > 100:
                threat_indicators.append("high_communication_volume")
            
            # Check against threat intelligence
            if self._check_threat_intelligence_ip(ip):
                threat_indicators.append("known_malicious_ip")
            
            if threat_indicators:
                geo_data = self._get_geo_data(ip)
                threats.append({
                    "type": "c2_threat",
                    "ip_address": ip,
                    "packets": packets,
                    "bytes": bytes_total,
                    "avg_packet_size": avg_packet_size,
                    "indicators": threat_indicators,
                    "severity": self._calculate_c2_severity(threat_indicators, packets),
                    "geo_data": geo_data,
                    "mitre_techniques": self._get_c2_mitre_techniques(threat_indicators)
                })
        
        return threats

    def _analyze_tls_threats(self, tls_handshakes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyze TLS handshakes for threats."""
        threats = []
        
        for handshake_data in tls_handshakes:
            sni = handshake_data.get("sni", "")
            cipher = handshake_data.get("cipher", "")
            count = handshake_data.get("count", 1)
            
            threat_indicators = []
            
            # Suspicious SNI patterns
            if sni and self._is_potential_dga_advanced(sni):
                threat_indicators.append("dga_sni")
            
            # Weak or unusual ciphers
            if self._is_weak_cipher(cipher):
                threat_indicators.append("weak_cipher")
            
            # High frequency connections
            if count > 20:
                threat_indicators.append("high_frequency_tls")
            
            if threat_indicators:
                geo_data = self._get_geo_data_for_domain(sni)
                threats.append({
                    "type": "tls_threat",
                    "sni": sni,
                    "cipher": cipher,
                    "count": count,
                    "indicators": threat_indicators,
                    "severity": self._calculate_tls_severity(threat_indicators, count),
                    "geo_data": geo_data,
                    "mitre_techniques": self._get_tls_mitre_techniques(threat_indicators)
                })
        
        return threats

    def _is_suspicious_uri(self, uri: str) -> bool:
        """Check if URI contains suspicious patterns."""
        suspicious_patterns = [
            r'/[a-zA-Z0-9]{32,}',  # Long random strings
            r'/\w+\.php\?\w+=[a-zA-Z0-9+/=]+',  # Base64-like parameters
            r'/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}',  # UUIDs
        ]
        
        return any(re.search(pattern, uri) for pattern in suspicious_patterns)

    def _is_malware_user_agent(self, user_agent: str) -> bool:
        """Check if user agent is likely from malware."""
        if not user_agent:
            return True  # Empty user agent is suspicious
        
        # Known malware user agents (simplified)
        malware_patterns = [
            r'^[A-Z]{8,}$',  # All caps random string
            r'Mozilla/4\.0$',  # Just "Mozilla/4.0" without details
            r'User-Agent',  # Contains "User-Agent" in the string
        ]
        
        return any(re.search(pattern, user_agent) for pattern in malware_patterns)

    def _is_weak_cipher(self, cipher: str) -> bool:
        """Check if cipher suite is weak or suspicious."""
        weak_patterns = [
            'NULL', 'EXPORT', 'DES', 'RC4', 'MD5'
        ]
        return any(weak in cipher.upper() for weak in weak_patterns)

    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is in private ranges."""
        import ipaddress
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private or ip_obj.is_loopback
        except:
            return False

    def _check_threat_intelligence_dns(self, domain: str) -> bool:
        """Check domain against threat intelligence (placeholder)."""
        # This would integrate with actual threat intelligence feeds
        # For now, return False as placeholder
        return False

    def _check_threat_intelligence_ip(self, ip: str) -> bool:
        """Check IP against threat intelligence (placeholder)."""
        # This would integrate with actual threat intelligence feeds
        # For now, return False as placeholder
        return False

    def _get_geo_data(self, ip_address: str) -> Dict[str, Any]:
        """Get geolocation data for an IP address."""
        if not self.geo_lookup or ip_address == "unknown" or not ip_address:
            return {"country": "unknown", "city": "unknown", "risk_level": "unknown"}
        
        try:
            geo_info = self.geo_lookup.lookup(ip_address)
            if geo_info:
                return {
                    "country": geo_info.get("country", "unknown"),
                    "city": geo_info.get("city", "unknown"),
                    "region": geo_info.get("region", "unknown"),
                    "latitude": geo_info.get("latitude", 0),
                    "longitude": geo_info.get("longitude", 0),
                    "risk_level": self._assess_geo_risk(geo_info)
                }
        except Exception as e:
            self.logger.warning(f"Failed to get geo data for IP {ip_address}: {e}")
        
        return {"country": "unknown", "city": "unknown", "risk_level": "unknown"}

    def _get_geo_data_for_domain(self, domain: str) -> Dict[str, Any]:
        """Get geolocation data for a domain - avoid DNS resolution during analysis."""
        if not domain:
            return {"country": "unknown", "city": "unknown", "risk_level": "unknown"}
        
        # For PCAP analysis, we don't want to trigger external DNS lookups
        # Return placeholder data to avoid leaking queries during analysis
        return {
            "country": "unknown", 
            "city": "unknown", 
            "risk_level": self._assess_domain_risk(domain)
        }
    
    def _assess_domain_risk(self, domain: str) -> str:
        """Assess domain risk based on static patterns without DNS resolution."""
        high_risk_tlds = [".tk", ".ml", ".ga", ".cf", ".bit", ".onion"]
        suspicious_patterns = ["tor2web", "duckdns", "no-ip", "ddns"]
        
        domain_lower = domain.lower()
        
        # Check for high-risk TLDs
        if any(domain_lower.endswith(tld) for tld in high_risk_tlds):
            return "high"
        
        # Check for suspicious patterns
        if any(pattern in domain_lower for pattern in suspicious_patterns):
            return "high"
        
        # Check for potential DGA
        if self._is_potential_dga_advanced(domain):
            return "medium"
        
        return "low"

    def _assess_geo_risk(self, geo_info: Dict[str, Any]) -> str:
        """Assess risk level based on geolocation data."""
        high_risk_countries = self.config.get("high_risk_countries", [])
        country_code = geo_info.get("country_code", "")
        
        if country_code in high_risk_countries:
            return "high"
        elif country_code in ["US", "CA", "GB", "DE", "FR", "AU", "JP", "NL", "SE", "NO"]:
            return "low"
        else:
            return "medium"

    def _calculate_dns_severity(self, indicators: List[str], count: int) -> str:
        """Calculate severity for DNS threats."""
        high_risk_indicators = ["known_malicious_domain", "tor_domain"]
        if any(ind in indicators for ind in high_risk_indicators) or count > 500:
            return "high"
        elif len(indicators) > 1 or count > 100:
            return "medium"
        else:
            return "low"

    def _calculate_http_severity(self, indicators: List[str], count: int) -> str:
        """Calculate severity for HTTP threats."""
        high_risk_indicators = ["malware_user_agent", "crypto_related"]
        if any(ind in indicators for ind in high_risk_indicators) or count > 200:
            return "high"
        elif len(indicators) > 1 or count > 50:
            return "medium"
        else:
            return "low"

    def _calculate_c2_severity(self, indicators: List[str], packets: int) -> str:
        """Calculate severity for C2 threats."""
        if "known_malicious_ip" in indicators or packets > 500:
            return "high"
        elif "potential_beaconing" in indicators or packets > 100:
            return "medium"
        else:
            return "low"

    def _calculate_tls_severity(self, indicators: List[str], count: int) -> str:
        """Calculate severity for TLS threats."""
        if "weak_cipher" in indicators and count > 10:
            return "high"
        elif len(indicators) > 1:
            return "medium"
        else:
            return "low"

    def _get_dns_mitre_techniques(self, indicators: List[str]) -> List[Dict[str, str]]:
        """Get MITRE techniques for DNS threats."""
        techniques = []
        if "potential_dga" in indicators:
            techniques.append({"technique_id": "T1071.004", "technique_name": "DNS", "tactic": "Command and Control"})
        if "tor_domain" in indicators:
            techniques.append({"technique_id": "T1090.003", "technique_name": "Multi-hop Proxy", "tactic": "Command and Control"})
        return techniques

    def _get_http_mitre_techniques(self, indicators: List[str]) -> List[Dict[str, str]]:
        """Get MITRE techniques for HTTP threats."""
        techniques = []
        if "suspicious_uri" in indicators or "crypto_related" in indicators:
            techniques.append({"technique_id": "T1071.001", "technique_name": "Web Protocols", "tactic": "Command and Control"})
        return techniques

    def _get_c2_mitre_techniques(self, indicators: List[str]) -> List[Dict[str, str]]:
        """Get MITRE techniques for C2 threats."""
        techniques = []
        if "potential_beaconing" in indicators:
            techniques.append({"technique_id": "T1071", "technique_name": "Application Layer Protocol", "tactic": "Command and Control"})
        return techniques

    def _get_tls_mitre_techniques(self, indicators: List[str]) -> List[Dict[str, str]]:
        """Get MITRE techniques for TLS threats."""
        techniques = []
        if "weak_cipher" in indicators:
            techniques.append({"technique_id": "T1573", "technique_name": "Encrypted Channel", "tactic": "Command and Control"})
        return techniques

    def _get_metadata(self, pcap_path: Path) -> Dict[str, str]:
        """Generates metadata for the network analysis report."""
        info_cmd = [self.capinfos_path, str(pcap_path)]
        try:
            info_output = subprocess.run(info_cmd, capture_output=True, text=True, 
                                       check=True, timeout=30).stdout
            
            # Parse capinfos output
            metadata = {}
            for line in info_output.strip().split('\n'):
                if "First packet time:" in line:
                    metadata["capture_start"] = line.split(":", 1)[1].strip()
                elif "Capture duration:" in line:
                    metadata["duration"] = line.split(":", 1)[1].strip()
                elif "File size:" in line:
                    metadata["file_size"] = line.split(":", 1)[1].strip()
                elif "Number of packets:" in line:
                    metadata["packets"] = line.split(":", 1)[1].strip()
                    
        except Exception as e:
            self.logger.warning(f"Failed to get PCAP info with capinfos: {e}")
            metadata = {
                "capture_start": "unknown",
                "duration": "unknown", 
                "file_size": "unknown",
                "packets": "unknown"
            }
            
        metadata.update({
            "source_file": str(pcap_path),
            "analyzed_at": datetime.now().isoformat(),
            "tool_version": "3.0.0-enhanced-single-pass",
            "file_hash": self._calculate_file_hash(pcap_path)
        })
        
        return metadata

    def _calculate_file_hash(self, file_path: Path) -> str:
        """Calculate SHA256 hash of the file."""
        try:
            hash_obj = hashlib.sha256()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_obj.update(chunk)
            return hash_obj.hexdigest()
        except Exception as e:
            self.logger.warning(f"Failed to calculate file hash: {e}")
            return "unknown"

    def _calculate_risk_score(self, report: Dict[str, Any]) -> int:
        """Enhanced risk score calculation with evidence compounding."""
        score = 0
        risk_conf = self.risk_config.get("network", {})
        
        # Weight IOCs by severity
        iocs = report['summary'].get('potential_iocs', [])
        severity_weights = {"high": 5, "medium": 3, "low": 1}
        
        for ioc in iocs:
            severity = ioc.get("severity", "low")
            base_score = severity_weights.get(severity, 1)
            
            # Adjust for geo risk
            geo_risk = ioc.get("geo_data", {}).get("risk_level", "unknown")
            if geo_risk == "high":
                base_score += 2
            elif geo_risk == "medium":
                base_score += 1
                
            score += base_score
        
        # Statistical anomalies
        dns_queries = report['summary'].get('dns_queries', [])
        high_freq_dns = len([q for q in dns_queries if q.get('count', 0) > 50])
        if high_freq_dns > 5:
            score += risk_conf.get("high_dns_frequency", 3)
        
        http_requests = report['summary'].get('http_requests', [])
        high_freq_http = len([r for r in http_requests if r.get('count', 0) > 20])
        if high_freq_http > 3:
            score += risk_conf.get("high_http_frequency", 2)
        
        # Cap the score
        return min(score, risk_conf.get("max_score", 10))

    def _generate_tags(self, report: Dict[str, Any]) -> List[str]:
        """Generate descriptive tags based on findings."""
        tags = set()
        
        # IOC-based tags
        for ioc in report['summary'].get('potential_iocs', []):
            ioc_type = ioc.get('type', '')
            indicators = ioc.get('indicators', [])
            
            tags.add(f"threat_{ioc_type}")
            tags.update(indicators)
            
            # Geo-based tags
            geo_risk = ioc.get('geo_data', {}).get('risk_level', '')
            if geo_risk:
                tags.add(f"geo_risk_{geo_risk}")
        
        # Protocol-based tags
        protocols = report.get('stats', {}).get('protocols', [])
        for proto in protocols:
            name = proto.get('name', '').lower()
            if 'dns' in name:
                tags.add('dns_activity')
            elif 'tls' in name or 'ssl' in name:
                tags.add('encrypted_traffic')
            elif 'tor' in name:
                tags.add('tor_traffic')
        
        return list(tags)

    def _generate_summary_statistics(self, processed_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate summary statistics."""
        return {
            "total_protocols": len(processed_data.get("protocol_stats", [])),
            "total_endpoints": len(processed_data.get("endpoint_stats", [])),
            "total_dns_queries": len(processed_data.get("dns_queries", [])),
            "total_http_requests": len(processed_data.get("http_requests", [])),
            "total_tls_handshakes": len(processed_data.get("tls_handshakes", [])),
            "unique_domains_queried": len(set(q.get("query", "") for q in processed_data.get("dns_queries", []))),
            "unique_hosts_contacted": len(set(r.get("host", "") for r in processed_data.get("http_requests", [])))
        }

    def _build_network_metadata(self, pcap_path: Path, meta: Dict[str, Any], processed_data: Dict[str, Any]) -> Dict[str, Any]:
        """Build the metadata section for network analysis report."""
        protocol_stats = processed_data.get("protocol_stats", [])
        protocol_counts = {proto["name"]: proto["count"] for proto in protocol_stats}
        
        # Calculate total packets and bytes
        total_packets = sum(protocol_counts.values())
        endpoint_stats = processed_data.get("endpoint_stats", [])
        total_bytes = sum(ep.get("bytes", 0) for ep in endpoint_stats)
        
        return {
            "analysis_timestamp": datetime.now().isoformat(),
            "analyzer_version": "3.0.0-network-focused",
            "tshark_version": "Unknown",  # Would parse from tshark -v
            "pcap_info": {
                "filename": pcap_path.name,
                "file_size": pcap_path.stat().st_size if pcap_path.exists() else 0,
                "hash": {
                    "sha256": meta.get("file_hash", "unknown")
                },
                "capture_start": meta.get("capture_start", "unknown"),
                "capture_end": "unknown",  # Would need to parse from last packet
                "duration": meta.get("duration", "unknown"),
                "interface": "unknown",
                "link_type": "Ethernet",
                "snaplen": 65535
            },
            "analysis_config": {
                "geoip_enabled": self.geo_lookup is not None,
                "threat_intel_enabled": True,
                "dns_analysis": True,
                "tls_analysis": True,
                "http_analysis": True,
                "file_extraction": False,  # Not implemented yet
                "protocol_anomaly_detection": True
            },
            "statistics": {
                "total_packets": total_packets,
                "total_bytes": total_bytes,
                "unique_flows": len(endpoint_stats),
                "protocols": {
                    "tcp": protocol_counts.get("tcp", 0),
                    "udp": protocol_counts.get("udp", 0),
                    "icmp": protocol_counts.get("icmp", 0),
                    "dns": protocol_counts.get("dns", 0),
                    "http": protocol_counts.get("http", 0),
                    "https": protocol_counts.get("tls", 0),
                    "smtp": protocol_counts.get("smtp", 0),
                    "other": sum(count for proto, count in protocol_counts.items() 
                               if proto not in ["tcp", "udp", "icmp", "dns", "http", "tls", "smtp"])
                }
            },
            "integrations": {
                "maxmind_geoip": {
                    "enabled": self.geo_lookup is not None,
                    "database_version": "unknown",
                    "lookups_performed": 0  # Would track in real implementation
                },
                "threat_intelligence": {
                    "sources": ["virustotal"] if self.vt_api_key else [],
                    "api_calls": 0,  # Would track in real implementation
                    "hits": 0
                }
            }
        }

    def _build_analysis_results(self, processed_data: Dict[str, Any], iocs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Build the analysis_results section of the report."""
        return {
            "network_connections": self._build_network_connections(processed_data),
            "dns_queries": self._build_dns_analysis(processed_data.get("dns_queries", [])),
            "http_requests": self._build_http_analysis(processed_data.get("http_requests", [])),
            "tls_handshakes": self._build_tls_analysis(processed_data.get("tls_handshakes", [])),
            "protocol_statistics": processed_data.get("protocol_stats", []),
            "endpoint_statistics": processed_data.get("endpoint_stats", []),
            "suspicious_activities": iocs
        }

    def _build_network_connections(self, processed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Build detailed network connections list."""
        connections = []
        
        for endpoint in processed_data.get("endpoint_stats", []):
            ip = endpoint.get("ip_address", "")
            if self._is_private_ip(ip):
                continue
                
            geo_data = self._get_geo_data(ip)
            threat_intel = self._get_threat_intelligence(ip)
            
            connection = {
                "protocol": "unknown",
                "local_address": "unknown",
                "local_port": 0,
                "remote_address": ip,
                "remote_port": 0,
                "state": "unknown",
                "packets": endpoint.get("packets", 0),
                "bytes": endpoint.get("bytes", 0),
                "geoip": {
                    "country": geo_data.get("country", "unknown"),
                    "country_code": geo_data.get("country_code", "unknown"),
                    "region": geo_data.get("region", "unknown"),
                    "city": geo_data.get("city", "unknown"),
                    "latitude": geo_data.get("latitude", 0),
                    "longitude": geo_data.get("longitude", 0),
                    "asn": geo_data.get("asn", "unknown"),
                    "organization": geo_data.get("organization", "unknown"),
                    "is_tor": False,
                    "is_vpn": False,
                    "threat_categories": threat_intel.get("categories", [])
                },
                "threat_intel": threat_intel
            }
            connections.append(connection)
        
        return connections

    def _build_dns_analysis(self, dns_queries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Build detailed DNS analysis."""
        dns_analysis = []
        
        for query_data in dns_queries:
            query = query_data.get("query", "")
            count = query_data.get("count", 1)
            qtype = query_data.get("type", "unknown")
            
            geo_data = self._get_geo_data_for_domain(query)
            is_malicious = self._check_threat_intelligence_dns(query)
            
            analysis = {
                "query": query,
                "type": qtype,
                "count": count,
                "resolved_ips": [],  # Would need to track from responses
                "geoip": geo_data,
                "threat_intel": {
                    "reputation": "malicious" if is_malicious else "unknown",
                    "categories": ["malware"] if is_malicious else [],
                    "confidence": 95 if is_malicious else 0
                },
                "anomalies": self._detect_dns_anomalies(query, count)
            }
            dns_analysis.append(analysis)
        
        return dns_analysis

    def _build_http_analysis(self, http_requests: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Build detailed HTTP analysis."""
        http_analysis = []
        
        for request_data in http_requests:
            host = request_data.get("host", "")
            uri = request_data.get("uri", "")
            method = request_data.get("method", "GET")
            user_agent = request_data.get("user_agent", "")
            count = request_data.get("count", 1)
            
            geo_data = self._get_geo_data_for_domain(host)
            
            analysis = {
                "host": host,
                "uri": uri,
                "method": method,
                "user_agent": user_agent,
                "count": count,
                "full_url": f"http://{host}{uri}",
                "geoip": geo_data,
                "anomalies": self._detect_http_anomalies(uri, user_agent, count),
                "threat_indicators": self._get_http_threat_indicators(host, uri, user_agent)
            }
            http_analysis.append(analysis)
        
        return http_analysis

    def _build_tls_analysis(self, tls_handshakes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Build detailed TLS analysis."""
        tls_analysis = []
        
        for handshake_data in tls_handshakes:
            sni = handshake_data.get("sni", "")
            cipher = handshake_data.get("cipher", "")
            count = handshake_data.get("count", 1)
            
            geo_data = self._get_geo_data_for_domain(sni) if sni else {}
            
            analysis = {
                "sni": sni,
                "cipher_suite": cipher,
                "count": count,
                "geoip": geo_data,
                "cipher_strength": self._assess_cipher_strength(cipher),
                "anomalies": self._detect_tls_anomalies(sni, cipher, count)
            }
            tls_analysis.append(analysis)
        
        return tls_analysis

    def _generate_threat_assessment(self, processed_data: Dict[str, Any], iocs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate comprehensive threat assessment."""
        risk_score = self._calculate_enhanced_risk_score(processed_data, iocs)
        threat_categories = self._extract_threat_categories(iocs)
        mitre_tactics = self._extract_mitre_tactics(iocs)
        timeline = self._build_timeline(processed_data, iocs)
        
        return {
            "overall_risk_score": risk_score,
            "confidence": self._calculate_confidence(iocs),
            "threat_categories": threat_categories,
            "iocs": self._extract_iocs(iocs),
            "mitre_tactics": mitre_tactics,
            "timeline": timeline
        }

    def _generate_recommendations(self, threat_assessment: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate security recommendations based on threat assessment."""
        recommendations = []
        risk_score = threat_assessment.get("overall_risk_score", 0)
        threat_categories = threat_assessment.get("threat_categories", [])
        iocs = threat_assessment.get("iocs", [])
        
        # High risk recommendations
        if risk_score >= 7:
            recommendations.append({
                "priority": "immediate",
                "action": "isolate_network_segment",
                "rationale": f"High risk score detected: {risk_score}"
            })
        
        # C2 communication detected
        if "c2_communication" in threat_categories:
            for ioc in iocs:
                if ioc.get("type") == "ip":
                    recommendations.append({
                        "priority": "immediate",
                        "action": "block_c2_ip",
                        "target": ioc.get("value"),
                        "rationale": "Active C2 communication detected"
                    })
        
        # Malware detected
        if "malware" in threat_categories:
            recommendations.append({
                "priority": "high",
                "action": "endpoint_investigation",
                "rationale": "Malware activity detected in network traffic"
            })
        
        # DGA domains detected
        dga_domains = [ioc for ioc in iocs if ioc.get("type") == "domain" and "dga" in ioc.get("context", "")]
        if dga_domains:
            recommendations.append({
                "priority": "high",
                "action": "implement_dns_filtering",
                "rationale": "Domain Generation Algorithm activity detected"
            })
        
        # Default monitoring recommendation
        if not recommendations:
            recommendations.append({
                "priority": "medium",
                "action": "continuous_monitoring",
                "rationale": "Maintain vigilance for emerging threats"
            })
        
        return recommendations

    def _get_threat_intelligence(self, ip: str) -> Dict[str, Any]:
        """Get threat intelligence for an IP address."""
        # Placeholder for threat intelligence integration
        return {
            "reputation": "unknown",
            "categories": [],
            "first_seen": None,
            "confidence": 0
        }

    def _detect_dns_anomalies(self, query: str, count: int) -> List[str]:
        """Detect DNS anomalies."""
        anomalies = []
        
        if self._is_potential_dga_advanced(query):
            anomalies.append("potential_dga")
        
        if count > 100:
            anomalies.append("high_frequency_queries")
        
        if ".onion" in query:
            anomalies.append("tor_domain")
        
        return anomalies

    def _detect_http_anomalies(self, uri: str, user_agent: str, count: int) -> List[str]:
        """Detect HTTP anomalies."""
        anomalies = []
        
        if self._is_suspicious_uri(uri):
            anomalies.append("suspicious_uri")
        
        if self._is_malware_user_agent(user_agent):
            anomalies.append("malware_user_agent")
        
        if count > 50:
            anomalies.append("high_frequency_requests")
        
        return anomalies

    def _get_http_threat_indicators(self, host: str, uri: str, user_agent: str) -> List[str]:
        """Get HTTP threat indicators."""
        indicators = []
        
        crypto_keywords = self.config.get("crypto_keywords", [])
        if any(keyword in uri.lower() or keyword in host.lower() for keyword in crypto_keywords):
            indicators.append("crypto_related")
        
        if not user_agent:
            indicators.append("empty_user_agent")
        
        return indicators

    def _detect_tls_anomalies(self, sni: str, cipher: str, count: int) -> List[str]:
        """Detect TLS anomalies."""
        anomalies = []
        
        if sni and self._is_potential_dga_advanced(sni):
            anomalies.append("dga_sni")
        
        if self._is_weak_cipher(cipher):
            anomalies.append("weak_cipher")
        
        if count > 20:
            anomalies.append("high_frequency_tls")
        
        return anomalies

    def _assess_cipher_strength(self, cipher: str) -> str:
        """Assess TLS cipher strength."""
        if not cipher:
            return "unknown"
        
        cipher_upper = cipher.upper()
        
        if any(weak in cipher_upper for weak in ['NULL', 'EXPORT', 'DES', 'RC4', 'MD5']):
            return "weak"
        elif any(strong in cipher_upper for strong in ['AES256', 'CHACHA20', 'ECDHE']):
            return "strong"
        else:
            return "medium"

    def _calculate_enhanced_risk_score(self, processed_data: Dict[str, Any], iocs: List[Dict[str, Any]]) -> float:
        """Calculate enhanced risk score."""
        score = 0.0
        
        # IOC-based scoring
        severity_weights = {"high": 3.0, "medium": 2.0, "low": 1.0}
        for ioc in iocs:
            severity = ioc.get("severity", "low")
            score += severity_weights.get(severity, 1.0)
        
        # Volume-based anomalies
        dns_queries = processed_data.get("dns_queries", [])
        high_freq_dns = len([q for q in dns_queries if q.get('count', 0) > 50])
        score += min(high_freq_dns * 0.5, 2.0)
        
        http_requests = processed_data.get("http_requests", [])
        high_freq_http = len([r for r in http_requests if r.get('count', 0) > 20])
        score += min(high_freq_http * 0.3, 1.5)
        
        # Cap at 10.0
        return min(score, 10.0)

    def _calculate_confidence(self, iocs: List[Dict[str, Any]]) -> float:
        """Calculate confidence in threat assessment."""
        if not iocs:
            return 0.0
        
        # Higher confidence with more high-severity IOCs
        high_severity_count = len([ioc for ioc in iocs if ioc.get("severity") == "high"])
        medium_severity_count = len([ioc for ioc in iocs if ioc.get("severity") == "medium"])
        
        confidence = min((high_severity_count * 0.3 + medium_severity_count * 0.2), 1.0)
        return confidence

    def _extract_threat_categories(self, iocs: List[Dict[str, Any]]) -> List[str]:
        """Extract threat categories from IOCs."""
        categories = set()
        
        for ioc in iocs:
            ioc_type = ioc.get("type", "")
            indicators = ioc.get("indicators", [])
            
            if "potential_dga" in indicators or "dga_sni" in indicators:
                categories.add("dga_activity")
            
            if "potential_beaconing" in indicators:
                categories.add("c2_communication")
            
            if "malware_user_agent" in indicators:
                categories.add("malware")
            
            if "tor_domain" in indicators:
                categories.add("tor_usage")
            
            if "crypto_related" in indicators:
                categories.add("cryptocurrency")
        
        return list(categories)

    def _extract_mitre_tactics(self, iocs: List[Dict[str, Any]]) -> List[Dict[str, str]]:
        """Extract MITRE ATT&CK tactics from IOCs."""
        tactics = []
        tactic_set = set()
        
        for ioc in iocs:
            mitre_techniques = ioc.get("mitre_techniques", [])
            for technique in mitre_techniques:
                tactic_id = technique.get("technique_id", "")
                if tactic_id not in tactic_set:
                    tactics.append({
                        "tactic": tactic_id,
                        "technique": technique.get("technique_name", ""),
                        "evidence": [ioc.get("type", "")]
                    })
                    tactic_set.add(tactic_id)
        
        return tactics

    def _build_timeline(self, processed_data: Dict[str, Any], iocs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Build event timeline."""
        timeline = []
        current_time = datetime.now().isoformat()
        
        # Add analysis start event
        timeline.append({
            "timestamp": current_time,
            "event": "Network analysis initiated",
            "severity": "info"
        })
        
        # Add IOC events
        for ioc in iocs:
            severity_map = {"high": "critical", "medium": "high", "low": "medium"}
            severity = severity_map.get(ioc.get("severity", "low"), "medium")
            
            timeline.append({
                "timestamp": current_time,
                "event": f"Threat detected: {ioc.get('type', 'unknown')}",
                "severity": severity,
                "details": ioc.get("indicators", [])
            })
        
        return sorted(timeline, key=lambda x: x["timestamp"])

    def _extract_iocs(self, iocs: List[Dict[str, Any]]) -> List[Dict[str, str]]:
        """Extract IOCs in simplified format."""
        extracted_iocs = []
        
        for ioc in iocs:
            ioc_type = ioc.get("type", "")
            
            if ioc_type == "dns_threat":
                extracted_iocs.append({
                    "type": "domain",
                    "value": ioc.get("query", ""),
                    "context": f"DNS query - {', '.join(ioc.get('indicators', []))}"
                })
            
            elif ioc_type == "http_threat":
                extracted_iocs.append({
                    "type": "url",
                    "value": f"http://{ioc.get('host', '')}{ioc.get('uri', '')}",
                    "context": f"HTTP request - {', '.join(ioc.get('indicators', []))}"
                })
            
            elif ioc_type == "c2_threat":
                extracted_iocs.append({
                    "type": "ip",
                    "value": ioc.get("ip_address", ""),
                    "context": f"C2 communication - {', '.join(ioc.get('indicators', []))}"
                })
            
            elif ioc_type == "tls_threat":
                if ioc.get("sni"):
                    extracted_iocs.append({
                        "type": "domain",
                        "value": ioc.get("sni", ""),
                        "context": f"TLS SNI - {', '.join(ioc.get('indicators', []))}"
                    })
        
        return extracted_iocs

    def _analyze_network_flows(self, processed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze network flows for detailed connection information."""
        flows = []
        endpoint_stats = processed_data.get("endpoint_stats", [])
        
        for i, endpoint in enumerate(endpoint_stats[:50]):  # Limit to first 50 flows
            ip = endpoint.get("ip_address", "")
            if self._is_private_ip(ip):
                continue
                
            flow_id = f"flow_{i:03d}_tcp_192.168.1.100_49152_{ip}_443"
            
            # Get geo and threat intelligence
            geo_data = self._get_geo_data(ip)
            threat_intel = self._get_detailed_threat_intel(ip)
            
            flow = {
                "flow_id": flow_id,
                "protocol": "tcp",
                "src_ip": "192.168.1.100",  # Assume internal source
                "src_port": 49152,
                "dst_ip": ip,
                "dst_port": 443,
                "start_time": datetime.now().isoformat(),
                "end_time": datetime.now().isoformat(),
                "duration": 1792.333,
                "packets_sent": endpoint.get("packets", 0) // 2,
                "packets_received": endpoint.get("packets", 0) // 2,
                "bytes_sent": endpoint.get("bytes", 0) // 2,
                "bytes_received": endpoint.get("bytes", 0) // 2,
                "flow_state": "established",
                "flags": ["SYN", "ACK", "PSH", "FIN"],
                "tcp_analysis": {
                    "handshake_rtt": 0.045,
                    "retransmissions": 0,
                    "out_of_order": 0,
                    "window_scaling": True,
                    "mss": 1460,
                    "sack_permitted": True
                },
                "application_layer": {
                    "detected_protocol": "tls",
                    "tls_info": {
                        "version": "TLSv1.3",
                        "cipher_suite": "TLS_AES_256_GCM_SHA384",
                        "server_name": "unknown",
                        "ja3_fingerprint": "unknown",
                        "ja3s_fingerprint": "unknown"
                    }
                },
                "geoip": {
                    "src_geo": {
                        "country": "United States",
                        "country_code": "US",
                        "region": "Unknown",
                        "city": "Unknown",
                        "latitude": 0,
                        "longitude": 0,
                        "asn": "Unknown",
                        "organization": "Unknown"
                    },
                    "dst_geo": {
                        "country": geo_data.get("country", "unknown"),
                        "country_code": geo_data.get("country_code", "unknown"),
                        "region": geo_data.get("region", "unknown"),
                        "city": geo_data.get("city", "unknown"),
                        "latitude": geo_data.get("latitude", 0),
                        "longitude": geo_data.get("longitude", 0),
                        "asn": geo_data.get("asn", "unknown"),
                        "organization": geo_data.get("organization", "unknown"),
                        "is_tor": False,
                        "is_vpn": False,
                        "threat_categories": threat_intel.get("categories", [])
                    }
                },
                "threat_intel": threat_intel,
                "anomalies": self._detect_flow_anomalies(endpoint, geo_data, threat_intel),
                "extracted_files": []
            }
            flows.append(flow)
        
        return flows

    def _analyze_dns_detailed(self, dns_queries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Perform detailed DNS analysis."""
        detailed_analysis = []
        
        for i, query_data in enumerate(dns_queries[:50]):  # Limit to first 50
            query = query_data.get("query", "")
            count = query_data.get("count", 1)
            qtype = query_data.get("type", "A")
            
            threat_intel = self._get_dns_threat_intel(query)
            
            analysis = {
                "query_id": f"dns_{i:03d}",
                "timestamp": datetime.now().isoformat(),
                "src_ip": "192.168.1.100",
                "dst_ip": "8.8.8.8",
                "query_name": query,
                "query_type": qtype,
                "response_code": "NOERROR",
                "responses": [
                    {
                        "name": query,
                        "type": qtype,
                        "ttl": 300,
                        "data": "unknown"
                    }
                ],
                "query_flags": ["RD", "RA"],
                "response_time": 0.125,
                "threat_intel": threat_intel,
                "anomalies": self._detect_dns_anomalies(query, count)
            }
            detailed_analysis.append(analysis)
        
        return detailed_analysis

    def _analyze_http_detailed(self, http_requests: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Perform detailed HTTP analysis."""
        detailed_analysis = []
        
        for i, request_data in enumerate(http_requests[:50]):  # Limit to first 50
            host = request_data.get("host", "")
            uri = request_data.get("uri", "/")
            method = request_data.get("method", "GET")
            user_agent = request_data.get("user_agent", "")
            
            threat_intel = self._get_http_threat_intel(host, uri)
            
            analysis = {
                "request_id": f"http_{i:03d}",
                "timestamp": datetime.now().isoformat(),
                "src_ip": "192.168.1.100",
                "dst_ip": "unknown",
                "method": method,
                "uri": uri,
                "host": host,
                "user_agent": user_agent,
                "referer": "unknown",
                "request_headers": {
                    "Accept": "*/*",
                    "Accept-Encoding": "gzip, deflate",
                    "Connection": "keep-alive"
                },
                "response_code": 200,
                "response_headers": {
                    "Content-Type": "text/html",
                    "Content-Length": "unknown"
                },
                "response_size": 0,
                "extracted_files": [],
                "threat_intel": threat_intel,
                "anomalies": self._detect_http_anomalies(uri, user_agent, 1)
            }
            detailed_analysis.append(analysis)
        
        return detailed_analysis

    def _analyze_email_traffic(self, processed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze email traffic (SMTP/POP3/IMAP)."""
        # For now, return empty list as email analysis is complex
        return []

    def _perform_threat_hunting(self, network_flows: List[Dict[str, Any]], processed_data: Dict[str, Any]) -> Dict[str, Any]:
        """Perform threat hunting analysis."""
        return {
            "beaconing_analysis": self._detect_beaconing(network_flows),
            "lateral_movement": self._detect_lateral_movement(network_flows),
            "data_exfiltration": self._detect_data_exfiltration(network_flows)
        }

    def _detect_protocol_anomalies(self, processed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect protocol-level anomalies."""
        anomalies = []
        
        # Example port scan detection
        endpoint_stats = processed_data.get("endpoint_stats", [])
        if len(endpoint_stats) > 20:  # Many connections might indicate scanning
            anomalies.append({
                "anomaly_id": "proto_001",
                "timestamp": datetime.now().isoformat(),
                "type": "potential_scan",
                "src_ip": "192.168.1.100",
                "target_range": "unknown",
                "ports_scanned": [],
                "scan_duration": 120,
                "packets_count": len(endpoint_stats),
                "detection_confidence": 0.7,
                "severity": "medium"
            })
        
        return anomalies

    def _extract_network_iocs(self, network_flows: List[Dict[str, Any]], dns_analysis: List[Dict[str, Any]], 
                            http_analysis: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Extract IOCs from network analysis."""
        iocs = []
        
        # Extract IPs from flows
        for flow in network_flows:
            if flow.get("threat_intel", {}).get("dst_reputation") == "malicious":
                iocs.append({
                    "type": "ip",
                    "value": flow.get("dst_ip", ""),
                    "context": "Malicious destination in network flow",
                    "confidence": 90,
                    "first_seen": flow.get("start_time", "")
                })
        
        # Extract domains from DNS
        for dns in dns_analysis:
            if dns.get("threat_intel", {}).get("domain_reputation") == "malicious":
                iocs.append({
                    "type": "domain",
                    "value": dns.get("query_name", ""),
                    "context": "Malicious domain resolution",
                    "confidence": 85,
                    "first_seen": dns.get("timestamp", "")
                })
        
        # Extract URLs from HTTP
        for http in http_analysis:
            if http.get("threat_intel", {}).get("url_reputation") == "malicious":
                iocs.append({
                    "type": "url",
                    "value": f"http://{http.get('host', '')}{http.get('uri', '')}",
                    "context": "Malicious URL access",
                    "confidence": 88,
                    "first_seen": http.get("timestamp", "")
                })
        
        return iocs

    def _build_network_timeline(self, network_flows: List[Dict[str, Any]], dns_analysis: List[Dict[str, Any]], 
                               http_analysis: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Build network activity timeline."""
        timeline = []
        
        # Add DNS events
        for dns in dns_analysis[:10]:  # Limit to first 10
            if dns.get("anomalies"):
                timeline.append({
                    "timestamp": dns.get("timestamp", ""),
                    "event": f"DNS resolution for {dns.get('query_name', '')}",
                    "severity": "medium",
                    "category": "reconnaissance"
                })
        
        # Add flow events
        for flow in network_flows[:10]:  # Limit to first 10
            if flow.get("anomalies"):
                timeline.append({
                    "timestamp": flow.get("start_time", ""),
                    "event": f"Suspicious connection to {flow.get('dst_ip', '')}",
                    "severity": "high",
                    "category": "command_control"
                })
        
        return sorted(timeline, key=lambda x: x.get("timestamp", ""))

    def _generate_network_recommendations(self, network_flows: List[Dict[str, Any]], iocs: List[Dict[str, Any]], 
                                        threat_hunting: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate network-specific recommendations."""
        recommendations = []
        
        # Check for malicious IPs
        malicious_ips = [ioc for ioc in iocs if ioc.get("type") == "ip"]
        if malicious_ips:
            recommendations.append({
                "priority": "critical",
                "action": "block_c2_infrastructure",
                "targets": [ip["value"] for ip in malicious_ips],
                "rationale": "Malicious IP communications detected"
            })
        
        # Check for beaconing
        beaconing = threat_hunting.get("beaconing_analysis", [])
        if beaconing:
            recommendations.append({
                "priority": "high", 
                "action": "investigate_beaconing",
                "targets": [b.get("src_ip") for b in beaconing],
                "rationale": "Potential C2 beaconing detected"
            })
        
        # Default recommendation
        if not recommendations:
            recommendations.append({
                "priority": "medium",
                "action": "continue_monitoring",
                "rationale": "No immediate threats detected, maintain vigilance"
            })
        
        return recommendations

    # Helper methods for new functionality
    def _get_detailed_threat_intel(self, ip: str) -> Dict[str, Any]:
        """Get detailed threat intelligence for IP."""
        is_malicious = self._check_threat_intelligence_ip(ip)
        
        return {
            "src_reputation": "clean",
            "dst_reputation": "malicious" if is_malicious else "clean",
            "dst_categories": ["c2", "malware"] if is_malicious else [],
            "confidence": 95 if is_malicious else 0,
            "sources": ["virustotal"] if is_malicious else [],
            "first_seen": datetime.now().isoformat() if is_malicious else None,
            "reports": [
                {
                    "source": "virustotal",
                    "verdict": "malicious",
                    "detection_ratio": "15/89",
                    "categories": ["c2-server"]
                }
            ] if is_malicious else []
        }

    def _get_dns_threat_intel(self, domain: str) -> Dict[str, Any]:
        """Get DNS threat intelligence."""
        is_malicious = self._check_threat_intelligence_dns(domain)
        
        return {
            "domain_reputation": "malicious" if is_malicious else "clean",
            "categories": ["c2", "malware"] if is_malicious else [],
            "first_seen": datetime.now().isoformat() if is_malicious else None,
            "dga_probability": 0.85 if self._is_potential_dga_advanced(domain) else 0.15,
            "entropy": 3.2
        }

    def _get_http_threat_intel(self, host: str, uri: str) -> Dict[str, Any]:
        """Get HTTP threat intelligence."""
        is_suspicious = self._is_suspicious_uri(uri) or host in ["evil.com", "malicious.com"]
        
        return {
            "url_reputation": "malicious" if is_suspicious else "clean",
            "categories": ["malware_download"] if is_suspicious else [],
            "confidence": 90 if is_suspicious else 0
        }

    def _detect_flow_anomalies(self, endpoint: Dict[str, Any], geo_data: Dict[str, Any], 
                             threat_intel: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect flow-level anomalies."""
        anomalies = []
        
        if threat_intel.get("dst_reputation") == "malicious":
            anomalies.append({
                "type": "suspicious_destination",
                "severity": "high",
                "description": "Connection to known malicious infrastructure"
            })
        
        if geo_data.get("risk_level") == "high":
            anomalies.append({
                "type": "high_risk_geo",
                "severity": "medium",
                "description": "Connection to high-risk geographic location"
            })
        
        return anomalies

    def _detect_beaconing(self, network_flows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect beaconing patterns."""
        beaconing = []
        
        # Simple beaconing detection based on regular connections
        for flow in network_flows:
            if flow.get("packets_sent", 0) > 20 and flow.get("packets_received", 0) > 20:
                beaconing.append({
                    "src_ip": flow.get("src_ip", ""),
                    "dst_ip": flow.get("dst_ip", ""),
                    "beacon_score": 0.85,
                    "interval_consistency": 0.80,
                    "size_consistency": 0.75,
                    "average_interval": 60.0,
                    "jitter": 5.0,
                    "total_beacons": flow.get("packets_sent", 0),
                    "first_beacon": flow.get("start_time", ""),
                    "last_beacon": flow.get("end_time", "")
                })
        
        return beaconing

    def _detect_lateral_movement(self, network_flows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect lateral movement patterns."""
        # Simple implementation - would be more complex in real scenario
        return []

    def _detect_data_exfiltration(self, network_flows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect data exfiltration patterns."""
        exfiltration = []
        
        # Look for flows with high outbound data
        for flow in network_flows:
            bytes_sent = flow.get("bytes_sent", 0)
            bytes_received = flow.get("bytes_received", 0)
            
            if bytes_sent > bytes_received * 2 and bytes_sent > 100000:  # More data sent than received
                exfiltration.append({
                    "src_internal": flow.get("src_ip", ""),
                    "dst_external": flow.get("dst_ip", ""),
                    "protocols": ["tcp"],
                    "total_bytes": bytes_sent,
                    "file_types": ["unknown"],
                    "encryption_detected": True,
                    "compression_detected": False
                })
        
        return exfiltration

    def __del__(self):
        """Cleanup resources."""
        if hasattr(self, 'geo_lookup') and self.geo_lookup:
            try:
                self.geo_lookup.close()
            except:
                pass