import aiohttp
import asyncio
import sqlite3
import json
from pathlib import Path
from typing import Dict, Any, Optional, List
from datetime import datetime
import logging

from .logger import setup_logger

# It's better practice to load this from an environment variable or a secure config
# For this example, it's placed here for simplicity.
VT_API_KEY = "YOUR_VIRUSTOTAL_API_KEY_HERE" 
VT_API_URL = "https://www.virustotal.com/api/v3/files/{hash}"

class VTEnricher:
    """
    Enriches file hashes with VirusTotal data, using a local SQLite cache
    to avoid redundant API calls.
    """
    def __init__(self, api_key: str, cache_db: str = "data/vt_cache.db"):
        if not api_key or api_key == "YOUR_VIRUSTOTAL_API_KEY_HERE":
            raise ValueError("A valid VirusTotal API key is required.")
        self.api_key = api_key
        self.cache_db_path = Path(cache_db)
        self.cache_db_path.parent.mkdir(parents=True, exist_ok=True)
        self.logger = setup_logger("VTEnricher")
        self._init_cache()

    def _init_cache(self):
        """Initializes the SQLite database and cache table."""
        try:
            with sqlite3.connect(self.cache_db_path) as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS vt_cache (
                        hash TEXT PRIMARY KEY,
                        response TEXT,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                """)
        except sqlite3.Error as e:
            self.logger.error(f"Database error: {e}")
            raise

    async def query_hash(self, file_hash: str) -> Optional[Dict[str, Any]]:
        """
        Asynchronously queries VirusTotal for a file hash, using a cache first.
        """
        if not file_hash:
            return None
            
        # Check cache first
        cached = self._get_cached_result(file_hash)
        if cached:
            self.logger.info(f"Found cached VT result for hash: {file_hash[:10]}...")
            return cached
        
        # If not in cache, query API
        self.logger.info(f"Querying VT API for hash: {file_hash[:10]}...")
        headers = {"x-apikey": self.api_key}
        url = VT_API_URL.format(hash=file_hash)
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers) as response:
                    if response.status == 200:
                        result = await response.json()
                        self._cache_result(file_hash, result)
                        return result
                    elif response.status == 404:
                        self.logger.warning(f"Hash not found on VirusTotal: {file_hash}")
                        # Cache the "not found" result to avoid re-querying
                        self._cache_result(file_hash, {"error": "not_found"})
                        return None
                    else:
                        self.logger.error(f"VirusTotal API error: {response.status} - {await response.text()}")
                        return None
        except aiohttp.ClientError as e:
            self.logger.error(f"HTTP client error during VT query: {e}")
            return None

    async def query_ip(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """
        Query VirusTotal for IP reputation information.
        """
        if not ip_address:
            return None
            
        ip_key = f"ip_{ip_address}"
        
        # Check cache first
        cached = self._get_cached_result(ip_key)
        if cached:
            self.logger.info(f"Found cached VT IP result for: {ip_address}")
            return cached
        
        # Query VT IP API
        self.logger.info(f"Querying VT API for IP: {ip_address}")
        headers = {"x-apikey": self.api_key}
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers) as response:
                    if response.status == 200:
                        result = await response.json()
                        self._cache_result(ip_key, result)
                        return result
                    elif response.status == 404:
                        self.logger.warning(f"IP not found on VirusTotal: {ip_address}")
                        self._cache_result(ip_key, {"error": "not_found"})
                        return None
                    else:
                        self.logger.error(f"VirusTotal IP API error: {response.status}")
                        return None
        except aiohttp.ClientError as e:
            self.logger.error(f"HTTP client error during VT IP query: {e}")
            return None
    
    def _get_cached_result(self, file_hash: str) -> Optional[Dict[str, Any]]:
        """Retrieves a result from the SQLite cache if it exists."""
        try:
            with sqlite3.connect(self.cache_db_path) as conn:
                cursor = conn.execute(
                    "SELECT response FROM vt_cache WHERE hash = ?", (file_hash,)
                )
                row = cursor.fetchone()
                return json.loads(row[0]) if row else None
        except sqlite3.Error as e:
            self.logger.error(f"Cache read error: {e}")
            return None

    def _cache_result(self, file_hash: str, data: Dict[str, Any]):
        """Stores a VirusTotal API response in the SQLite cache."""
        try:
            with sqlite3.connect(self.cache_db_path) as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO vt_cache (hash, response) VALUES (?, ?)",
                    (file_hash, json.dumps(data))
                )
        except sqlite3.Error as e:
            self.logger.error(f"Cache write error: {e}")

    def extract_detection_ratio(self, vt_result: Dict[str, Any]) -> str:
        """Extract detection ratio from VT result."""
        try:
            stats = vt_result.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            malicious = stats.get('malicious', 0)
            total = sum(stats.values()) if stats else 0
            return f"{malicious}/{total}" if total > 0 else "0/0"
        except:
            return "Unknown"
    
    def extract_threat_names(self, vt_result: Dict[str, Any]) -> List[str]:
        """Extract threat names from VT result."""
        try:
            results = vt_result.get('data', {}).get('attributes', {}).get('last_analysis_results', {})
            threats = []
            for engine, result in results.items():
                if result.get('category') == 'malicious' and result.get('result'):
                    threats.append(f"{engine}: {result['result']}")
            return threats[:5]  # Limit to top 5 detections
        except:
            return []
    
    def calculate_reputation_score(self, vt_result: Dict[str, Any]) -> int:
        """Calculate a reputation score (0-100) based on VT results."""
        try:
            stats = vt_result.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            malicious = stats.get('malicious', 0)
            total = sum(stats.values()) if stats else 0
            
            if total == 0:
                return 50  # Unknown
            
            malicious_ratio = malicious / total
            return max(0, 100 - int(malicious_ratio * 100))  # Higher score = more trusted
        except:
            return 50
    
    def extract_signature_info(self, vt_result: Dict[str, Any]) -> bool:
        """Check if the file is digitally signed."""
        try:
            signature_info = vt_result.get('data', {}).get('attributes', {}).get('signature_info', {})
            return bool(signature_info.get('verified'))
        except:
            return False
    
    def extract_malware_families(self, vt_result: Dict[str, Any]) -> List[str]:
        """Extract malware family names from VT result."""
        try:
            families = []
            popular_threat_names = vt_result.get('data', {}).get('attributes', {}).get('popular_threat_classification', {})
            if popular_threat_names:
                families.extend(popular_threat_names.get('suggested_threat_label', '').split())
            
            # Also check sandbox family names
            sandbox_verdicts = vt_result.get('data', {}).get('attributes', {}).get('sandbox_verdicts', {})
            for sandbox, verdict in sandbox_verdicts.items():
                if verdict.get('malware_classification'):
                    families.extend(verdict['malware_classification'])
            
            return list(set(families))[:3]  # Limit and deduplicate
        except:
            return []
    
    def calculate_suspicion_boost(self, vt_result: Dict[str, Any]) -> int:
        """Calculate how much to boost suspicion score based on VT results."""
        try:
            stats = vt_result.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            malicious = stats.get('malicious', 0)
            total = sum(stats.values()) if stats else 0
            
            if total == 0:
                return 0
            
            malicious_ratio = malicious / total
            if malicious_ratio > 0.5:  # More than 50% detect as malicious
                return 40
            elif malicious_ratio > 0.3:  # 30-50% detect as malicious
                return 25
            elif malicious_ratio > 0.1:  # 10-30% detect as malicious
                return 15
            elif malicious_ratio > 0:  # Any detection
                return 10
            
            return 0
        except:
            return 0
    
    def extract_ip_reputation(self, vt_result: Dict[str, Any]) -> Dict[str, Any]:
        """Extract IP reputation information from VT IP result."""
        try:
            attributes = vt_result.get('data', {}).get('attributes', {})
            reputation = attributes.get('reputation', 0)
            
            # Extract categories
            categories = []
            if 'categories' in attributes:
                categories = list(attributes['categories'].keys())
            
            # Check for malicious votes
            last_analysis_stats = attributes.get('last_analysis_stats', {})
            malicious_votes = last_analysis_stats.get('malicious', 0)
            total_votes = sum(last_analysis_stats.values()) if last_analysis_stats else 0
            
            return {
                'reputation_score': max(0, reputation),
                'threat_categories': categories,
                'is_malicious': malicious_votes > 0,
                'detection_ratio': f"{malicious_votes}/{total_votes}" if total_votes > 0 else "0/0"
            }
        except:
            return {
                'reputation_score': 50,
                'threat_categories': [],
                'is_malicious': False,
                'detection_ratio': "0/0"
            }
