import maxminddb
from pathlib import Path
import ipaddress
from typing import Dict, Union, Optional
import logging

from .logger import setup_logger

class GeoIPLookup:
    """
    Provides GeoIP information for IP addresses using a MaxMind database.
    Implements the context manager protocol for safe file handling.
    """
    def __init__(self, db_path: str = "data/GeoLite2-City.mmdb"):
        self.db_path = Path(db_path)
        self.reader: Optional[maxminddb.Reader] = None
        self.logger = setup_logger("GeoIPLookup")

        if not self.db_path.exists():
            self.logger.error(f"GeoIP database not found at {self.db_path}. Please download it from MaxMind.")
            # We don't raise an error here, so the tool can run without it, just with less data.
            # The lookup method will handle the case where the reader is None.
            
    def __enter__(self):
        """Opens the database reader when entering a 'with' block."""
        if self.db_path.exists():
            try:
                self.reader = maxminddb.open_database(str(self.db_path))
            except maxminddb.errors.InvalidDatabaseError as e:
                self.logger.error(f"Invalid GeoIP database file: {e}")
                self.reader = None
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Closes the database reader when exiting a 'with' block."""
        if self.reader:
            self.reader.close()
            self.reader = None

    def lookup(self, ip: str) -> Dict[str, Union[str, float]]:
        """
        Get GeoIP information for an IP address. Returns an empty dict for
        private IPs or if the IP is not found.
        """
        if not self.reader:
            # The database wasn't loaded, so we can't perform a lookup.
            return {}
            
        if not ip:
            return {}
            
        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_unspecified:
                return {}
        except ValueError:
            self.logger.warning(f"Invalid IP address for lookup: {ip}")
            return {}

        try:
            result = self.reader.get(ip)
            if not result:
                return {}
            
            # Safely extract nested data using .get() with default values
            country = result.get("country", {})
            city = result.get("city", {})
            location = result.get("location", {})
            
            return {
                "country": country.get("names", {}).get("en", "Unknown"),
                "country_iso": country.get("iso_code", "XX"),
                "city": city.get("names", {}).get("en", "Unknown"),
                "latitude": location.get("latitude", 0.0),
                "longitude": location.get("longitude", 0.0),
            }
        except Exception as e:
            self.logger.error(f"An unexpected error occurred during GeoIP lookup for {ip}: {e}")
            return {"error": str(e)}
