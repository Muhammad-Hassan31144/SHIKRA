"""
SHIKRA Analysis Module

This module contains the core analysis components for malware forensics:
- disk: Disk image analysis and forensics
- memory: Memory dump analysis using Volatility
- network: Network traffic analysis with PCAP processing  
- procmon: Process monitoring log analysis

Each component provides both CLI and programmatic interfaces for comprehensive
malware behavior analysis.
"""

# For now, we'll import these on-demand to avoid circular import issues
# during the reorganization process. Users can still access them via:
# from shikra.analysis.disk import DiskAnalyzer
# from shikra.analysis.memory import MemoryAnalyzer  
# from shikra.analysis.network import NetworkAnalyzer
# from shikra.analysis.procmon import ProcMonAnalyzer

__all__ = [
    "disk",
    "memory", 
    "network",
    "procmon"
]
