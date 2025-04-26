"""
Thunderscan Scanner Modules
===========================

A collection of security scanning components for web application vulnerability detection.
"""

__version__ = "1.0.0"
__author__ = "Temitope Paul-Bamidele"
__license__ = "MIT"

from .spider import Spider
from .sqli_scanner import SQLiScanner
from .directory_bruteforcer import DirectoryBruteforcer

# Expose public API
__all__ = [
    'Spider',
    'SQLiScanner',
    'DirectoryBruteforcer'
]

def list_scanners():
    """Return available scanner classes"""
    return {
        'spider': Spider,
        'sql_injection': SQLiScanner,
        'directory_bruteforce': DirectoryBruteforcer
    }