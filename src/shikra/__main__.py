#!/usr/bin/env python3
"""
Entry point for running ransomkit as a module.

This allows the package to be executed as:
    python3 -m ransomkit [command] [options]
"""

from .cli import app

if __name__ == "__main__":
    app()
