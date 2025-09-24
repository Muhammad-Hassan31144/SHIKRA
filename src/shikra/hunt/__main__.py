"""
Shikra Static Analysis Module - Main Entry Point
Fixes the RuntimeWarning when executing as a module
"""

import sys
import os

# Add the project root to sys.path to avoid import issues
project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

def main():
    """Main entry point for module execution"""
    from shikra.core.modules.static_analysis import main as analysis_main
    return analysis_main()

if __name__ == "__main__":
    sys.exit(main())
