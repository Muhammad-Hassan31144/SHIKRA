"""
SHIKRA Analysis CLI Module

Provides command-line interface for all analysis modules:
- memory: Memory dump analysis
- network: Network traffic analysis
- disk: Disk image analysis
- procmon: Process monitoring analysis
"""

import typer
from .memory import cli as memory_cli
from .network import cli as network_cli
from .disk import cli as disk_cli
from .procmon import cli as procmon_cli

app = typer.Typer(
    name="analysis",
    help="Analysis modules for comprehensive malware forensics.",
    add_completion=False,
)

# Add analysis submodules
app.add_typer(memory_cli.app, name="memory")
app.add_typer(network_cli.app, name="network")
app.add_typer(disk_cli.app, name="disk")
app.add_typer(procmon_cli.app, name="procmon")
