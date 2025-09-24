"""
SHIKRA Hunt CLI Module

Provides command-line interface for threat hunting and static analysis operations.
"""

import typer
from typing_extensions import Annotated
from pathlib import Path
from typing import Optional
import json
import sys

from .static_analysis import StaticAnalyzer

app = typer.Typer(
    name="hunt",
    help="Threat hunting and static analysis for malware samples.",
    add_completion=False,
)

@app.command()
def analyze(
    sample_path: Annotated[Path, typer.Argument(help="Path to the malware sample file to analyze")],
    output_dir: Annotated[Optional[Path], typer.Option("--output-dir", "-d", help="Output directory for analysis artifacts")] = None,
    output_format: Annotated[str, typer.Option("--format", "-f", help="Output format")] = "summary",
    quick: Annotated[bool, typer.Option("--quick", "-q", help="Quick triage mode - skip expensive operations")] = False,
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Enable verbose logging output")] = False
):
    """
    Perform static analysis on a malware sample.
    
    This command runs comprehensive static analysis including:
    - File type and metadata extraction
    - Hash computation and entropy analysis  
    - String extraction and pattern matching
    - Import/export analysis
    - YARA rule matching
    - Risk assessment and scoring
    """
    if not sample_path.exists():
        typer.echo(f"❌ Sample file does not exist: {sample_path}", err=True)
        raise typer.Exit(code=1)
    
    if verbose:
        import logging
        logging.basicConfig(level=logging.DEBUG, 
                          format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
    try:
        typer.echo(f"🔍 Starting static analysis of: {sample_path}")
        
        analyzer = StaticAnalyzer()
        results = analyzer.analyze_sample(
            str(sample_path),
            output_dir=str(output_dir) if output_dir else None,
            skip_expensive=quick
        )
        
        # Handle different output formats
        if output_format == "json":
            typer.echo(json.dumps(results, indent=2, default=str))
        elif output_format == "monitoring":
            monitoring_config = _generate_monitoring_config(results)
            typer.echo(json.dumps(monitoring_config, indent=2, default=str))
        else:  # summary format (default)
            _display_summary(results)
        
        typer.echo("✅ Static analysis completed successfully")
        
    except Exception as e:
        typer.echo(f"❌ Analysis failed: {e}", err=True)
        if verbose:
            import traceback
            typer.echo(traceback.format_exc(), err=True)
        raise typer.Exit(code=1)

@app.command()
def triage(
    sample_path: Annotated[Path, typer.Argument(help="Path to the malware sample file")],
    output_dir: Annotated[Optional[Path], typer.Option("--output-dir", "-d", help="Output directory")] = None
):
    """
    Quick triage analysis for rapid threat assessment.
    
    Performs lightweight analysis focused on immediate threat indicators:
    - Basic file analysis and hashing
    - Quick string extraction
    - Essential metadata extraction
    - Risk scoring
    """
    if not sample_path.exists():
        typer.echo(f"❌ Sample file does not exist: {sample_path}", err=True)
        raise typer.Exit(code=1)
    
    try:
        typer.echo(f"⚡ Quick triage analysis of: {sample_path}")
        
        analyzer = StaticAnalyzer()
        results = analyzer.analyze_sample(
            str(sample_path),
            output_dir=str(output_dir) if output_dir else None,
            skip_expensive=True  # Quick mode
        )
        
        _display_triage_summary(results)
        
    except Exception as e:
        typer.echo(f"❌ Triage failed: {e}", err=True)
        raise typer.Exit(code=1)

@app.command()
def monitor_config(
    sample_path: Annotated[Path, typer.Argument(help="Path to the malware sample file")],
    output_file: Annotated[Optional[Path], typer.Option("--output", "-o", help="Output file for monitoring config")] = None
):
    """
    Generate monitoring configuration based on static analysis.
    
    Creates configuration for dynamic analysis monitoring based on 
    static analysis findings including:
    - Process names to monitor
    - Registry keys to watch
    - File paths to track
    - Network indicators
    """
    if not sample_path.exists():
        typer.echo(f"❌ Sample file does not exist: {sample_path}", err=True)
        raise typer.Exit(code=1)
    
    try:
        typer.echo(f"⚙️ Generating monitoring config for: {sample_path}")
        
        analyzer = StaticAnalyzer()
        results = analyzer.analyze_sample(str(sample_path), skip_expensive=True)
        
        monitoring_config = _generate_monitoring_config(results)
        
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(monitoring_config, f, indent=2, default=str)
            typer.echo(f"📄 Monitoring config saved to: {output_file}")
        else:
            typer.echo(json.dumps(monitoring_config, indent=2, default=str))
        
    except Exception as e:
        typer.echo(f"❌ Config generation failed: {e}", err=True)
        raise typer.Exit(code=1)

def _display_summary(results: dict):
    """Display a formatted summary of analysis results."""
    typer.echo("\n" + "="*60)
    typer.echo("📊 STATIC ANALYSIS SUMMARY")
    typer.echo("="*60)
    
    # Risk Assessment
    risk = results.get("risk_assessment", {})
    risk_level = risk.get("level", "UNKNOWN")
    risk_score = risk.get("score", 0)
    
    risk_color = "red" if risk_level in ["HIGH", "CRITICAL"] else "yellow" if risk_level == "MEDIUM" else "green"
    typer.echo(f"🎯 Risk Level: ", nl=False)
    typer.echo(f"{risk_level} ({risk_score:.1f}/10)", fg=risk_color)
    
    # Basic Info
    basic = results.get("basic_analysis", {})
    typer.echo(f"📁 File Type: {basic.get('file_type', 'Unknown')}")
    typer.echo(f"📏 File Size: {basic.get('size', 0):,} bytes")
    typer.echo(f"🔐 MD5: {basic.get('md5', 'N/A')}")
    typer.echo(f"🔐 SHA256: {basic.get('sha256', 'N/A')}")
    
    # Key Findings
    recommendations = results.get("recommendations", [])
    if recommendations:
        typer.echo("\n🔍 Key Findings:")
        for rec in recommendations[:5]:  # Show top 5
            typer.echo(f"  • {rec}")
    
    typer.echo("\n" + "="*60)

def _display_triage_summary(results: dict):
    """Display a quick triage summary."""
    typer.echo("\n" + "="*40)
    typer.echo("⚡ QUICK TRIAGE RESULTS")
    typer.echo("="*40)
    
    risk = results.get("risk_assessment", {})
    risk_level = risk.get("level", "UNKNOWN")
    risk_score = risk.get("score", 0)
    
    if risk_level in ["HIGH", "CRITICAL"]:
        typer.echo(f"🚨 HIGH RISK: {risk_score:.1f}/10", fg="red")
        typer.echo("⚠️  Recommend immediate containment")
    elif risk_level == "MEDIUM":
        typer.echo(f"⚠️  MEDIUM RISK: {risk_score:.1f}/10", fg="yellow")
        typer.echo("👀 Requires further investigation")  
    else:
        typer.echo(f"✅ LOW RISK: {risk_score:.1f}/10", fg="green")
        typer.echo("📈 Safe for detailed analysis")
    
    typer.echo("="*40)

def _generate_monitoring_config(static_results: dict) -> dict:
    """Generate monitoring configuration from static analysis results."""
    from datetime import datetime
    
    # Extract IoCs and create monitoring config
    config = {
        "generated_at": datetime.now().isoformat(),
        "source": "shikra_static_analysis",
        "monitoring_targets": {
            "processes": [],
            "files": [],
            "registry": [],
            "network": []
        }
    }
    
    # Extract process names from strings/imports
    strings_data = static_results.get("strings", {})
    processes = strings_data.get("process_names", [])
    config["monitoring_targets"]["processes"] = processes[:10]  # Top 10
    
    # Extract file paths
    file_paths = strings_data.get("file_paths", [])
    config["monitoring_targets"]["files"] = file_paths[:20]  # Top 20
    
    # Extract registry keys
    registry_keys = strings_data.get("registry_keys", [])
    config["monitoring_targets"]["registry"] = registry_keys[:15]  # Top 15
    
    # Extract network indicators
    network_data = strings_data.get("network_indicators", [])
    config["monitoring_targets"]["network"] = network_data[:10]  # Top 10
    
    return config
