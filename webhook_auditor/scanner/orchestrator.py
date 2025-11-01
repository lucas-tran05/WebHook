"""Orchestrator for running all security tests based on selected standards."""
import httpx
from .config import ScannerSettings
from .stride import run_stride_tests
from .pci_dss import run_pci_dss_tests
from .owasp import run_owasp_tests
from ..utils.reporter import generate_report
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn


async def run_all_tests(config: ScannerSettings):
    """
    Run security tests based on selected standards against the target webhook endpoint.
    
    Args:
        config: Scanner configuration with target URL, settings, and test standards
    """
    console = Console()
    
    # Determine which standards to test
    standards = config.test_standards if config.test_standards else ["STRIDE"]
    standards_str = ", ".join(standards)
    
    console.print(f"\n[bold cyan]🔍 Starting Webhook Security Scan[/bold cyan]")
    console.print(f"[dim]Target: {config.target_url}[/dim]")
    console.print(f"[dim]Standards: {standards_str}[/dim]\n")
    
    all_results = []
    
    # Create HTTP client with custom settings
    timeout = httpx.Timeout(30.0, connect=10.0)
    
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            
            # STRIDE Tests
            if "STRIDE" in standards:
                task = progress.add_task("[cyan]Testing STRIDE Security Model...", total=None)
                results = await run_stride_tests(config, client)
                all_results.extend(results)
                progress.update(task, completed=True)
            
            # PCI DSS Tests
            if any(std in standards for std in ["PCI-DSS", "PCI DSS", "PCI_DSS", "pci_dss"]):
                task = progress.add_task("[cyan]Testing PCI DSS Compliance...", total=None)
                results = await run_pci_dss_tests(config)
                all_results.extend(results)
                progress.update(task, completed=True)
            
            # OWASP Tests
            if "OWASP" in standards:
                task = progress.add_task("[cyan]Testing OWASP Top 10...", total=None)
                results = await run_owasp_tests(config)
                all_results.extend(results)
                progress.update(task, completed=True)
    
    console.print("\n[bold green]✓ Scan Complete[/bold green]\n")
    
    # Generate and display report
    generate_report(all_results, config.target_url)
    
    return all_results
