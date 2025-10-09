"""Orchestrator for running all security tests based on selected standards."""
import httpx
from .config import ScannerSettings
from .spoofing_tests import run_spoofing_tampering_tests
from .repudiation_tests import run_repudiation_tests
from .info_disclosure_tests import run_info_disclosure_tests
from .dos_tests import run_dos_tests
from .privilege_escalation_tests import run_privilege_escalation_tests
from .injection_tests import run_injection_tests
from .pci_dss_tests import run_pci_dss_tests
from .owasp_tests import run_owasp_tests
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
                # Run Spoofing & Tampering tests
                task = progress.add_task("[cyan]Testing Spoofing & Tampering...", total=None)
                results = await run_spoofing_tampering_tests(config, client)
                all_results.extend(results)
                progress.update(task, completed=True)
                
                # Run Repudiation tests
                task = progress.add_task("[cyan]Testing Repudiation...", total=None)
                results = await run_repudiation_tests(config, client)
                all_results.extend(results)
                progress.update(task, completed=True)
                
                # Run Information Disclosure tests
                task = progress.add_task("[cyan]Testing Information Disclosure...", total=None)
                results = await run_info_disclosure_tests(config, client)
                all_results.extend(results)
                progress.update(task, completed=True)
                
                # Run Denial of Service tests
                task = progress.add_task("[cyan]Testing Denial of Service...", total=None)
                results = await run_dos_tests(config, client)
                all_results.extend(results)
                progress.update(task, completed=True)
                
                # Run Elevation of Privilege tests
                task = progress.add_task("[cyan]Testing Elevation of Privilege...", total=None)
                results = await run_privilege_escalation_tests(config, client)
                all_results.extend(results)
                progress.update(task, completed=True)
                
                # Run Injection tests
                task = progress.add_task("[cyan]Testing Injection Attacks...", total=None)
                results = await run_injection_tests(config, client)
                all_results.extend(results)
                progress.update(task, completed=True)
            
            # PCI DSS Tests
            if "PCI-DSS" in standards or "PCI DSS" in standards:
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
