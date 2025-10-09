"""Reporting module for displaying security scan results."""
from typing import List, Dict
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box


def generate_report(results: List[Dict], target_url: str):
    """
    Generate and print a formatted security report.
    
    Args:
        results: List of test result dictionaries
        target_url: The target URL that was scanned
    """
    console = Console()
    
    # Print header
    console.print()
    console.print(Panel.fit(
        f"[bold cyan]STRIDE Webhook Security Report[/bold cyan]\n"
        f"Target: [yellow]{target_url}[/yellow]",
        border_style="cyan"
    ))
    console.print()
    
    # Group results by category
    categories = {
        "Spoofing & Tampering": [],
        "Repudiation": [],
        "Information Disclosure": [],
        "Denial of Service": [],
        "Elevation of Privilege": [],
        "Injection Attacks": []
    }
    
    for result in results:
        category = result.get("category", "Unknown")
        if category in categories:
            categories[category].append(result)
    
    # Track overall statistics
    total_tests = len(results)
    passed_tests = sum(1 for r in results if r.get("status") == "PASS")
    failed_tests = sum(1 for r in results if r.get("status") == "FAIL")
    warnings = sum(1 for r in results if r.get("status") == "WARN")
    
    # Print results by category
    for category, tests in categories.items():
        if not tests:
            continue
            
        console.print(f"[bold magenta]{category}[/bold magenta]")
        console.print("=" * 60)
        
        for test in tests:
            status = test.get("status", "UNKNOWN")
            name = test.get("name", "Unnamed Test")
            details = test.get("details", "")
            risk = test.get("risk", "")
            mitigation = test.get("mitigation", "")
            
            # Status icon and color
            if status == "PASS":
                icon = "✓"
                color = "green"
            elif status == "FAIL":
                icon = "✗"
                color = "red"
            elif status == "WARN":
                icon = "⚠"
                color = "yellow"
            else:
                icon = "?"
                color = "white"
            
            console.print(f"  [{color}]{icon} [{status}][/{color}] {name}")
            
            if details:
                console.print(f"    [dim]{details}[/dim]")
            
            if status == "FAIL" and risk:
                console.print(f"    [red]⚠ Risk:[/red] {risk}")
            
            if status == "FAIL" and mitigation:
                console.print(f"    [cyan]💡 Mitigation:[/cyan] {mitigation}")
            
            console.print()
        
        console.print()
    
    # Print summary
    summary_table = Table(title="Summary", box=box.ROUNDED, show_header=False)
    summary_table.add_column("Metric", style="cyan")
    summary_table.add_column("Count", style="bold")
    
    summary_table.add_row("Total Tests", str(total_tests))
    summary_table.add_row("Passed", f"[green]{passed_tests}[/green]")
    summary_table.add_row("Failed", f"[red]{failed_tests}[/red]")
    summary_table.add_row("Warnings", f"[yellow]{warnings}[/yellow]")
    
    console.print(summary_table)
    console.print()
    
    # Overall assessment
    if failed_tests == 0:
        console.print(Panel(
            "[bold green]✓ All security tests passed![/bold green]",
            border_style="green"
        ))
    elif failed_tests <= 2:
        console.print(Panel(
            f"[bold yellow]⚠ {failed_tests} security issue(s) detected. Review and address them.[/bold yellow]",
            border_style="yellow"
        ))
    else:
        console.print(Panel(
            f"[bold red]✗ {failed_tests} security issues detected! Immediate action recommended.[/bold red]",
            border_style="red"
        ))
    
    console.print()
