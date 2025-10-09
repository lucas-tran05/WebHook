"""Main CLI entry point for the Webhook Security Auditor."""
import click
import asyncio
from webhook_auditor.scanner.config import ScannerSettings
from webhook_auditor.scanner.orchestrator import run_all_tests


@click.group()
@click.version_option(version="1.0.0", prog_name="Webhook Security Auditor")
def cli():
    """
    Webhook Security Auditor - STRIDE-based security testing for webhooks.
    
    Security scanner to audit webhook endpoints against STRIDE threats
    via CLI or Web Interface.
    """
    pass


@cli.command()
@click.option(
    '--target-url',
    required=True,
    help='The webhook endpoint URL to test'
)
@click.option(
    '--secret',
    default=None,
    help='The shared secret key for HMAC signature generation (optional)'
)
@click.option(
    '--method',
    default='POST',
    help='HTTP method to use (default: POST)'
)
@click.option(
    '--signature-header',
    default='X-Webhook-Signature',
    help='HTTP header name for the signature (default: X-Webhook-Signature)'
)
@click.option(
    '--timestamp-header',
    default='X-Webhook-Timestamp',
    help='HTTP header name for the timestamp (default: X-Webhook-Timestamp)'
)
@click.option(
    '--payload',
    default='{"event": "test", "data": "sample"}',
    help='Sample valid JSON payload for testing'
)
@click.option(
    '--signature-prefix',
    default='sha256=',
    help='Prefix for the signature (default: sha256=)'
)
@click.option(
    '--custom-header',
    multiple=True,
    help='Custom headers in format "Header-Name: value" (can be used multiple times)'
)
@click.option(
    '--standards',
    default='STRIDE',
    help='Security standards to test (comma-separated: STRIDE,PCI-DSS,OWASP)'
)
def scan(target_url, secret, method, signature_header, timestamp_header, payload, signature_prefix, custom_header, standards):
    """
    Run security scan against a webhook endpoint.
    
    This command performs comprehensive security testing based on selected standards:
    
    - STRIDE: Spoofing, Tampering, Repudiation, Information Disclosure, DoS, Privilege Escalation
    
    - PCI-DSS: Payment Card Industry Data Security Standard compliance
    
    - OWASP: Open Web Application Security Project Top 10
    
    Example:
        python main.py scan --target-url https://api.example.com/webhook --secret mysecret
        
        python main.py scan --target-url https://api.example.com/webhook --standards STRIDE,PCI-DSS,OWASP
        
        python main.py scan --target-url https://api.example.com/webhook --custom-header "X-API-Key: abc123"
    """
    # Parse custom headers
    custom_headers_dict = {}
    for header in custom_header:
        if ':' in header:
            key, value = header.split(':', 1)
            custom_headers_dict[key.strip()] = value.strip()
    
    # Parse standards
    standards_list = [s.strip().upper() for s in standards.split(',')]
    
    # Create configuration
    config = ScannerSettings(
        target_url=target_url,
        http_method=method,
        shared_secret=secret,
        signature_header_name=signature_header,
        timestamp_header_name=timestamp_header,
        sample_valid_payload=payload,
        signature_prefix=signature_prefix,
        custom_headers=custom_headers_dict if custom_headers_dict else None,
        test_standards=standards_list
    )
    
    # Run the scan
    asyncio.run(run_all_tests(config))





@cli.command()
@click.option(
    '--host',
    default='0.0.0.0',
    help='Host to bind the web interface to (default: 0.0.0.0)'
)
@click.option(
    '--port',
    default=8080,
    type=int,
    help='Port for the web interface (default: 8080)'
)
def web(host, port):
    """
    Start the web interface for security scanning.
    
    Launches a browser-based interface where you can configure and run
    security scans against webhook endpoints with a user-friendly GUI.
    
    Example:
        python main.py web --port 8080
    """
    import uvicorn
    click.echo(f"\n🚀 Starting Web Interface on http://{host}:{port}")
    click.echo("📍 Open your browser and navigate to the URL above")
    click.echo("📚 API documentation: http://{}:{}/docs\n".format(host if host != '0.0.0.0' else 'localhost', port))
    
    # Import and run the web scanner
    from web_scanner import app
    uvicorn.run(app, host=host, port=port, log_level="info")


if __name__ == '__main__':
    cli()
