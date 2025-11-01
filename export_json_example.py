"""Export scan results to JSON for demonstration."""
import asyncio
import json
from webhook_auditor.scanner.config import ScannerSettings
from webhook_auditor.scanner.orchestrator import run_all_tests


async def main():
    # Configure scan
    config = ScannerSettings(
        target_url='https://example.com',
        shared_secret='test123456789012',
        test_standards=['STRIDE', 'OWASP', 'PCI_DSS']
    )
    
    # Run scan (suppress console output by temporarily redirecting)
    results = await run_all_tests(config)
    
    # Create summary
    scan_output = {
        "scan_info": {
            "target": config.target_url,
            "standards": config.test_standards,
            "timestamp": "2025-11-01T00:00:00Z",
            "total_tests": len(results),
            "passed": sum(1 for r in results if r.get('status') == 'PASS'),
            "failed": sum(1 for r in results if r.get('status') == 'FAIL'),
            "warnings": sum(1 for r in results if r.get('status') == 'WARN')
        },
        "results": results
    }
    
    # Save to JSON
    with open('scan_results_example.json', 'w', encoding='utf-8') as f:
        json.dump(scan_output, f, indent=2, ensure_ascii=False, default=str)
    
    print("\n✅ JSON file created: scan_results_example.json")
    print(f"📊 Summary: {scan_output['scan_info']['total_tests']} tests")
    print(f"   ✓ Passed: {scan_output['scan_info']['passed']}")
    print(f"   ✗ Failed: {scan_output['scan_info']['failed']}")
    print(f"   ⚠ Warnings: {scan_output['scan_info']['warnings']}")
    
    # Show sample structure
    print("\n📄 JSON Structure Preview:")
    print(json.dumps(scan_output, indent=2, ensure_ascii=False, default=str)[:2000])
    print("\n... (full content in scan_results_example.json)")


if __name__ == '__main__':
    asyncio.run(main())
