"""Test scanner with all standards and no secret."""
import asyncio
from webhook_auditor.scanner.config import ScannerSettings
from webhook_auditor.scanner.orchestrator import run_all_tests

async def test_all_standards_no_secret():
    """Test scanner with all standards without shared secret."""
    config = ScannerSettings(
        target_url='https://webhook-test.com/test',
        sample_valid_payload='{"test":"data"}',
        test_standards=['STRIDE', 'PCI-DSS', 'OWASP']
        # No shared_secret provided
    )
    
    results = await run_all_tests(config)
    
    print(f"\nTotal results: {len(results)}")
    
    # Group by status
    by_status = {}
    for result in results:
        status = result['status']
        by_status[status] = by_status.get(status, 0) + 1
    
    print(f"\nBy status:")
    for status, count in sorted(by_status.items()):
        print(f"  {status}: {count}")
    
    # Check no crashes (all results should be WARN, PASS, or FAIL)
    valid_statuses = ['WARN', 'PASS', 'FAIL']
    assert all(r['status'] in valid_statuses for r in results), "Invalid status found!"
    print("\n✅ All standards tested successfully! No crashes with empty secret.")

if __name__ == "__main__":
    asyncio.run(test_all_standards_no_secret())
