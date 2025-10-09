"""Test scanner with no secret key."""
import asyncio
from webhook_auditor.scanner.config import ScannerSettings
from webhook_auditor.scanner.orchestrator import run_all_tests

async def test_no_secret():
    """Test scanner without shared secret."""
    config = ScannerSettings(
        target_url='https://webhook-test.com/test',
        sample_valid_payload='{"test":"data"}',
        test_standards=['STRIDE']
        # No shared_secret provided
    )
    
    results = await run_all_tests(config)
    
    print(f"\nTotal results: {len(results)}")
    for result in results:
        print(f"  {result['status']} - {result['name']}")
    
    # Check all results are WARN or PASS (not crashing)
    assert all(r['status'] in ['WARN', 'PASS'] for r in results), "Some tests failed!"
    print("\n✅ All tests passed! No crashes with empty secret.")

if __name__ == "__main__":
    asyncio.run(test_no_secret())
