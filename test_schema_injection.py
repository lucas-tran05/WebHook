"""
Test schema-based injection testing.

This demonstrates how the new field-based schema works:
1. Define fields with types (event: string, id: integer)
2. Scanner generates injection payloads for each field
3. Tests SQL injection, XSS, command injection, etc. on appropriate fields
4. No duplicate default payload tests
"""
import asyncio
import httpx
import json

async def test_schema_based_injection():
    """Test the schema-based injection feature."""
    
    # Define payload schema
    payload_schema = [
        {
            "name": "event",
            "type": "string",
            "example": "user.created"
        },
        {
            "name": "id",
            "type": "integer",
            "example": 12345
        },
        {
            "name": "email",
            "type": "email",
            "example": "user@example.com"
        }
    ]
    
    # Prepare scan request
    scan_request = {
        "target_url": "https://webhook-test.com/test",
        "http_method": "POST",
        "payload_schema": payload_schema,
        "test_standards": []  # Empty to focus on injection only
    }
    
    print("="*70)
    print("🧪 Testing Schema-Based Injection")
    print("="*70)
    print(f"\n📋 Payload Schema:")
    for field in payload_schema:
        print(f"   - {field['name']}: {field['type']} (e.g., {field['example']})")
    
    print(f"\n🎯 Target: {scan_request['target_url']}")
    print(f"\n🚀 Starting scan...\n")
    
    # Send request
    async with httpx.AsyncClient(timeout=120.0) as client:
        response = await client.post(
            "http://localhost:8080/api/scan",
            json=scan_request
        )
        
        if response.status_code == 200:
            data = response.json()
            
            print(f"✅ Scan completed!")
            print(f"\n📊 Statistics:")
            print(f"   Total Tests: {data['total_tests']}")
            print(f"   Passed: {data['passed']}")
            print(f"   Failed: {data['failed']}")
            print(f"   Warnings: {data['warnings']}")
            
            print(f"\n📝 Test Results:")
            
            # Group by field
            by_field = {}
            for result in data['results']:
                payload_name = result.get('payload_name', 'Unknown')
                if payload_name not in by_field:
                    by_field[payload_name] = []
                by_field[payload_name].append(result)
            
            for field_name, results in list(by_field.items())[:10]:  # Show first 10
                status_icon = "✅" if results[0]['status'] == 'PASS' else "❌" if results[0]['status'] == 'FAIL' else "⚠️"
                print(f"\n   {status_icon} {field_name}")
                print(f"      Status: {results[0]['status']}")
                print(f"      Details: {results[0]['details'][:80]}...")
            
            if len(by_field) > 10:
                print(f"\n   ... and {len(by_field) - 10} more tests")
            
            print(f"\n💡 Summary: {data['summary']}")
        else:
            print(f"❌ Error: {response.status_code}")
            print(response.text)
    
    print("\n" + "="*70)
    print("✨ Test complete!")
    print("="*70)


if __name__ == "__main__":
    asyncio.run(test_schema_based_injection())
