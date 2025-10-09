"""
Example 1: Basic STRIDE Security Test

Ví dụ đơn giản nhất để test STRIDE threat model.
Chạy file này sau khi start web_scanner.py
"""

import httpx
import sys

def main():
    print("=" * 80)
    print("🔍 STRIDE Security Test Example")
    print("=" * 80)
    
    # Định nghĩa schema cho webhook
    schema = [
        {"name": "event", "type": "string", "sample_value": "user.created"},
        {"name": "user_id", "type": "integer", "sample_value": "123"},
        {"name": "email", "type": "email", "sample_value": "test@example.com"}
    ]
    
    print("\n📋 Schema defined:")
    for field in schema:
        print(f"   - {field['name']}: {field['type']} = {field['sample_value']}")
    
    print("\n🚀 Starting STRIDE scan...")
    print("⏳ Please wait (this may take 30-60 seconds)...\n")
    
    try:
        # Gửi request để scan
        response = httpx.post("http://localhost:8080/api/scan", json={
            "target_url": "https://webhook.site/unique-id-here",  # Thay bằng URL của bạn
            "shared_secret": "test_secret_key",
            "payload_schema": schema,
            "test_standards": ["STRIDE"]
        }, timeout=60.0)
        
        if response.status_code != 200:
            print(f"❌ Error: HTTP {response.status_code}")
            print(f"Response: {response.text}")
            return
        
        result = response.json()
        
        print("=" * 80)
        print("✅ SCAN COMPLETE")
        print("=" * 80)
        
        print(f"\n📊 Summary:")
        print(f"   Scan ID: {result['scan_id']}")
        print(f"   Total Tests: {len(result['results'])}")
        
        # Đếm theo category
        categories = {}
        for test in result['results']:
            name = test.get('name', '')
            if 'Spoofing' in name:
                categories['Spoofing'] = categories.get('Spoofing', 0) + 1
            elif 'Tampering' in name:
                categories['Tampering'] = categories.get('Tampering', 0) + 1
            elif 'Repudiation' in name:
                categories['Repudiation'] = categories.get('Repudiation', 0) + 1
            elif 'InfoDisclosure' in name:
                categories['InfoDisclosure'] = categories.get('InfoDisclosure', 0) + 1
            elif 'DoS' in name:
                categories['DoS'] = categories.get('DoS', 0) + 1
            elif 'Privilege' in name:
                categories['Privilege'] = categories.get('Privilege', 0) + 1
        
        print(f"\n🎯 STRIDE Categories:")
        for cat, count in sorted(categories.items()):
            print(f"   - {cat}: {count} tests")
        
        # Đếm PASS/FAIL
        passed = len([t for t in result['results'] if t['status'] == 'PASS'])
        failed = len([t for t in result['results'] if t['status'] == 'FAIL'])
        warnings = len([t for t in result['results'] if t['status'] == 'WARN'])
        
        print(f"\n📈 Results:")
        print(f"   ✅ PASS: {passed}")
        print(f"   ❌ FAIL: {failed}")
        print(f"   ⚠️  WARN: {warnings}")
        
        # Hiển thị top 5 tests
        print(f"\n🔍 Sample Tests (first 5):")
        for i, test in enumerate(result['results'][:5], 1):
            status_icon = "✅" if test['status'] == 'PASS' else "❌" if test['status'] == 'FAIL' else "⚠️"
            print(f"\n{i}. {status_icon} {test['name']}")
            print(f"   Status: {test['status']}")
            print(f"   Details: {test['details'][:80]}...")
        
        print("\n" + "=" * 80)
        print("✨ Test complete! Check full results above.")
        print("=" * 80)
        
    except httpx.ConnectError:
        print("❌ Error: Cannot connect to server")
        print("💡 Make sure web_scanner.py is running on http://localhost:8080")
        print("   Run: python web_scanner.py")
        sys.exit(1)
    except httpx.TimeoutException:
        print("❌ Error: Request timeout")
        print("💡 Server is taking too long. Try increasing timeout or check endpoint.")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
