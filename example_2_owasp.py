"""
Example 2: OWASP Top 10 with SSRF Detection

Test OWASP vulnerabilities, đặc biệt là SSRF (Server-Side Request Forgery)
"""

import httpx
import sys

def main():
    print("=" * 80)
    print("🔍 OWASP Top 10 Security Test")
    print("=" * 80)
    
    # Schema với URL field để test SSRF
    schema = [
        {"name": "event", "type": "string", "sample_value": "webhook.triggered"},
        {"name": "callback_url", "type": "url", "sample_value": "https://example.com/callback"},
        {"name": "user_id", "type": "integer", "sample_value": "456"},
        {"name": "email", "type": "email", "sample_value": "user@example.com"}
    ]
    
    print("\n📋 Schema with URL field (for SSRF testing):")
    for field in schema:
        print(f"   - {field['name']}: {field['type']} = {field['sample_value']}")
    
    print("\n🚀 Starting OWASP scan...")
    print("⏳ Testing for SSRF, Injection, XSS, and more...\n")
    
    try:
        response = httpx.post("http://localhost:8080/api/scan", json={
            "target_url": "https://webhook.site/unique-id-here",
            "shared_secret": "owasp_test_key",
            "payload_schema": schema,
            "test_standards": ["OWASP"]
        }, timeout=60.0)
        
        if response.status_code != 200:
            print(f"❌ Error: HTTP {response.status_code}")
            return
        
        result = response.json()
        all_tests = result['results']
        
        print("=" * 80)
        print("✅ OWASP SCAN COMPLETE")
        print("=" * 80)
        
        print(f"\n📊 Total Tests: {len(all_tests)}")
        
        # Phân loại theo OWASP category
        ssrf_tests = [t for t in all_tests if 'SSRF' in t['name'] or 'A10' in t['name']]
        injection_tests = [t for t in all_tests if 'Injection' in t['name'] or 'A03' in t['name']]
        xss_tests = [t for t in all_tests if 'XSS' in t['name'] or 'A07' in t['name']]
        access_tests = [t for t in all_tests if 'Access' in t['name'] or 'A01' in t['name']]
        path_tests = [t for t in all_tests if 'Path' in t['name'] or 'A05' in t['name']]
        
        print(f"\n🎯 OWASP Categories:")
        print(f"   - A10 SSRF: {len(ssrf_tests)} tests")
        print(f"   - A03 Injection: {len(injection_tests)} tests")
        print(f"   - A07 XSS: {len(xss_tests)} tests")
        print(f"   - A01 Access Control: {len(access_tests)} tests")
        print(f"   - A05 Misconfiguration: {len(path_tests)} tests")
        
        # SSRF Details (quan trọng nhất)
        if ssrf_tests:
            print(f"\n🚨 SSRF Tests (Server-Side Request Forgery):")
            print("   Testing if endpoint blocks internal IPs...")
            for test in ssrf_tests:
                status_icon = "✅" if test['status'] == 'PASS' else "❌"
                print(f"\n   {status_icon} {test['name']}")
                print(f"      Status: {test['status']}")
                if test['status'] == 'FAIL':
                    print(f"      ⚠️  WARNING: Potential SSRF vulnerability!")
                    print(f"      Details: {test['details']}")
        
        # Injection Details
        if injection_tests:
            print(f"\n💉 Injection Tests:")
            failed_injections = [t for t in injection_tests if t['status'] == 'FAIL']
            if failed_injections:
                print(f"   ⚠️  Found {len(failed_injections)} injection vulnerabilities!")
                for test in failed_injections[:3]:
                    print(f"   - {test['name']}")
            else:
                print(f"   ✅ All injection tests passed!")
        
        # Summary
        passed = len([t for t in all_tests if t['status'] == 'PASS'])
        failed = len([t for t in all_tests if t['status'] == 'FAIL'])
        
        print(f"\n📈 Overall Results:")
        print(f"   ✅ PASS: {passed}")
        print(f"   ❌ FAIL: {failed}")
        
        if failed > 0:
            print(f"\n⚠️  SECURITY ISSUES DETECTED:")
            print(f"   Found {failed} potential vulnerabilities")
            print(f"   Review failed tests above for details")
        else:
            print(f"\n✅ EXCELLENT: No vulnerabilities detected!")
        
        print("\n" + "=" * 80)
        
    except httpx.ConnectError:
        print("❌ Error: Cannot connect to server")
        print("💡 Run: python web_scanner.py")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
