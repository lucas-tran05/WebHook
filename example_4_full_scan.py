"""
Example 4: Full Security Scan (All Standards)

Comprehensive scan với STRIDE, OWASP, và PCI-DSS
"""

import httpx
import sys
import json
from datetime import datetime

def main():
    print("=" * 80)
    print("🔒 COMPREHENSIVE SECURITY SCAN")
    print("   STRIDE + OWASP + PCI-DSS")
    print("=" * 80)
    
    # Complete schema với nhiều field types
    schema = [
        {"name": "event", "type": "string", "sample_value": "order.created"},
        {"name": "order_id", "type": "integer", "sample_value": "789"},
        {"name": "customer_email", "type": "email", "sample_value": "customer@example.com"},
        {"name": "webhook_url", "type": "url", "sample_value": "https://example.com/notify"},
        {"name": "user_role", "type": "string", "sample_value": "customer"},
        {"name": "amount", "type": "float", "sample_value": "199.99"}
    ]
    
    print("\n📋 Complete Schema ({} fields):".format(len(schema)))
    for field in schema:
        print(f"   - {field['name']}: {field['type']} = {field['sample_value']}")
    
    print("\n🚀 Starting comprehensive security scan...")
    print("📊 Testing: STRIDE, OWASP Top 10, PCI-DSS")
    print("⏳ This may take 1-2 minutes...\n")
    
    try:
        start_time = datetime.now()
        
        response = httpx.post("http://localhost:8080/api/scan", json={
            "target_url": "https://webhook.site/unique-id-here",
            "shared_secret": "comprehensive_test_key",
            "payload_schema": schema,
            "test_standards": ["STRIDE", "OWASP", "PCI-DSS"]
        }, timeout=120.0)
        
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        if response.status_code != 200:
            print(f"❌ Error: HTTP {response.status_code}")
            print(f"Response: {response.text[:500]}")
            return
        
        result = response.json()
        all_tests = result['results']
        
        print("=" * 80)
        print("✅ COMPREHENSIVE SCAN COMPLETE")
        print("=" * 80)
        
        print(f"\n⏱️  Scan Duration: {duration:.1f} seconds")
        print(f"🆔 Scan ID: {result['scan_id']}")
        print(f"🎯 Total Tests: {len(all_tests)}")
        
        # Phân loại theo standard
        stride_tests = [t for t in all_tests if 'STRIDE' in t['name']]
        owasp_tests = [t for t in all_tests if 'OWASP' in t['name']]
        pci_tests = [t for t in all_tests if 'PCI-DSS' in t['name']]
        
        print(f"\n📊 Breakdown by Standard:")
        print(f"   🛡️  STRIDE: {len(stride_tests)} tests")
        print(f"   🌐 OWASP: {len(owasp_tests)} tests")
        print(f"   💳 PCI-DSS: {len(pci_tests)} tests")
        
        # Status breakdown
        passed = len([t for t in all_tests if t['status'] == 'PASS'])
        failed = len([t for t in all_tests if t['status'] == 'FAIL'])
        warnings = len([t for t in all_tests if t['status'] == 'WARN'])
        
        print(f"\n📈 Overall Results:")
        print(f"   ✅ PASS: {passed} ({passed*100//len(all_tests)}%)")
        print(f"   ❌ FAIL: {failed} ({failed*100//len(all_tests) if len(all_tests) > 0 else 0}%)")
        print(f"   ⚠️  WARN: {warnings} ({warnings*100//len(all_tests) if len(all_tests) > 0 else 0}%)")
        
        # STRIDE Category Breakdown
        print(f"\n🛡️  STRIDE Threat Model:")
        stride_categories = {
            'Spoofing': [t for t in stride_tests if 'Spoofing' in t['name']],
            'Tampering': [t for t in stride_tests if 'Tampering' in t['name']],
            'Repudiation': [t for t in stride_tests if 'Repudiation' in t['name']],
            'InfoDisclosure': [t for t in stride_tests if 'InfoDisclosure' in t['name']],
            'DoS': [t for t in stride_tests if 'DoS' in t['name']],
            'Privilege': [t for t in stride_tests if 'Privilege' in t['name']]
        }
        
        for category, tests in stride_categories.items():
            if tests:
                failed_count = len([t for t in tests if t['status'] == 'FAIL'])
                status = "❌" if failed_count > 0 else "✅"
                print(f"   {status} {category}: {len(tests)} tests ({failed_count} failed)")
        
        # OWASP Highlights
        print(f"\n🌐 OWASP Top 10 Highlights:")
        ssrf_tests = [t for t in owasp_tests if 'SSRF' in t['name']]
        injection_tests = [t for t in owasp_tests if 'Injection' in t['name']]
        xss_tests = [t for t in owasp_tests if 'XSS' in t['name']]
        
        if ssrf_tests:
            ssrf_failed = len([t for t in ssrf_tests if t['status'] == 'FAIL'])
            status = "❌" if ssrf_failed > 0 else "✅"
            print(f"   {status} A10-SSRF: {len(ssrf_tests)} tests ({ssrf_failed} failed)")
        
        if injection_tests:
            inj_failed = len([t for t in injection_tests if t['status'] == 'FAIL'])
            status = "❌" if inj_failed > 0 else "✅"
            print(f"   {status} A03-Injection: {len(injection_tests)} tests ({inj_failed} failed)")
        
        if xss_tests:
            xss_failed = len([t for t in xss_tests if t['status'] == 'FAIL'])
            status = "❌" if xss_failed > 0 else "✅"
            print(f"   {status} A07-XSS: {len(xss_tests)} tests ({xss_failed} failed)")
        
        # PCI-DSS Critical Check
        print(f"\n💳 PCI-DSS Compliance:")
        chd_tests = [t for t in pci_tests if 'CHD' in t['name']]
        if chd_tests:
            chd_failed = len([t for t in chd_tests if t['status'] == 'FAIL'])
            if chd_failed > 0:
                print(f"   🚨 CRITICAL: {chd_failed} cardholder data violations!")
            else:
                print(f"   ✅ No cardholder data detected")
        
        # Top Failed Tests
        failed_tests = [t for t in all_tests if t['status'] == 'FAIL']
        if failed_tests:
            print(f"\n❌ TOP FAILED TESTS:")
            for i, test in enumerate(failed_tests[:5], 1):
                print(f"\n{i}. {test['name']}")
                print(f"   Category: {test.get('category', 'Unknown')}")
                print(f"   Details: {test['details'][:100]}...")
        
        # Security Score
        security_score = (passed * 100) // len(all_tests) if len(all_tests) > 0 else 0
        print(f"\n🎯 SECURITY SCORE: {security_score}/100")
        
        if security_score >= 90:
            print("   🎉 EXCELLENT: Very secure configuration!")
        elif security_score >= 70:
            print("   ✅ GOOD: Minor issues to address")
        elif security_score >= 50:
            print("   ⚠️  FAIR: Several vulnerabilities found")
        else:
            print("   🚨 POOR: Critical security issues detected!")
        
        # Save detailed results
        output_file = f"scan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        
        print(f"\n💾 Detailed results saved to: {output_file}")
        
        # Recommendations
        print(f"\n💡 RECOMMENDATIONS:")
        if failed > 0:
            print(f"   1. Review {failed} failed tests above")
            print(f"   2. Fix critical vulnerabilities first (CHD, SSRF, Injection)")
            print(f"   3. Re-run scan after fixes")
            print(f"   4. Check detailed results in {output_file}")
        else:
            print(f"   ✅ All tests passed! Maintain security best practices:")
            print(f"   - Regular security scans")
            print(f"   - Keep dependencies updated")
            print(f"   - Monitor for new vulnerabilities")
        
        print("\n" + "=" * 80)
        print("🔒 Security scan complete!")
        print("=" * 80)
        
    except httpx.ConnectError:
        print("❌ Error: Cannot connect to server")
        print("💡 Make sure web_scanner.py is running:")
        print("   python web_scanner.py")
        sys.exit(1)
    except httpx.TimeoutException:
        print("❌ Error: Request timeout")
        print("💡 Server is taking too long. This is normal for full scans.")
        print("   Try running individual standard tests first.")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
