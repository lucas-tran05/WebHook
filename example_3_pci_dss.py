"""
Example 3: PCI-DSS Compliance Test (Cardholder Data Protection)

Test để đảm bảo không có dữ liệu thẻ tín dụng bị lưu trữ
"""

import httpx
import sys

def main():
    print("=" * 80)
    print("💳 PCI-DSS Compliance Test")
    print("=" * 80)
    
    # Schema cho payment webhook
    schema = [
        {"name": "transaction_id", "type": "string", "sample_value": "txn_123456789"},
        {"name": "amount", "type": "float", "sample_value": "99.99"},
        {"name": "currency", "type": "string", "sample_value": "USD"},
        {"name": "customer_email", "type": "email", "sample_value": "customer@example.com"},
        {"name": "card_token", "type": "string", "sample_value": "tok_visa_4111"}
    ]
    
    print("\n📋 Payment Schema:")
    for field in schema:
        print(f"   - {field['name']}: {field['type']} = {field['sample_value']}")
    
    print("\n🚀 Starting PCI-DSS compliance scan...")
    print("⏳ Checking for cardholder data (PAN, CVV)...\n")
    
    try:
        response = httpx.post("http://localhost:8080/api/scan", json={
            "target_url": "https://webhook.site/unique-id-here",
            "shared_secret": "pci_test_secret",
            "payload_schema": schema,
            "test_standards": ["PCI-DSS"]
        }, timeout=60.0)
        
        if response.status_code != 200:
            print(f"❌ Error: HTTP {response.status_code}")
            return
        
        result = response.json()
        all_tests = result['results']
        
        print("=" * 80)
        print("✅ PCI-DSS SCAN COMPLETE")
        print("=" * 80)
        
        print(f"\n📊 Total Tests: {len(all_tests)}")
        
        # Phân loại tests
        chd_tests = [t for t in all_tests if 'CHD' in t['name']]
        injection_tests = [t for t in all_tests if '6.5.1' in t['name']]
        xss_tests = [t for t in all_tests if '6.5.7' in t['name']]
        buffer_tests = [t for t in all_tests if '6.5.8' in t['name']]
        auth_tests = [t for t in all_tests if '6.5.10' in t['name']]
        
        print(f"\n🎯 PCI-DSS Requirements:")
        print(f"   - CHD Protection: {len(chd_tests)} tests")
        print(f"   - 6.5.1 Injection Prevention: {len(injection_tests)} tests")
        print(f"   - 6.5.7 XSS Prevention: {len(xss_tests)} tests")
        print(f"   - 6.5.8 Buffer Overflow: {len(buffer_tests)} tests")
        print(f"   - 6.5.10 Authentication: {len(auth_tests)} tests")
        
        # CHD Tests (CRITICAL)
        if chd_tests:
            print(f"\n🔒 CARDHOLDER DATA PROTECTION (CHD):")
            print("   " + "=" * 60)
            
            chd_failed = [t for t in chd_tests if t['status'] == 'FAIL']
            chd_passed = [t for t in chd_tests if t['status'] == 'PASS']
            
            if chd_failed:
                print(f"   🚨 CRITICAL: {len(chd_failed)} CHD violations detected!")
                print(f"\n   Failed Tests:")
                for test in chd_failed:
                    print(f"   ❌ {test['name']}")
                    print(f"      Details: {test['details']}")
                    print()
            else:
                print(f"   ✅ PASS: No cardholder data detected!")
            
            # Show what was tested
            print(f"\n   Tests performed:")
            for test in chd_tests[:5]:
                status_icon = "✅" if test['status'] == 'PASS' else "❌"
                print(f"   {status_icon} {test['name']}")
        
        # Injection Tests
        if injection_tests:
            print(f"\n💉 Requirement 6.5.1 - Injection Prevention:")
            failed = [t for t in injection_tests if t['status'] == 'FAIL']
            if failed:
                print(f"   ⚠️  {len(failed)} injection vulnerabilities found")
            else:
                print(f"   ✅ All injection tests passed")
        
        # Buffer Overflow Tests
        if buffer_tests:
            print(f"\n🛡️  Requirement 6.5.8 - Buffer Overflow Protection:")
            for test in buffer_tests:
                status_icon = "✅" if test['status'] == 'PASS' else "❌"
                print(f"   {status_icon} {test['name']}")
                print(f"      Status: {test['status']}")
        
        # Overall Summary
        passed = len([t for t in all_tests if t['status'] == 'PASS'])
        failed = len([t for t in all_tests if t['status'] == 'FAIL'])
        
        print(f"\n📈 Overall PCI-DSS Compliance:")
        print(f"   ✅ PASS: {passed}")
        print(f"   ❌ FAIL: {failed}")
        
        # Compliance Status
        chd_critical = len([t for t in chd_tests if t['status'] == 'FAIL']) if chd_tests else 0
        
        print(f"\n🎖️  COMPLIANCE STATUS:")
        if chd_critical > 0:
            print(f"   🚨 NON-COMPLIANT: Cardholder data detected!")
            print(f"   ⚠️  CRITICAL: Must fix CHD violations immediately")
            print(f"   📋 Action: Remove all PAN/CVV from storage and logs")
        elif failed > 0:
            print(f"   ⚠️  PARTIALLY COMPLIANT: {failed} issues found")
            print(f"   📋 Action: Review and fix failed tests")
        else:
            print(f"   ✅ COMPLIANT: Passed all PCI-DSS tests!")
            print(f"   🎉 No cardholder data vulnerabilities detected")
        
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
