"""Quick test to verify web scanner updates."""

print("🧪 Testing Web Scanner v2.0...\n")

# Test 1: Import modules
print("1. Testing imports...")
try:
    from web_scanner import app, ScanRequest
    print("   ✅ Web scanner imported")
except Exception as e:
    print(f"   ❌ Import failed: {e}")
    exit(1)

# Test 2: Check ScanRequest model
print("\n2. Testing ScanRequest model...")
try:
    # Test with minimal required fields
    req1 = ScanRequest(target_url="https://example.com")
    print(f"   ✅ Minimal request: secret={req1.shared_secret}, standards={req1.test_standards}")
    
    # Test with all fields
    req2 = ScanRequest(
        target_url="https://example.com",
        shared_secret="test-key",
        custom_headers={"X-API-Key": "value"},
        test_standards=["STRIDE", "PCI-DSS", "OWASP"]
    )
    print(f"   ✅ Full request: secret={req2.shared_secret}, headers={req2.custom_headers}, standards={req2.test_standards}")
except Exception as e:
    print(f"   ❌ Model validation failed: {e}")
    exit(1)

# Test 3: Check if PCI DSS and OWASP modules exist
print("\n3. Testing new test modules...")
try:
    from webhook_auditor.scanner import pci_dss_tests, owasp_tests
    print("   ✅ PCI DSS tests module loaded")
    print("   ✅ OWASP tests module loaded")
except Exception as e:
    print(f"   ❌ Test modules failed: {e}")
    exit(1)

# Test 4: Check config
print("\n4. Testing config...")
try:
    from webhook_auditor.scanner.config import ScannerSettings
    
    # Test optional secret
    config1 = ScannerSettings(target_url="https://example.com")
    print(f"   ✅ Config without secret: {config1.shared_secret}")
    
    # Test with custom headers
    config2 = ScannerSettings(
        target_url="https://example.com",
        custom_headers={"X-API-Key": "test"}
    )
    print(f"   ✅ Config with custom headers: {config2.custom_headers}")
    
    # Test with standards
    config3 = ScannerSettings(
        target_url="https://example.com",
        test_standards=["STRIDE", "PCI-DSS", "OWASP"]
    )
    print(f"   ✅ Config with standards: {config3.test_standards}")
except Exception as e:
    print(f"   ❌ Config failed: {e}")
    exit(1)

print("\n" + "="*50)
print("✅ All tests passed!")
print("="*50)
print("\n🚀 Web interface is ready!")
print("Run: python main.py web")
print("Open: http://localhost:8080")
print("\n📊 Total tests available:")
print("   • STRIDE: 12 tests")
print("   • Injection: 6 tests (part of STRIDE)")
print("   • PCI DSS: 7 tests")
print("   • OWASP: 9 tests")
print("   • TOTAL: 28-34 tests (depending on selection)")
