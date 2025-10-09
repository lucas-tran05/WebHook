"""
Test the field-based schema injection generator.

This demonstrates how the scanner automatically generates
injection test payloads from a field schema.
"""
import asyncio
import json
from web_scanner import FieldSchema, generate_injection_payloads

def test_schema_based_generation():
    """Test automatic payload generation from schema."""
    
    print("=" * 70)
    print("🧪 Field-Based Schema Test - Auto Injection Payload Generation")
    print("=" * 70)
    
    # Define a realistic webhook schema
    schema = [
        FieldSchema(name="event", type="string", sample_value="user.created"),
        FieldSchema(name="user_id", type="integer", sample_value="12345"),
        FieldSchema(name="email", type="email", sample_value="test@example.com"),
    ]
    
    print("\n📋 Input Schema:")
    print("-" * 70)
    for field in schema:
        print(f"  • {field.name:15} → {field.type:10} → '{field.sample_value}'")
    
    # Generate injection payloads
    print("\n⚙️  Generating injection test payloads...")
    payloads = generate_injection_payloads(schema)
    
    print(f"\n✨ Generated {len(payloads)} test payloads!\n")
    
    # Group by attack type
    attack_types = {}
    for payload in payloads:
        attack_type = payload.name.split(" on ")[0] if " on " in payload.name else "Other"
        if attack_type not in attack_types:
            attack_types[attack_type] = []
        attack_types[attack_type].append(payload)
    
    print("📊 Breakdown by Attack Type:")
    print("-" * 70)
    for attack_type, payloads_list in sorted(attack_types.items()):
        print(f"  {attack_type:30} → {len(payloads_list):3} tests")
    
    # Show sample payloads
    print("\n🔍 Sample Generated Payloads:")
    print("-" * 70)
    
    # SQL Injection samples
    sql_samples = [p for p in payloads if "SQL Injection" in p.name][:3]
    if sql_samples:
        print("\n  1️⃣  SQL Injection Tests:")
        for i, payload in enumerate(sql_samples, 1):
            parsed = json.loads(payload.data)
            print(f"      Test #{i}: {payload.name}")
            print(f"      Payload: {json.dumps(parsed, indent=14)}")
            print()
    
    # XSS samples
    xss_samples = [p for p in payloads if "XSS" in p.name][:2]
    if xss_samples:
        print("  2️⃣  XSS (Cross-Site Scripting) Tests:")
        for i, payload in enumerate(xss_samples, 1):
            parsed = json.loads(payload.data)
            print(f"      Test #{i}: {payload.name}")
            print(f"      Payload: {json.dumps(parsed, indent=14)}")
            print()
    
    # Integer tests
    int_samples = [p for p in payloads if "Integer" in p.name or "Boundary" in p.name][:2]
    if int_samples:
        print("  3️⃣  Integer Boundary/Overflow Tests:")
        for i, payload in enumerate(int_samples, 1):
            parsed = json.loads(payload.data)
            print(f"      Test #{i}: {payload.name}")
            print(f"      Payload: {json.dumps(parsed, indent=14)}")
            print()
    
    # Type confusion
    type_samples = [p for p in payloads if "Type Confusion" in p.name][:2]
    if type_samples:
        print("  4️⃣  Type Confusion Tests:")
        for i, payload in enumerate(type_samples, 1):
            parsed = json.loads(payload.data)
            print(f"      Test #{i}: {payload.name}")
            print(f"      Payload: {json.dumps(parsed, indent=14)}")
            print()
    
    print("=" * 70)
    print("✅ Test Complete!")
    print(f"   Generated {len(payloads)} comprehensive injection tests")
    print(f"   Covering {len(attack_types)} different attack types")
    print(f"   Testing {len(schema)} fields with type-aware payloads")
    print("=" * 70)
    
    return payloads


def test_different_schemas():
    """Test with different schema configurations."""
    print("\n\n" + "=" * 70)
    print("🎯 Testing Different Schema Configurations")
    print("=" * 70)
    
    scenarios = [
        {
            "name": "Payment Webhook",
            "schema": [
                FieldSchema(name="transaction_id", type="string", sample_value="TXN123456"),
                FieldSchema(name="amount", type="float", sample_value="99.99"),
                FieldSchema(name="currency", type="string", sample_value="USD"),
                FieldSchema(name="customer_email", type="email", sample_value="customer@example.com"),
            ]
        },
        {
            "name": "API Callback",
            "schema": [
                FieldSchema(name="callback_url", type="url", sample_value="https://example.com/callback"),
                FieldSchema(name="status", type="string", sample_value="completed"),
                FieldSchema(name="retry_count", type="integer", sample_value="0"),
            ]
        },
        {
            "name": "Simple Event",
            "schema": [
                FieldSchema(name="event_name", type="string", sample_value="user.login"),
            ]
        }
    ]
    
    for scenario in scenarios:
        print(f"\n📦 Scenario: {scenario['name']}")
        print(f"   Fields: {len(scenario['schema'])}")
        
        payloads = generate_injection_payloads(scenario['schema'])
        print(f"   Generated: {len(payloads)} test payloads")
        
        # Count by attack type
        attack_counts = {}
        for payload in payloads:
            attack_type = payload.name.split(" on ")[0] if " on " in payload.name else "Other"
            attack_counts[attack_type] = attack_counts.get(attack_type, 0) + 1
        
        print(f"   Attack types: {', '.join(attack_counts.keys())}")
    
    print("\n" + "=" * 70)


if __name__ == "__main__":
    # Test 1: Main demo
    payloads = test_schema_based_generation()
    
    # Test 2: Different scenarios
    test_different_schemas()
    
    print("\n🎉 All tests completed successfully!")
    print(f"\n💡 Tip: The web interface at http://localhost:8080 uses this")
    print(f"   same logic to auto-generate injection tests from your schema!")
