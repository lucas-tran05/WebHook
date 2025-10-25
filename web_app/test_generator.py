"""
Test Payload Generator

Generates security test payloads based on field schema and selected standards.
Supports STRIDE, OWASP Top 10, and PCI-DSS compliance testing.
"""
import json
from typing import List, Dict
from .models import FieldSchema, TestPayload


def generate_schema_based_tests(schema: List[FieldSchema], standards: List[str]) -> dict:
    """
    Generate security tests based on field schema and selected standards.
    Properly aligned with STRIDE threat model, OWASP Top 10, and PCI-DSS requirements.
    
    Returns dict with:
    - payloads: List of test payloads to send
    - test_types: Type of tests (STRIDE, OWASP, PCI-DSS)
    - base_payload: The base payload structure
    """
    result = {
        "payloads": [],
        "test_types": [],
        "base_payload": {}
    }
    
    # Build base payload from schema
    base_payload = {}
    for field in schema:
        if field.type == 'integer':
            try:
                base_payload[field.name] = int(field.sample_value) if field.sample_value else 0
            except:
                base_payload[field.name] = 0
        elif field.type == 'float':
            try:
                base_payload[field.name] = float(field.sample_value) if field.sample_value else 0.0
            except:
                base_payload[field.name] = 0.0
        elif field.type == 'boolean':
            base_payload[field.name] = str(field.sample_value).lower() in ['true', '1', 'yes'] if field.sample_value else False
        else:
            base_payload[field.name] = field.sample_value if field.sample_value else ""
    
    result["base_payload"] = base_payload
    
    # Generate tests based on selected standards
    if not standards or len(standards) == 0:
        standards = ["STRIDE"]  # Default
    
    from webhook_auditor.scanner.injection_tests import INJECTION_PAYLOADS
    
    for standard in standards:
        if standard == "STRIDE":
            result["test_types"].append("STRIDE")
            _generate_stride_tests(result, base_payload, schema)
        
        elif standard in ["PCI-DSS", "PCI DSS"]:
            result["test_types"].append("PCI-DSS")
            _generate_pci_dss_tests(result, base_payload, schema)
        
        elif standard == "OWASP":
            result["test_types"].append("OWASP")
            _generate_owasp_tests(result, base_payload, schema)
    
    return result


def _generate_stride_tests(result: dict, base_payload: dict, schema: List[FieldSchema]):
    """Generate STRIDE threat model tests."""
    # 1. SPOOFING (Authentication)
    result["payloads"].append(TestPayload(
        name="[STRIDE-Spoofing] Request without signature header",
        data=json.dumps({"__test_type__": "no_signature", **base_payload})
    ))
    
    result["payloads"].append(TestPayload(
        name="[STRIDE-Spoofing] Request with invalid signature",
        data=json.dumps({"__test_type__": "invalid_signature", **base_payload})
    ))
    
    result["payloads"].append(TestPayload(
        name="[STRIDE-Spoofing] Request with empty signature",
        data=json.dumps({"__test_type__": "empty_signature", **base_payload})
    ))
    
    # 2. TAMPERING (Integrity)
    tampered_payload = base_payload.copy()
    for field in schema:
        if field.type == 'string':
            tampered_payload[field.name] = f"{field.sample_value}_TAMPERED"
            break
    result["payloads"].append(TestPayload(
        name="[STRIDE-Tampering] Modified payload integrity check",
        data=json.dumps(tampered_payload)
    ))
    
    result["payloads"].append(TestPayload(
        name="[STRIDE-Tampering] HTTPS/TLS 1.2+ enforcement check",
        data=json.dumps({"__check_https__": True, **base_payload})
    ))
    
    # 3. REPUDIATION (Logging & Audit Trail)
    result["payloads"].append(TestPayload(
        name="[STRIDE-Repudiation] Request without timestamp header",
        data=json.dumps({"__test_type__": "no_timestamp", **base_payload})
    ))
    
    result["payloads"].append(TestPayload(
        name="[STRIDE-Repudiation] Logging mechanism check",
        data=json.dumps(base_payload)
    ))
    
    old_timestamp_payload = base_payload.copy()
    old_timestamp_payload["timestamp"] = "2020-01-01T00:00:00Z"
    result["payloads"].append(TestPayload(
        name="[STRIDE-Repudiation] Replay attack with old timestamp",
        data=json.dumps(old_timestamp_payload)
    ))
    
    # 4. INFORMATION DISCLOSURE
    sensitive_payload = base_payload.copy()
    sensitive_payload.update({
        "api_key": "sk_test_51234567890",
        "password": "Password123!",
        "secret_token": "ghp_1234567890abcdef"
    })
    result["payloads"].append(TestPayload(
        name="[STRIDE-InfoDisclosure] Sensitive data in payload",
        data=json.dumps(sensitive_payload)
    ))
    
    result["payloads"].append(TestPayload(
        name="[STRIDE-InfoDisclosure] Error message information leakage",
        data=json.dumps({"invalid": "data", "__trigger_error__": True})
    ))
    
    result["payloads"].append(TestPayload(
        name="[STRIDE-InfoDisclosure] Verbose headers check",
        data=json.dumps({"__check_headers__": True, **base_payload})
    ))
    
    # 5. DENIAL OF SERVICE
    result["payloads"].append(TestPayload(
        name="[STRIDE-DoS] Rate limiting check",
        data=json.dumps({"__rate_limit_test__": True, **base_payload})
    ))
    
    large_payload = base_payload.copy()
    large_payload["large_field"] = "A" * (15 * 1024 * 1024)  # 15MB
    result["payloads"].append(TestPayload(
        name="[STRIDE-DoS] Large payload rejection (>10MB)",
        data=json.dumps(large_payload)
    ))
    
    result["payloads"].append(TestPayload(
        name="[STRIDE-DoS] Async processing timeout",
        data=json.dumps({"__check_timeout__": True, **base_payload})
    ))
    
    # 6. ELEVATION OF PRIVILEGE
    from webhook_auditor.scanner.injection_tests import INJECTION_PAYLOADS
    
    # SQL Injection on all string fields
    for field in schema:
        if field.type in ['string', 'email', 'url']:
            priv_payload = base_payload.copy()
            priv_payload[field.name] = INJECTION_PAYLOADS["sql"][0]
            result["payloads"].append(TestPayload(
                name=f"[STRIDE-Privilege] SQL Injection on '{field.name}'",
                data=json.dumps(priv_payload)
            ))
            break
    
    # Command Injection
    for field in schema:
        if field.type == 'string':
            cmd_payload = base_payload.copy()
            cmd_payload[field.name] = INJECTION_PAYLOADS["command"][0]
            result["payloads"].append(TestPayload(
                name=f"[STRIDE-Privilege] Command Injection on '{field.name}'",
                data=json.dumps(cmd_payload)
            ))
            break
    
    # Privilege escalation via role field
    for field in schema:
        if any(keyword in field.name.lower() for keyword in ['role', 'permission', 'admin', 'privilege']):
            role_payload = base_payload.copy()
            role_payload[field.name] = "admin"
            result["payloads"].append(TestPayload(
                name=f"[STRIDE-Privilege] Role escalation on '{field.name}'",
                data=json.dumps(role_payload)
            ))
            break


def _generate_pci_dss_tests(result: dict, base_payload: dict, schema: List[FieldSchema]):
    """Generate PCI-DSS compliance tests."""
    from webhook_auditor.scanner.injection_tests import INJECTION_PAYLOADS
    
    # CARDHOLDER DATA PROTECTION (CHD)
    card_numbers = ["4111111111111111", "5500000000000004", "378282246310005"]
    for field in schema:
        if field.type in ['string', 'integer']:
            for i, card in enumerate(card_numbers[:2]):
                chd_payload = base_payload.copy()
                chd_payload[field.name] = card
                result["payloads"].append(TestPayload(
                    name=f"[PCI-DSS-CHD] Card number in '{field.name}' #{i+1}",
                    data=json.dumps(chd_payload)
                ))
            break
    
    # CVV in payload
    test_data = base_payload.copy()
    test_data.update({"cvv": "123", "cvc": "456", "security_code": "789"})
    result["payloads"].append(TestPayload(
        name="[PCI-DSS-CHD] CVV/CVC in payload",
        data=json.dumps(test_data)
    ))
    
    # Tokenization check
    result["payloads"].append(TestPayload(
        name="[PCI-DSS-CHD] Tokenization check",
        data=json.dumps({"card_token": "tok_visa_4111", **base_payload})
    ))
    
    # Requirement 6.5.1: Injection Flaws
    for field in schema:
        if field.type in ['string', 'email', 'url']:
            inj_payload = base_payload.copy()
            inj_payload[field.name] = INJECTION_PAYLOADS["sql"][0]
            result["payloads"].append(TestPayload(
                name=f"[PCI-DSS-6.5.1] SQL Injection on '{field.name}'",
                data=json.dumps(inj_payload)
            ))
            break
    
    # Requirement 6.5.7: XSS
    for field in schema:
        if field.type in ['string', 'email']:
            xss_payload = base_payload.copy()
            xss_payload[field.name] = INJECTION_PAYLOADS["xss"][0]
            result["payloads"].append(TestPayload(
                name=f"[PCI-DSS-6.5.7] XSS on '{field.name}'",
                data=json.dumps(xss_payload)
            ))
            break
    
    # Requirement 6.5.8: Buffer overflow
    large_payload = base_payload.copy()
    large_payload["buffer_overflow_test"] = "A" * (100 * 1024 * 1024)  # 100MB
    result["payloads"].append(TestPayload(
        name="[PCI-DSS-6.5.8] Buffer overflow protection",
        data=json.dumps(large_payload)
    ))
    
    # Requirement 6.5.10: Authentication
    result["payloads"].append(TestPayload(
        name="[PCI-DSS-6.5.10] Empty authentication rejection",
        data=json.dumps({"__empty_auth__": True, **base_payload})
    ))


def _generate_owasp_tests(result: dict, base_payload: dict, schema: List[FieldSchema]):
    """Generate OWASP Top 10 tests."""
    from webhook_auditor.scanner.injection_tests import INJECTION_PAYLOADS
    
    # A01: Broken Access Control
    result["payloads"].append(TestPayload(
        name="[OWASP-A01] Cross-account data access",
        data=json.dumps({"user_id": "OTHER_USER_12345", "account_id": "VICTIM_789", **base_payload})
    ))
    
    for field in schema:
        if any(keyword in field.name.lower() for keyword in ['role', 'permission', 'admin']):
            access_payload = base_payload.copy()
            access_payload[field.name] = "administrator"
            result["payloads"].append(TestPayload(
                name=f"[OWASP-A01] Privilege escalation on '{field.name}'",
                data=json.dumps(access_payload)
            ))
            break
    
    # A03: Injection
    for field in schema:
        if field.type in ['string', 'email', 'url']:
            sql_payload = base_payload.copy()
            sql_payload[field.name] = INJECTION_PAYLOADS["sql"][0]
            result["payloads"].append(TestPayload(
                name=f"[OWASP-A03] SQL Injection on '{field.name}'",
                data=json.dumps(sql_payload)
            ))
            break
    
    # Command Injection
    for field in schema:
        if field.type == 'string':
            cmd_payload = base_payload.copy()
            cmd_payload[field.name] = INJECTION_PAYLOADS["command"][0]
            result["payloads"].append(TestPayload(
                name=f"[OWASP-A03] Command Injection on '{field.name}'",
                data=json.dumps(cmd_payload)
            ))
            break
    
    # A05: Security Misconfiguration - Path Traversal
    for field in schema:
        if any(keyword in field.name.lower() for keyword in ['file', 'path', 'filename', 'dir']):
            path_payload = base_payload.copy()
            path_payload[field.name] = INJECTION_PAYLOADS["path_traversal"][0]
            result["payloads"].append(TestPayload(
                name=f"[OWASP-A05] Path Traversal on '{field.name}'",
                data=json.dumps(path_payload)
            ))
            break
    
    # A07: XSS
    for field in schema:
        if field.type in ['string', 'email']:
            xss_payload = base_payload.copy()
            xss_payload[field.name] = INJECTION_PAYLOADS["xss"][0]
            result["payloads"].append(TestPayload(
                name=f"[OWASP-A07] XSS on '{field.name}'",
                data=json.dumps(xss_payload)
            ))
            break
    
    # A10: SSRF (Server-Side Request Forgery)
    internal_ips = [
        "http://localhost/admin",
        "http://127.0.0.1/admin",
        "http://10.0.0.1/internal",
        "http://192.168.1.1/admin",
        "http://169.254.169.254/latest/meta-data/"
    ]
    
    for field in schema:
        if field.type in ['url', 'string'] and any(keyword in field.name.lower() for keyword in ['url', 'webhook', 'callback', 'link']):
            for i, ip in enumerate(internal_ips[:2]):
                ssrf_payload = base_payload.copy()
                ssrf_payload[field.name] = ip
                result["payloads"].append(TestPayload(
                    name=f"[OWASP-A10] SSRF on '{field.name}' #{i+1}",
                    data=json.dumps(ssrf_payload)
                ))
            break


def generate_injection_payloads(schema: List[FieldSchema]) -> List[TestPayload]:
    """
    Generate injection test payloads based on field schema.
    
    For each field, generates targeted injection payloads based on its data type.
    """
    from webhook_auditor.scanner.injection_tests import INJECTION_PAYLOADS
    
    test_payloads = []
    
    # Build base payload from schema
    base_payload = {}
    for field in schema:
        if field.sample_value:
            if field.type == 'integer':
                try:
                    base_payload[field.name] = int(field.sample_value)
                except:
                    base_payload[field.name] = 0
            elif field.type == 'float':
                try:
                    base_payload[field.name] = float(field.sample_value)
                except:
                    base_payload[field.name] = 0.0
            elif field.type == 'boolean':
                base_payload[field.name] = field.sample_value.lower() in ['true', '1', 'yes']
            else:
                base_payload[field.name] = field.sample_value
        else:
            base_payload[field.name] = None
    
    # Generate injection tests for each field
    for field in schema:
        field_name = field.name
        field_type = field.type
        
        # SQL Injection tests for string/integer fields
        if field_type in ['string', 'integer', 'email', 'url']:
            for i, sql_payload in enumerate(INJECTION_PAYLOADS.get("sql", [])[:3]):  # Top 3 SQL injections
                test_data = base_payload.copy()
                test_data[field_name] = sql_payload
                test_payloads.append(TestPayload(
                    name=f"SQL Injection on '{field_name}' #{i+1}",
                    data=json.dumps(test_data)
                ))
        
        # XSS tests for string fields
        if field_type in ['string', 'email', 'url']:
            for i, xss_payload in enumerate(INJECTION_PAYLOADS.get("xss", [])[:3]):
                test_data = base_payload.copy()
                test_data[field_name] = xss_payload
                test_payloads.append(TestPayload(
                    name=f"XSS Injection on '{field_name}' #{i+1}",
                    data=json.dumps(test_data)
                ))
        
        # Command Injection for string fields
        if field_type == 'string':
            for i, cmd_payload in enumerate(INJECTION_PAYLOADS.get("command", [])[:2]):
                test_data = base_payload.copy()
                test_data[field_name] = cmd_payload
                test_payloads.append(TestPayload(
                    name=f"Command Injection on '{field_name}' #{i+1}",
                    data=json.dumps(test_data)
                ))
        
        # Path Traversal for string fields
        if field_type == 'string':
            for i, path_payload in enumerate(INJECTION_PAYLOADS.get("path_traversal", [])[:2]):
                test_data = base_payload.copy()
                test_data[field_name] = path_payload
                test_payloads.append(TestPayload(
                    name=f"Path Traversal on '{field_name}' #{i+1}",
                    data=json.dumps(test_data)
                ))
        
        # NoSQL Injection for string fields
        if field_type == 'string':
            for i, nosql_payload in enumerate(INJECTION_PAYLOADS.get("nosql", [])[:2]):
                test_data = base_payload.copy()
                test_data[field_name] = nosql_payload
                test_payloads.append(TestPayload(
                    name=f"NoSQL Injection on '{field_name}' #{i+1}",
                    data=json.dumps(test_data)
                ))
        
        # Integer overflow/underflow tests
        if field_type in ['integer', 'float']:
            overflow_values = [
                -2147483648,  # Min int32
                2147483647,   # Max int32
                -1,
                0,
                999999999999,
                "' OR '1'='1",  # SQL injection as number
            ]
            for i, val in enumerate(overflow_values[:4]):
                test_data = base_payload.copy()
                test_data[field_name] = val
                test_payloads.append(TestPayload(
                    name=f"Integer Overflow on '{field_name}' #{i+1}",
                    data=json.dumps(test_data)
                ))
        
        # Type confusion tests
        type_confusion_values = [
            None,
            "",
            "null",
            "undefined",
            [],
            {},
        ]
        for i, val in enumerate(type_confusion_values[:3]):
            test_data = base_payload.copy()
            test_data[field_name] = val
            test_payloads.append(TestPayload(
                name=f"Type Confusion on '{field_name}' #{i+1}",
                data=json.dumps(test_data)
            ))
    
    return test_payloads
