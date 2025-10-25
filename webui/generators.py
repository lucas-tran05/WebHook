import json
from typing import List

from .models import FieldSchema, TestPayload


def generate_schema_based_tests(schema: List[FieldSchema], standards: List[str]) -> dict:
    """
    Generate security tests based on field schema and selected standards.

    Returns dict with:
    - payloads: List[TestPayload]
    - test_types: List[str]
    - base_payload: dict
    """
    result = {"payloads": [], "test_types": [], "base_payload": {}}

    base_payload = {}
    for field in schema:
        if field.type == "integer":
            try:
                base_payload[field.name] = int(field.sample_value) if field.sample_value else 0
            except Exception:
                base_payload[field.name] = 0
        elif field.type == "float":
            try:
                base_payload[field.name] = float(field.sample_value) if field.sample_value else 0.0
            except Exception:
                base_payload[field.name] = 0.0
        elif field.type == "boolean":
            base_payload[field.name] = (
                str(field.sample_value).lower() in ["true", "1", "yes"] if field.sample_value else False
            )
        else:
            base_payload[field.name] = field.sample_value if field.sample_value else ""

    result["base_payload"] = base_payload

    if not standards or len(standards) == 0:
        standards = ["STRIDE"]

    from webhook_auditor.scanner.injection_tests import INJECTION_PAYLOADS

    for standard in standards:
        if standard == "STRIDE":
            result["test_types"].append("STRIDE")

            # Spoofing
            result["payloads"].append(
                TestPayload(name="[STRIDE-Spoofing] Request without signature header", data=json.dumps({"__test_type__": "no_signature", **base_payload}))
            )
            result["payloads"].append(
                TestPayload(name="[STRIDE-Spoofing] Request with invalid signature", data=json.dumps({"__test_type__": "invalid_signature", **base_payload}))
            )
            result["payloads"].append(
                TestPayload(name="[STRIDE-Spoofing] Request with empty signature", data=json.dumps({"__test_type__": "empty_signature", **base_payload}))
            )

            # Tampering
            tampered_payload = base_payload.copy()
            for field in schema:
                if field.type == "string":
                    tampered_payload[field.name] = str(tampered_payload.get(field.name, "")) + "_MODIFIED"
                    break
            result["payloads"].append(
                TestPayload(name="[STRIDE-Tampering] Modified payload integrity check", data=json.dumps(tampered_payload))
            )
            result["payloads"].append(
                TestPayload(name="[STRIDE-Tampering] HTTPS/TLS 1.2+ enforcement check", data=json.dumps({"__check_https__": True, **base_payload}))
            )

            # Repudiation
            result["payloads"].append(
                TestPayload(name="[STRIDE-Repudiation] Request without timestamp header", data=json.dumps({"__test_type__": "no_timestamp", **base_payload}))
            )
            result["payloads"].append(
                TestPayload(name="[STRIDE-Repudiation] Logging mechanism check", data=json.dumps(base_payload))
            )
            old_timestamp_payload = base_payload.copy()
            old_timestamp_payload["timestamp"] = "2020-01-01T00:00:00Z"
            result["payloads"].append(
                TestPayload(name="[STRIDE-Repudiation] Replay attack with old timestamp", data=json.dumps(old_timestamp_payload))
            )

            # Information Disclosure
            sensitive_payload = base_payload.copy()
            sensitive_payload.update({"api_key": "sk_test_51234567890", "password": "Password123!", "secret_token": "ghp_1234567890abcdef"})
            result["payloads"].append(
                TestPayload(name="[STRIDE-InfoDisclosure] Sensitive data in payload", data=json.dumps(sensitive_payload))
            )
            result["payloads"].append(
                TestPayload(name="[STRIDE-InfoDisclosure] Error message information leakage", data=json.dumps({"invalid": "data", "__trigger_error__": True}))
            )
            result["payloads"].append(
                TestPayload(name="[STRIDE-InfoDisclosure] Verbose headers check", data=json.dumps({"__check_headers__": True, **base_payload}))
            )

            # DoS
            result["payloads"].append(
                TestPayload(name="[STRIDE-DoS] Rate limiting check", data=json.dumps({"__rate_limit_test__": True, **base_payload}))
            )
            large_payload = base_payload.copy()
            large_payload["large_field"] = "A" * (15 * 1024 * 1024)
            result["payloads"].append(
                TestPayload(name="[STRIDE-DoS] Large payload rejection (>10MB)", data=json.dumps(large_payload))
            )
            result["payloads"].append(
                TestPayload(name="[STRIDE-DoS] Async processing timeout", data=json.dumps({"__check_timeout__": True, **base_payload}))
            )

            # Elevation of Privilege
            for field in schema:
                if field.type in ["string", "email", "url"]:
                    for i, sql_payload in enumerate(INJECTION_PAYLOADS.get("sql", [])[:2]):
                        test_data = base_payload.copy()
                        test_data[field.name] = sql_payload
                        result["payloads"].append(
                            TestPayload(name=f"[STRIDE-Privilege] SQL Injection on '{field.name}' #{i+1}", data=json.dumps(test_data))
                        )
            for field in schema:
                if field.type == "string":
                    for i, cmd_payload in enumerate(INJECTION_PAYLOADS.get("command", [])[:2]):
                        test_data = base_payload.copy()
                        test_data[field.name] = cmd_payload
                        result["payloads"].append(
                            TestPayload(name=f"[STRIDE-Privilege] Command Injection on '{field.name}' #{i+1}", data=json.dumps(test_data))
                        )
            for field in schema:
                if any(keyword in field.name.lower() for keyword in ["role", "permission", "admin", "privilege"]):
                    for value in ["admin", "superuser", "root"]:
                        test_data = base_payload.copy()
                        test_data[field.name] = value
                        result["payloads"].append(
                            TestPayload(name=f"[STRIDE-Privilege] Privilege escalation via '{field.name}' = {value}", data=json.dumps(test_data))
                        )

        elif standard in ["PCI-DSS", "PCI DSS"]:
            result["test_types"].append("PCI-DSS")

            card_numbers = ["4111111111111111", "5500000000000004", "378282246310005"]
            for field in schema:
                if field.type in ["string", "integer"]:
                    for i, card_number in enumerate(card_numbers):
                        test_data = base_payload.copy()
                        test_data[field.name] = card_number
                        result["payloads"].append(
                            TestPayload(name=f"[PCI-DSS-CHD] Credit card in '{field.name}' #{i+1}", data=json.dumps(test_data))
                        )

            test_data = base_payload.copy()
            test_data.update({"cvv": "123", "cvc": "456", "security_code": "789"})
            result["payloads"].append(
                TestPayload(name="[PCI-DSS-CHD] CVV/CVC in payload", data=json.dumps(test_data))
            )

            result["payloads"].append(
                TestPayload(name="[PCI-DSS-CHD] Tokenization check", data=json.dumps({"card_token": "tok_visa_4111", **base_payload}))
            )

            for field in schema:
                if field.type in ["string", "email", "url"]:
                    for i, sql_payload in enumerate(INJECTION_PAYLOADS.get("sql", [])[:2]):
                        test_data = base_payload.copy()
                        test_data[field.name] = sql_payload
                        result["payloads"].append(
                            TestPayload(name=f"[PCI-DSS-6.5.1] SQL Injection on '{field.name}' #{i+1}", data=json.dumps(test_data))
                        )

            for field in schema:
                if field.type in ["string", "email"]:
                    for i, xss_payload in enumerate(INJECTION_PAYLOADS.get("xss", [])[:2]):
                        test_data = base_payload.copy()
                        test_data[field.name] = xss_payload
                        result["payloads"].append(
                            TestPayload(name=f"[PCI-DSS-6.5.7] XSS on '{field.name}' #{i+1}", data=json.dumps(test_data))
                        )

            large_payload = base_payload.copy()
            large_payload["buffer_overflow_test"] = "A" * (100 * 1024 * 1024)
            result["payloads"].append(
                TestPayload(name="[PCI-DSS-6.5.8] Buffer overflow protection", data=json.dumps(large_payload))
            )

            result["payloads"].append(
                TestPayload(name="[PCI-DSS-6.5.10] Empty authentication rejection", data=json.dumps({"__empty_auth__": True, **base_payload}))
            )

        elif standard == "OWASP":
            result["test_types"].append("OWASP")

            result["payloads"].append(
                TestPayload(name="[OWASP-A01] Cross-account data access", data=json.dumps({"user_id": "OTHER_USER_12345", "account_id": "VICTIM_789", **base_payload}))
            )

            for field in schema:
                if any(keyword in field.name.lower() for keyword in ["role", "permission", "admin"]):
                    test_data = base_payload.copy()
                    test_data[field.name] = "admin"
                    result["payloads"].append(
                        TestPayload(name=f"[OWASP-A01] Privilege escalation via '{field.name}'", data=json.dumps(test_data))
                    )

            for field in schema:
                if field.type in ["string", "email", "url"]:
                    for i, sql_payload in enumerate(INJECTION_PAYLOADS.get("sql", [])[:2]):
                        test_data = base_payload.copy()
                        test_data[field.name] = sql_payload
                        result["payloads"].append(
                            TestPayload(name=f"[OWASP-A03] SQL Injection on '{field.name}' #{i+1}", data=json.dumps(test_data))
                        )
                    nosql_payloads = ['{"$ne": null}', '{"$gt": ""}']
                    for i, nosql_payload in enumerate(nosql_payloads):
                        test_data = base_payload.copy()
                        test_data[field.name] = nosql_payload
                        result["payloads"].append(
                            TestPayload(name=f"[OWASP-A03] NoSQL Injection on '{field.name}' #{i+1}", data=json.dumps(test_data))
                        )

            for field in schema:
                if field.type == "string":
                    for i, cmd_payload in enumerate(INJECTION_PAYLOADS.get("command", [])[:1]):
                        test_data = base_payload.copy()
                        test_data[field.name] = cmd_payload
                        result["payloads"].append(
                            TestPayload(name=f"[OWASP-A03] Command Injection on '{field.name}' #{i+1}", data=json.dumps(test_data))
                        )

            for field in schema:
                if any(keyword in field.name.lower() for keyword in ["file", "path", "filename", "dir"]):
                    path_payloads = ["../../../etc/passwd", "..\\..\\..\\windows\\system32\\config\\sam"]
                    for i, path_payload in enumerate(path_payloads):
                        test_data = base_payload.copy()
                        test_data[field.name] = path_payload
                        result["payloads"].append(
                            TestPayload(name=f"[OWASP-A05] Path Traversal on '{field.name}' #{i+1}", data=json.dumps(test_data))
                        )

            for field in schema:
                if field.type in ["string", "email"]:
                    for i, xss_payload in enumerate(INJECTION_PAYLOADS.get("xss", [])[:2]):
                        test_data = base_payload.copy()
                        test_data[field.name] = xss_payload
                        result["payloads"].append(
                            TestPayload(name=f"[OWASP-A07] XSS on '{field.name}' #{i+1}", data=json.dumps(test_data))
                        )

            internal_ips = [
                "http://localhost/admin",
                "http://127.0.0.1/admin",
                "http://10.0.0.1/internal",
                "http://192.168.1.1/admin",
                "http://169.254.169.254/latest/meta-data/",
            ]

            for field in schema:
                if field.type in ["url", "string"] and any(
                    keyword in field.name.lower() for keyword in ["url", "webhook", "callback", "link"]
                ):
                    for i, internal_ip in enumerate(internal_ips):
                        test_data = base_payload.copy()
                        test_data[field.name] = internal_ip
                        result["payloads"].append(
                            TestPayload(name=f"[OWASP-A10] SSRF on '{field.name}' - Internal IP #{i+1}", data=json.dumps(test_data))
                        )

    return result


def generate_injection_payloads(schema: List[FieldSchema]) -> List[TestPayload]:
    """Generate injection test payloads based on field schema."""
    from webhook_auditor.scanner.injection_tests import INJECTION_PAYLOADS

    test_payloads: List[TestPayload] = []

    base_payload = {}
    for field in schema:
        if field.sample_value:
            if field.type == "integer":
                try:
                    base_payload[field.name] = int(field.sample_value)
                except Exception:
                    base_payload[field.name] = 0
            elif field.type == "float":
                try:
                    base_payload[field.name] = float(field.sample_value)
                except Exception:
                    base_payload[field.name] = 0.0
            elif field.type == "boolean":
                base_payload[field.name] = field.sample_value.lower() in ["true", "1", "yes"]
            else:
                base_payload[field.name] = field.sample_value
        else:
            base_payload[field.name] = None

    for field in schema:
        field_name = field.name
        field_type = field.type

        if field_type in ["string", "integer", "email", "url"]:
            for i, sql_payload in enumerate(INJECTION_PAYLOADS.get("sql", [])[:3]):
                test_data = base_payload.copy()
                test_data[field_name] = sql_payload
                test_payloads.append(TestPayload(name=f"SQL Injection on '{field_name}' #{i+1}", data=json.dumps(test_data)))

        if field_type in ["string", "email", "url"]:
            for i, xss_payload in enumerate(INJECTION_PAYLOADS.get("xss", [])[:3]):
                test_data = base_payload.copy()
                test_data[field_name] = xss_payload
                test_payloads.append(TestPayload(name=f"XSS Injection on '{field_name}' #{i+1}", data=json.dumps(test_data)))

        if field_type == "string":
            for i, cmd_payload in enumerate(INJECTION_PAYLOADS.get("command", [])[:2]):
                test_data = base_payload.copy()
                test_data[field_name] = cmd_payload
                test_payloads.append(TestPayload(name=f"Command Injection on '{field_name}' #{i+1}", data=json.dumps(test_data)))

        if field_type == "string":
            for i, path_payload in enumerate(INJECTION_PAYLOADS.get("path_traversal", [])[:2]):
                test_data = base_payload.copy()
                test_data[field_name] = path_payload
                test_payloads.append(TestPayload(name=f"Path Traversal on '{field_name}' #{i+1}", data=json.dumps(test_data)))

        if field_type == "string":
            for i, nosql_payload in enumerate(INJECTION_PAYLOADS.get("nosql", [])[:2]):
                test_data = base_payload.copy()
                test_data[field_name] = nosql_payload
                test_payloads.append(TestPayload(name=f"NoSQL Injection on '{field_name}' #{i+1}", data=json.dumps(test_data)))

        if field_type in ["integer", "float"]:
            overflow_values = [-2147483648, 2147483647, -1, 0]
            for i, val in enumerate(overflow_values[:4]):
                test_data = base_payload.copy()
                test_data[field_name] = val
                test_payloads.append(TestPayload(name=f"Integer Boundary Test on '{field_name}' #{i+1}", data=json.dumps(test_data)))

        type_confusion_values = [None, "", "null"]
        for i, val in enumerate(type_confusion_values[:3]):
            test_data = base_payload.copy()
            test_data[field_name] = val
            test_payloads.append(TestPayload(name=f"Type Confusion on '{field_name}' #{i+1}", data=json.dumps(test_data)))

    return test_payloads
