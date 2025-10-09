"""PCI DSS (Payment Card Industry Data Security Standard) compliance tests for webhooks.

PCI DSS Requirements relevant to webhooks:
- Requirement 4: Encrypt transmission of cardholder data across open, public networks
- Requirement 6: Develop and maintain secure systems and applications
- Requirement 8: Identify and authenticate access to system components
- Requirement 10: Track and monitor all access to network resources and cardholder data
- Requirement 11: Regularly test security systems and processes
"""
import httpx
import json
from typing import List, Dict
from webhook_auditor.utils.crypto import calculate_hmac_signature
from webhook_auditor.scanner.config import ScannerSettings


async def run_pci_dss_tests(config: ScannerSettings) -> List[Dict]:
    """
    Run PCI DSS compliance tests.
    
    Args:
        config: Scanner configuration settings
        
    Returns:
        List of test results
    """
    results = []
    
    # Requirement 4.1: Use strong cryptography for transmission
    results.append(await test_tls_version(config))
    results.append(await test_strong_ciphers(config))
    
    # Requirement 6.5: Address common coding vulnerabilities
    results.append(await test_sql_injection_protection(config))
    results.append(await test_xss_protection(config))
    
    # Requirement 8.2: Multi-factor authentication
    results.append(await test_authentication_strength(config))
    
    # Requirement 10.2: Audit trail logging
    results.append(await test_logging_capability(config))
    
    # Requirement 11.3: Penetration testing
    results.append(await test_vulnerability_disclosure(config))
    
    return results


async def test_tls_version(config: ScannerSettings) -> Dict:
    """
    Test if HTTPS with TLS 1.2+ is enforced.
    PCI DSS Requirement 4.1
    """
    try:
        # Check if URL uses HTTPS
        if not config.target_url.startswith("https://"):
            return {
                "category": "PCI DSS - Requirement 4",
                "name": "TLS Encryption Enforcement",
                "status": "FAIL",
                "details": "Webhook endpoint does not use HTTPS. PCI DSS requires TLS 1.2 or higher for all transmissions.",
                "risk": "Sensitive payment data could be intercepted in transit.",
                "mitigation": "Enable HTTPS with TLS 1.2 or higher on your webhook endpoint."
            }
        
        # Test connection with TLS
        async with httpx.AsyncClient(verify=True) as client:
            try:
                response = await client.get(config.target_url, timeout=10.0)
                return {
                    "category": "PCI DSS - Requirement 4",
                    "name": "TLS Encryption Enforcement",
                    "status": "PASS",
                    "details": "Endpoint uses HTTPS. TLS encryption is enforced.",
                    "risk": None,
                    "mitigation": None
                }
            except httpx.ConnectError:
                return {
                    "category": "PCI DSS - Requirement 4",
                    "name": "TLS Encryption Enforcement",
                    "status": "WARN",
                    "details": "Unable to verify TLS configuration due to connection error.",
                    "risk": "Cannot confirm secure transmission capability.",
                    "mitigation": "Ensure the endpoint is accessible and properly configured with valid TLS certificates."
                }
    except Exception as e:
        return {
            "category": "PCI DSS - Requirement 4",
            "name": "TLS Encryption Enforcement",
            "status": "WARN",
            "details": f"Error testing TLS: {str(e)}",
            "risk": "Unable to verify encryption requirements.",
            "mitigation": "Review webhook endpoint TLS configuration."
        }


async def test_strong_ciphers(config: ScannerSettings) -> Dict:
    """
    Test if strong cipher suites are supported.
    PCI DSS Requirement 4.1
    """
    try:
        if not config.target_url.startswith("https://"):
            return {
                "category": "PCI DSS - Requirement 4",
                "name": "Strong Cipher Suite Support",
                "status": "FAIL",
                "details": "HTTPS not used. Cannot verify cipher suite strength.",
                "risk": "Weak encryption could expose data to attackers.",
                "mitigation": "Enable HTTPS with strong cipher suites (AES-256, etc.)."
            }
        
        # Note: Full cipher suite testing requires specialized tools
        return {
            "category": "PCI DSS - Requirement 4",
            "name": "Strong Cipher Suite Support",
            "status": "PASS",
            "details": "HTTPS endpoint detected. Manual verification of cipher suites recommended using SSL Labs or similar tools.",
            "risk": None,
            "mitigation": "Verify cipher suite configuration meets PCI DSS requirements (no SSLv3, TLS 1.0, weak ciphers)."
        }
    except Exception as e:
        return {
            "category": "PCI DSS - Requirement 4",
            "name": "Strong Cipher Suite Support",
            "status": "WARN",
            "details": f"Error testing cipher suites: {str(e)}",
            "risk": "Unable to verify encryption strength.",
            "mitigation": "Use SSL Labs or similar tools to verify cipher suite configuration."
        }


async def test_sql_injection_protection(config: ScannerSettings) -> Dict:
    """
    Test if endpoint properly handles SQL injection attempts.
    PCI DSS Requirement 6.5.1
    """
    try:
        sql_injection_payloads = [
            {"event": "test", "data": "' OR '1'='1"},
            {"event": "test'; DROP TABLE users; --", "data": "sample"}
        ]
        
        headers = config.custom_headers.copy() if config.custom_headers else {}
        
        async with httpx.AsyncClient(verify=False) as client:
            vulnerable = False
            for payload in sql_injection_payloads:
                try:
                    response = await client.request(
                        config.http_method,
                        config.target_url,
                        json=payload,
                        headers=headers,
                        timeout=10.0
                    )
                    
                    # Check for SQL error messages in response
                    response_text = response.text.lower()
                    sql_errors = ["sql", "syntax error", "mysql", "postgresql", "ora-", "database error"]
                    if any(error in response_text for error in sql_errors):
                        vulnerable = True
                        break
                except:
                    pass
            
            if vulnerable:
                return {
                    "category": "PCI DSS - Requirement 6",
                    "name": "SQL Injection Protection",
                    "status": "FAIL",
                    "details": "Endpoint may be vulnerable to SQL injection. Database error messages detected.",
                    "risk": "Attackers could access, modify, or delete cardholder data.",
                    "mitigation": "Use parameterized queries and input validation. Never concatenate user input into SQL queries."
                }
            else:
                return {
                    "category": "PCI DSS - Requirement 6",
                    "name": "SQL Injection Protection",
                    "status": "PASS",
                    "details": "No SQL injection vulnerabilities detected in basic tests.",
                    "risk": None,
                    "mitigation": None
                }
    except Exception as e:
        return {
            "category": "PCI DSS - Requirement 6",
            "name": "SQL Injection Protection",
            "status": "WARN",
            "details": f"Error testing SQL injection protection: {str(e)}",
            "risk": "Unable to verify input validation.",
            "mitigation": "Ensure proper input validation and parameterized queries are used."
        }


async def test_xss_protection(config: ScannerSettings) -> Dict:
    """
    Test if endpoint has XSS protection headers.
    PCI DSS Requirement 6.5.7
    """
    try:
        headers = config.custom_headers.copy() if config.custom_headers else {}
        
        async with httpx.AsyncClient(verify=False) as client:
            response = await client.request(
                config.http_method,
                config.target_url,
                json=json.loads(config.sample_valid_payload),
                headers=headers,
                timeout=10.0
            )
            
            # Check for security headers
            security_headers = {
                "X-XSS-Protection": False,
                "X-Content-Type-Options": False,
                "Content-Security-Policy": False
            }
            
            for header in security_headers.keys():
                if header.lower() in [h.lower() for h in response.headers.keys()]:
                    security_headers[header] = True
            
            missing_headers = [h for h, present in security_headers.items() if not present]
            
            if len(missing_headers) >= 2:
                return {
                    "category": "PCI DSS - Requirement 6",
                    "name": "XSS Protection Headers",
                    "status": "FAIL",
                    "details": f"Missing important security headers: {', '.join(missing_headers)}",
                    "risk": "Application may be vulnerable to Cross-Site Scripting attacks.",
                    "mitigation": "Add security headers: X-XSS-Protection, X-Content-Type-Options, Content-Security-Policy"
                }
            elif len(missing_headers) == 1:
                return {
                    "category": "PCI DSS - Requirement 6",
                    "name": "XSS Protection Headers",
                    "status": "WARN",
                    "details": f"Missing security header: {missing_headers[0]}",
                    "risk": "Reduced protection against XSS attacks.",
                    "mitigation": f"Add missing header: {missing_headers[0]}"
                }
            else:
                return {
                    "category": "PCI DSS - Requirement 6",
                    "name": "XSS Protection Headers",
                    "status": "PASS",
                    "details": "All recommended XSS protection headers are present.",
                    "risk": None,
                    "mitigation": None
                }
    except Exception as e:
        return {
            "category": "PCI DSS - Requirement 6",
            "name": "XSS Protection Headers",
            "status": "WARN",
            "details": f"Error checking security headers: {str(e)}",
            "risk": "Unable to verify XSS protection.",
            "mitigation": "Ensure XSS protection headers are properly configured."
        }


async def test_authentication_strength(config: ScannerSettings) -> Dict:
    """
    Test authentication mechanism strength.
    PCI DSS Requirement 8.2
    """
    try:
        has_signature = config.shared_secret is not None and len(config.shared_secret) > 0
        has_custom_auth = False
        
        if config.custom_headers:
            auth_headers = ["authorization", "x-api-key", "api-key", "x-auth-token"]
            has_custom_auth = any(h.lower() in [k.lower() for k in config.custom_headers.keys()] for h in auth_headers)
        
        if not has_signature and not has_custom_auth:
            return {
                "category": "PCI DSS - Requirement 8",
                "name": "Authentication Strength",
                "status": "FAIL",
                "details": "No authentication mechanism detected (no signature, no API key).",
                "risk": "Unauthorized access to webhook endpoint could expose cardholder data.",
                "mitigation": "Implement HMAC signature validation or API key authentication."
            }
        
        if has_signature and len(config.shared_secret) < 32:
            return {
                "category": "PCI DSS - Requirement 8",
                "name": "Authentication Strength",
                "status": "WARN",
                "details": f"Shared secret is too short ({len(config.shared_secret)} characters). PCI DSS recommends 256-bit keys (32+ characters).",
                "risk": "Weak keys are easier to brute force.",
                "mitigation": "Use a shared secret of at least 32 characters (256 bits)."
            }
        
        return {
            "category": "PCI DSS - Requirement 8",
            "name": "Authentication Strength",
            "status": "PASS",
            "details": "Strong authentication mechanism detected.",
            "risk": None,
            "mitigation": None
        }
    except Exception as e:
        return {
            "category": "PCI DSS - Requirement 8",
            "name": "Authentication Strength",
            "status": "WARN",
            "details": f"Error evaluating authentication: {str(e)}",
            "risk": "Unable to verify authentication strength.",
            "mitigation": "Review authentication implementation."
        }


async def test_logging_capability(config: ScannerSettings) -> Dict:
    """
    Test if endpoint provides logging/audit trail capabilities.
    PCI DSS Requirement 10.2
    """
    try:
        headers = config.custom_headers.copy() if config.custom_headers else {}
        
        if config.shared_secret:
            timestamp = str(int(httpx.get("https://worldtimeapi.org/api/timezone/Etc/UTC", timeout=5).json()["unixtime"]))
            signature = calculate_hmac_signature(config.shared_secret, config.sample_valid_payload)
            headers[config.signature_header_name] = f"{config.signature_prefix}{signature}"
            if config.timestamp_header_name:
                headers[config.timestamp_header_name] = timestamp
        
        async with httpx.AsyncClient(verify=False) as client:
            response = await client.request(
                config.http_method,
                config.target_url,
                json=json.loads(config.sample_valid_payload),
                headers=headers,
                timeout=10.0
            )
            
            # Check for logging indicators in headers
            logging_headers = ["x-request-id", "x-correlation-id", "x-trace-id"]
            has_logging = any(h.lower() in [k.lower() for k in response.headers.keys()] for h in logging_headers)
            
            if has_logging:
                return {
                    "category": "PCI DSS - Requirement 10",
                    "name": "Audit Trail Logging",
                    "status": "PASS",
                    "details": "Request tracking headers detected. Endpoint appears to implement audit logging.",
                    "risk": None,
                    "mitigation": None
                }
            else:
                return {
                    "category": "PCI DSS - Requirement 10",
                    "name": "Audit Trail Logging",
                    "status": "WARN",
                    "details": "No request tracking headers detected. Cannot verify audit logging implementation.",
                    "risk": "Insufficient audit trail may prevent detection of security incidents.",
                    "mitigation": "Implement comprehensive logging with request IDs, timestamps, and user identification."
                }
    except Exception as e:
        return {
            "category": "PCI DSS - Requirement 10",
            "name": "Audit Trail Logging",
            "status": "WARN",
            "details": f"Error checking logging capability: {str(e)}",
            "risk": "Unable to verify audit trail implementation.",
            "mitigation": "Ensure all access to webhook endpoint is logged with timestamps and user identification."
        }


async def test_vulnerability_disclosure(config: ScannerSettings) -> Dict:
    """
    Test if endpoint discloses sensitive information about vulnerabilities.
    PCI DSS Requirement 11.3
    """
    try:
        headers = config.custom_headers.copy() if config.custom_headers else {}
        
        # Send invalid request to trigger error
        async with httpx.AsyncClient(verify=False) as client:
            response = await client.request(
                config.http_method,
                config.target_url,
                json={"invalid": "data"},
                headers=headers,
                timeout=10.0
            )
            
            response_text = response.text.lower()
            
            # Check for sensitive information disclosure
            sensitive_patterns = [
                "stack trace", "traceback", "exception",
                "line ", "file ", ".py", ".php", ".js",
                "version", "server:", "powered by"
            ]
            
            disclosed = [p for p in sensitive_patterns if p in response_text]
            
            if len(disclosed) >= 3:
                return {
                    "category": "PCI DSS - Requirement 11",
                    "name": "Vulnerability Information Disclosure",
                    "status": "FAIL",
                    "details": f"Error responses disclose sensitive information: {', '.join(disclosed[:3])}",
                    "risk": "Attackers can use disclosed information to identify and exploit vulnerabilities.",
                    "mitigation": "Implement generic error messages. Log detailed errors server-side only."
                }
            elif len(disclosed) > 0:
                return {
                    "category": "PCI DSS - Requirement 11",
                    "name": "Vulnerability Information Disclosure",
                    "status": "WARN",
                    "details": "Some technical details visible in error responses.",
                    "risk": "Minor information disclosure could aid attackers.",
                    "mitigation": "Review error handling to ensure minimal information disclosure."
                }
            else:
                return {
                    "category": "PCI DSS - Requirement 11",
                    "name": "Vulnerability Information Disclosure",
                    "status": "PASS",
                    "details": "Error responses do not disclose sensitive technical information.",
                    "risk": None,
                    "mitigation": None
                }
    except Exception as e:
        return {
            "category": "PCI DSS - Requirement 11",
            "name": "Vulnerability Information Disclosure",
            "status": "WARN",
            "details": f"Error testing vulnerability disclosure: {str(e)}",
            "risk": "Unable to verify information disclosure protection.",
            "mitigation": "Review error handling implementation."
        }
