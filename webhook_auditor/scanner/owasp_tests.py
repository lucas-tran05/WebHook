"""OWASP (Open Web Application Security Project) Top 10 tests for webhooks.

OWASP Top 10 (2021):
1. Broken Access Control
2. Cryptographic Failures
3. Injection
4. Insecure Design
5. Security Misconfiguration
6. Vulnerable and Outdated Components
7. Identification and Authentication Failures
8. Software and Data Integrity Failures
9. Security Logging and Monitoring Failures
10. Server-Side Request Forgery (SSRF)
"""
import httpx
import json
from typing import List, Dict
from webhook_auditor.utils.crypto import calculate_hmac_signature
from webhook_auditor.scanner.config import ScannerSettings


async def run_owasp_tests(config: ScannerSettings) -> List[Dict]:
    """
    Run OWASP Top 10 compliance tests.
    
    Args:
        config: Scanner configuration settings
        
    Returns:
        List of test results
    """
    results = []
    
    # A01: Broken Access Control
    results.append(await test_access_control(config))
    
    # A02: Cryptographic Failures
    results.append(await test_encryption_transit(config))
    
    # A03: Injection (covered in injection_tests.py, quick check here)
    results.append(await test_injection_basics(config))
    
    # A05: Security Misconfiguration
    results.append(await test_security_headers(config))
    results.append(await test_error_handling(config))
    
    # A07: Identification and Authentication Failures
    results.append(await test_weak_authentication(config))
    
    # A08: Software and Data Integrity Failures
    results.append(await test_integrity_checks(config))
    
    # A09: Security Logging Failures
    results.append(await test_logging_monitoring(config))
    
    # A10: SSRF
    results.append(await test_ssrf_protection(config))
    
    return results


async def test_access_control(config: ScannerSettings) -> Dict:
    """
    Test for broken access control (OWASP A01).
    """
    try:
        headers = config.custom_headers.copy() if config.custom_headers else {}
        
        # Test 1: Access without authentication
        async with httpx.AsyncClient(verify=False) as client:
            response_no_auth = await client.request(
                config.http_method,
                config.target_url,
                json=json.loads(config.sample_valid_payload),
                headers={},  # No authentication
                timeout=10.0
            )
            
            # Test 2: Access with invalid authentication
            invalid_headers = headers.copy()
            if config.shared_secret:
                invalid_headers[config.signature_header_name] = "invalid_signature"
            
            response_invalid = await client.request(
                config.http_method,
                config.target_url,
                json=json.loads(config.sample_valid_payload),
                headers=invalid_headers,
                timeout=10.0
            )
            
            # Check if unauthorized access is rejected
            if response_no_auth.status_code == 200 or response_invalid.status_code == 200:
                return {
                    "category": "OWASP - A01 Broken Access Control",
                    "name": "Access Control Enforcement",
                    "status": "FAIL",
                    "details": "Webhook accepts requests without proper authentication/authorization.",
                    "risk": "Unauthorized users can trigger webhook actions, potentially causing data breaches or system compromise.",
                    "mitigation": "Implement proper authentication (HMAC signatures, API keys) and reject unauthenticated requests with 401/403 status codes."
                }
            else:
                return {
                    "category": "OWASP - A01 Broken Access Control",
                    "name": "Access Control Enforcement",
                    "status": "PASS",
                    "details": "Webhook properly rejects unauthenticated/unauthorized requests.",
                    "risk": None,
                    "mitigation": None
                }
    except Exception as e:
        return {
            "category": "OWASP - A01 Broken Access Control",
            "name": "Access Control Enforcement",
            "status": "WARN",
            "details": f"Error testing access control: {str(e)}",
            "risk": "Unable to verify access control implementation.",
            "mitigation": "Ensure proper authentication and authorization checks are in place."
        }


async def test_encryption_transit(config: ScannerSettings) -> Dict:
    """
    Test for cryptographic failures in transit (OWASP A02).
    """
    try:
        if not config.target_url.startswith("https://"):
            return {
                "category": "OWASP - A02 Cryptographic Failures",
                "name": "Encryption in Transit",
                "status": "FAIL",
                "details": "Webhook does not use HTTPS. Data transmitted in plaintext.",
                "risk": "Sensitive data can be intercepted by attackers through man-in-the-middle attacks.",
                "mitigation": "Enable HTTPS with TLS 1.2+ and redirect all HTTP traffic to HTTPS."
            }
        
        # Test if HTTP is also accessible (should not be)
        http_url = config.target_url.replace("https://", "http://")
        try:
            async with httpx.AsyncClient(verify=False) as client:
                response = await client.get(http_url, timeout=5.0, follow_redirects=False)
                
                if response.status_code in [301, 302, 307, 308]:
                    # HTTP redirects to HTTPS - good
                    return {
                        "category": "OWASP - A02 Cryptographic Failures",
                        "name": "Encryption in Transit",
                        "status": "PASS",
                        "details": "HTTPS enforced. HTTP requests are redirected to HTTPS.",
                        "risk": None,
                        "mitigation": None
                    }
                elif response.status_code == 200:
                    return {
                        "category": "OWASP - A02 Cryptographic Failures",
                        "name": "Encryption in Transit",
                        "status": "WARN",
                        "details": "HTTP endpoint is accessible without redirect to HTTPS.",
                        "risk": "Users might accidentally use unencrypted HTTP.",
                        "mitigation": "Configure server to redirect all HTTP traffic to HTTPS."
                    }
        except:
            pass
        
        return {
            "category": "OWASP - A02 Cryptographic Failures",
            "name": "Encryption in Transit",
            "status": "PASS",
            "details": "HTTPS endpoint used. HTTP endpoint not accessible.",
            "risk": None,
            "mitigation": None
        }
    except Exception as e:
        return {
            "category": "OWASP - A02 Cryptographic Failures",
            "name": "Encryption in Transit",
            "status": "WARN",
            "details": f"Error testing encryption: {str(e)}",
            "risk": "Unable to verify encryption configuration.",
            "mitigation": "Ensure HTTPS with TLS 1.2+ is properly configured."
        }


async def test_injection_basics(config: ScannerSettings) -> Dict:
    """
    Basic injection test (OWASP A03).
    Detailed tests in injection_tests.py
    """
    try:
        malicious_payloads = [
            {"event": "<script>alert('xss')</script>", "data": "test"},
            {"event": "'; DROP TABLE users; --", "data": "test"},
            {"event": "test", "command": "cat /etc/passwd"}
        ]
        
        headers = config.custom_headers.copy() if config.custom_headers else {}
        if config.shared_secret:
            headers[config.signature_header_name] = "dummy_for_test"
        
        vulnerable = False
        async with httpx.AsyncClient(verify=False) as client:
            for payload in malicious_payloads:
                try:
                    response = await client.request(
                        config.http_method,
                        config.target_url,
                        json=payload,
                        headers=headers,
                        timeout=10.0
                    )
                    
                    # Check if malicious content is reflected
                    if "<script>" in response.text or "DROP TABLE" in response.text:
                        vulnerable = True
                        break
                except:
                    pass
        
        if vulnerable:
            return {
                "category": "OWASP - A03 Injection",
                "name": "Basic Injection Protection",
                "status": "FAIL",
                "details": "Endpoint may be vulnerable to injection attacks. Malicious input reflected in response.",
                "risk": "Attackers can execute arbitrary code, access databases, or steal data.",
                "mitigation": "Implement input validation, output encoding, and use parameterized queries."
            }
        else:
            return {
                "category": "OWASP - A03 Injection",
                "name": "Basic Injection Protection",
                "status": "PASS",
                "details": "No obvious injection vulnerabilities in basic tests. See detailed injection tests for comprehensive coverage.",
                "risk": None,
                "mitigation": None
            }
    except Exception as e:
        return {
            "category": "OWASP - A03 Injection",
            "name": "Basic Injection Protection",
            "status": "WARN",
            "details": f"Error testing injection protection: {str(e)}",
            "risk": "Unable to verify injection protection.",
            "mitigation": "Review input validation and sanitization practices."
        }


async def test_security_headers(config: ScannerSettings) -> Dict:
    """
    Test for security misconfiguration - missing security headers (OWASP A05).
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
            
            required_headers = {
                "Strict-Transport-Security": "HSTS header",
                "X-Content-Type-Options": "nosniff protection",
                "X-Frame-Options": "clickjacking protection",
                "Content-Security-Policy": "CSP protection",
                "X-XSS-Protection": "XSS filter"
            }
            
            missing = []
            for header, description in required_headers.items():
                if header.lower() not in [h.lower() for h in response.headers.keys()]:
                    missing.append(f"{header} ({description})")
            
            if len(missing) >= 3:
                return {
                    "category": "OWASP - A05 Security Misconfiguration",
                    "name": "Security Headers Configuration",
                    "status": "FAIL",
                    "details": f"Multiple security headers missing: {'; '.join(missing[:3])}",
                    "risk": "Application vulnerable to various attacks due to missing security controls.",
                    "mitigation": "Add missing security headers to HTTP responses."
                }
            elif len(missing) > 0:
                return {
                    "category": "OWASP - A05 Security Misconfiguration",
                    "name": "Security Headers Configuration",
                    "status": "WARN",
                    "details": f"Some security headers missing: {'; '.join(missing)}",
                    "risk": "Reduced protection against certain attack vectors.",
                    "mitigation": "Add recommended security headers."
                }
            else:
                return {
                    "category": "OWASP - A05 Security Misconfiguration",
                    "name": "Security Headers Configuration",
                    "status": "PASS",
                    "details": "All recommended security headers are present.",
                    "risk": None,
                    "mitigation": None
                }
    except Exception as e:
        return {
            "category": "OWASP - A05 Security Misconfiguration",
            "name": "Security Headers Configuration",
            "status": "WARN",
            "details": f"Error checking security headers: {str(e)}",
            "risk": "Unable to verify security header configuration.",
            "mitigation": "Review and implement security headers."
        }


async def test_error_handling(config: ScannerSettings) -> Dict:
    """
    Test for security misconfiguration - verbose error messages (OWASP A05).
    """
    try:
        headers = config.custom_headers.copy() if config.custom_headers else {}
        
        # Send malformed request
        async with httpx.AsyncClient(verify=False) as client:
            response = await client.request(
                config.http_method,
                config.target_url,
                content="invalid json {{{",  # Malformed JSON
                headers={**headers, "Content-Type": "application/json"},
                timeout=10.0
            )
            
            response_lower = response.text.lower()
            
            # Check for verbose error information
            verbose_indicators = [
                "traceback", "stack trace", "exception",
                "line ", ".py:", ".js:", ".php:",
                "at ", "file ", "in function",
                "sql error", "database error"
            ]
            
            found_indicators = [ind for ind in verbose_indicators if ind in response_lower]
            
            if len(found_indicators) >= 2:
                return {
                    "category": "OWASP - A05 Security Misconfiguration",
                    "name": "Error Handling Configuration",
                    "status": "FAIL",
                    "details": "Verbose error messages expose internal application details.",
                    "risk": "Attackers can use error information to identify vulnerabilities and plan attacks.",
                    "mitigation": "Implement generic error messages for users. Log detailed errors server-side only."
                }
            elif len(found_indicators) > 0:
                return {
                    "category": "OWASP - A05 Security Misconfiguration",
                    "name": "Error Handling Configuration",
                    "status": "WARN",
                    "details": "Some technical details visible in error responses.",
                    "risk": "Minor information leakage could aid attackers.",
                    "mitigation": "Review error handling to minimize information disclosure."
                }
            else:
                return {
                    "category": "OWASP - A05 Security Misconfiguration",
                    "name": "Error Handling Configuration",
                    "status": "PASS",
                    "details": "Error messages do not expose sensitive technical information.",
                    "risk": None,
                    "mitigation": None
                }
    except Exception as e:
        return {
            "category": "OWASP - A05 Security Misconfiguration",
            "name": "Error Handling Configuration",
            "status": "WARN",
            "details": f"Error testing error handling: {str(e)}",
            "risk": "Unable to verify error handling configuration.",
            "mitigation": "Review error handling implementation."
        }


async def test_weak_authentication(config: ScannerSettings) -> Dict:
    """
    Test for weak authentication mechanisms (OWASP A07).
    """
    try:
        if not config.shared_secret and not config.custom_headers:
            return {
                "category": "OWASP - A07 Auth Failures",
                "name": "Authentication Mechanism Strength",
                "status": "FAIL",
                "details": "No authentication mechanism configured.",
                "risk": "Anyone can send requests to your webhook endpoint.",
                "mitigation": "Implement HMAC signature validation or API key authentication."
            }
        
        if config.shared_secret:
            if len(config.shared_secret) < 16:
                return {
                    "category": "OWASP - A07 Auth Failures",
                    "name": "Authentication Mechanism Strength",
                    "status": "FAIL",
                    "details": f"Shared secret is too weak ({len(config.shared_secret)} characters). Minimum 16 characters recommended.",
                    "risk": "Weak secrets can be brute-forced or guessed.",
                    "mitigation": "Use a cryptographically random secret of at least 32 characters."
                }
            elif len(config.shared_secret) < 32:
                return {
                    "category": "OWASP - A07 Auth Failures",
                    "name": "Authentication Mechanism Strength",
                    "status": "WARN",
                    "details": f"Shared secret length is moderate ({len(config.shared_secret)} characters). 32+ characters recommended.",
                    "risk": "Moderate secrets provide less security margin.",
                    "mitigation": "Consider using a 256-bit (32+ character) secret for maximum security."
                }
        
        return {
            "category": "OWASP - A07 Auth Failures",
            "name": "Authentication Mechanism Strength",
            "status": "PASS",
            "details": "Strong authentication mechanism configured.",
            "risk": None,
            "mitigation": None
        }
    except Exception as e:
        return {
            "category": "OWASP - A07 Auth Failures",
            "name": "Authentication Mechanism Strength",
            "status": "WARN",
            "details": f"Error evaluating authentication: {str(e)}",
            "risk": "Unable to verify authentication strength.",
            "mitigation": "Review authentication implementation."
        }


async def test_integrity_checks(config: ScannerSettings) -> Dict:
    """
    Test for data integrity verification (OWASP A08).
    """
    try:
        if not config.shared_secret:
            return {
                "category": "OWASP - A08 Integrity Failures",
                "name": "Data Integrity Verification",
                "status": "FAIL",
                "details": "No signature verification mechanism configured.",
                "risk": "Webhook data can be tampered with in transit without detection.",
                "mitigation": "Implement HMAC signature verification to ensure data integrity."
            }
        
        headers = config.custom_headers.copy() if config.custom_headers else {}
        
        # Test with tampered payload
        payload = json.loads(config.sample_valid_payload)
        valid_signature = calculate_hmac_signature(config.shared_secret, json.dumps(payload))
        headers[config.signature_header_name] = f"{config.signature_prefix}{valid_signature}"
        
        # Modify payload after signature
        payload["tampered"] = "data"
        
        async with httpx.AsyncClient(verify=False) as client:
            response = await client.request(
                config.http_method,
                config.target_url,
                json=payload,
                headers=headers,
                timeout=10.0
            )
            
            # Endpoint should reject tampered data
            if response.status_code == 200:
                return {
                    "category": "OWASP - A08 Integrity Failures",
                    "name": "Data Integrity Verification",
                    "status": "FAIL",
                    "details": "Endpoint accepts tampered data. Signature validation not working properly.",
                    "risk": "Attackers can modify webhook payloads without detection.",
                    "mitigation": "Properly implement signature verification and reject requests with invalid signatures."
                }
            else:
                return {
                    "category": "OWASP - A08 Integrity Failures",
                    "name": "Data Integrity Verification",
                    "status": "PASS",
                    "details": "Endpoint rejects tampered data. Signature verification working correctly.",
                    "risk": None,
                    "mitigation": None
                }
    except Exception as e:
        return {
            "category": "OWASP - A08 Integrity Failures",
            "name": "Data Integrity Verification",
            "status": "WARN",
            "details": f"Error testing integrity checks: {str(e)}",
            "risk": "Unable to verify integrity protection.",
            "mitigation": "Ensure proper signature verification is implemented."
        }


async def test_logging_monitoring(config: ScannerSettings) -> Dict:
    """
    Test for security logging and monitoring (OWASP A09).
    """
    try:
        headers = config.custom_headers.copy() if config.custom_headers else {}
        
        if config.shared_secret:
            signature = calculate_hmac_signature(config.shared_secret, config.sample_valid_payload)
            headers[config.signature_header_name] = f"{config.signature_prefix}{signature}"
        
        async with httpx.AsyncClient(verify=False) as client:
            response = await client.request(
                config.http_method,
                config.target_url,
                json=json.loads(config.sample_valid_payload),
                headers=headers,
                timeout=10.0
            )
            
            # Check for logging/monitoring indicators
            tracking_headers = [
                "x-request-id", "x-correlation-id", "x-trace-id",
                "x-amzn-requestid", "cf-ray", "x-cloud-trace-context"
            ]
            
            has_tracking = any(h.lower() in [k.lower() for k in response.headers.keys()] for h in tracking_headers)
            
            if has_tracking:
                return {
                    "category": "OWASP - A09 Logging Failures",
                    "name": "Security Logging and Monitoring",
                    "status": "PASS",
                    "details": "Request tracking headers present. Endpoint implements logging/monitoring.",
                    "risk": None,
                    "mitigation": None
                }
            else:
                return {
                    "category": "OWASP - A09 Logging Failures",
                    "name": "Security Logging and Monitoring",
                    "status": "WARN",
                    "details": "No request tracking headers detected. Cannot verify logging implementation.",
                    "risk": "Insufficient logging may prevent detection of security incidents.",
                    "mitigation": "Implement comprehensive logging with request IDs, timestamps, IP addresses, and security events."
                }
    except Exception as e:
        return {
            "category": "OWASP - A09 Logging Failures",
            "name": "Security Logging and Monitoring",
            "status": "WARN",
            "details": f"Error checking logging capability: {str(e)}",
            "risk": "Unable to verify logging implementation.",
            "mitigation": "Ensure security events are properly logged and monitored."
        }


async def test_ssrf_protection(config: ScannerSettings) -> Dict:
    """
    Test for Server-Side Request Forgery protection (OWASP A10).
    """
    try:
        # SSRF payloads targeting internal resources
        ssrf_payloads = [
            {"url": "http://169.254.169.254/latest/meta-data/"},  # AWS metadata
            {"callback_url": "http://localhost:22"},  # Internal SSH
            {"webhook": "http://127.0.0.1:6379"},  # Internal Redis
            {"redirect": "file:///etc/passwd"}  # Local file
        ]
        
        headers = config.custom_headers.copy() if config.custom_headers else {}
        if config.shared_secret:
            headers[config.signature_header_name] = "dummy_for_test"
        
        vulnerable = False
        async with httpx.AsyncClient(verify=False) as client:
            for payload in ssrf_payloads:
                try:
                    response = await client.request(
                        config.http_method,
                        config.target_url,
                        json=payload,
                        headers=headers,
                        timeout=10.0
                    )
                    
                    # Check if SSRF attempt succeeded (look for metadata or internal content)
                    response_lower = response.text.lower()
                    if any(indicator in response_lower for indicator in ["ami-id", "instance-id", "redis", "ssh", "root:"]):
                        vulnerable = True
                        break
                except:
                    pass
        
        if vulnerable:
            return {
                "category": "OWASP - A10 SSRF",
                "name": "Server-Side Request Forgery Protection",
                "status": "FAIL",
                "details": "Endpoint may be vulnerable to SSRF attacks. Internal resources accessible.",
                "risk": "Attackers can access internal services, cloud metadata, or local files.",
                "mitigation": "Validate and sanitize all URLs. Block access to internal IP ranges and cloud metadata endpoints."
            }
        else:
            return {
                "category": "OWASP - A10 SSRF",
                "name": "Server-Side Request Forgery Protection",
                "status": "PASS",
                "details": "No obvious SSRF vulnerabilities detected in basic tests.",
                "risk": None,
                "mitigation": None
            }
    except Exception as e:
        return {
            "category": "OWASP - A10 SSRF",
            "name": "Server-Side Request Forgery Protection",
            "status": "WARN",
            "details": f"Error testing SSRF protection: {str(e)}",
            "risk": "Unable to verify SSRF protection.",
            "mitigation": "Implement URL validation and block internal/metadata endpoints."
        }
