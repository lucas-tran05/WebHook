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
from typing import List, Dict
from ..config import ScannerSettings
from .test_a01_access_control import test_access_control
from .test_a02_crypto import test_encryption_transit
from .test_a03_injection import test_injection_basics
from .test_a04_error_handling import test_error_handling
from .test_a05_security_headers import test_security_headers
from .test_a07_authentication import test_weak_authentication
from .test_a08_integrity import test_integrity_checks
from .test_a09_logging import test_logging_monitoring
from .test_a10_ssrf import test_ssrf_protection


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
    
    # A03: Injection (covered in STRIDE injection_tests, quick check here)
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
