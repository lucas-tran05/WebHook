"""PCI DSS (Payment Card Industry Data Security Standard) compliance tests for webhooks.

PCI DSS Requirements relevant to webhooks:
- Requirement 4: Encrypt transmission of cardholder data across open, public networks
- Requirement 6: Develop and maintain secure systems and applications
- Requirement 8: Identify and authenticate access to system components
- Requirement 10: Track and monitor all access to network resources and cardholder data
- Requirement 11: Regularly test security systems and processes
"""
from typing import List, Dict
from ..config import ScannerSettings
from .test_b01_tls import test_tls_version
from .test_b02_ciphers import test_strong_ciphers
from .test_b03_sqli import test_sql_injection_protection
from .test_b04_xss import test_xss_protection
from .test_b05_auth import test_authentication_strength
from .test_b06_logging import test_logging_capability
from .test_b07_vuln import test_vulnerability_disclosure


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
