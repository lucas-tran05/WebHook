"""
STRIDE Threat Model Security Tests

STRIDE is a threat modeling framework for identifying security vulnerabilities:
- S: Spoofing
- T: Tampering
- R: Repudiation
- I: Information Disclosure
- D: Denial of Service
- E: Elevation of Privilege

This module aggregates all STRIDE test functions.
"""

from typing import Dict, List
import httpx

# Import individual test modules
from .test_c01_spoofing_tampering import run_spoofing_tampering_tests
from .test_c02_repudiation import run_repudiation_tests
from .test_c03_info_disclosure import run_info_disclosure_tests
from .test_c04_dos import run_dos_tests
from .test_c05_privilege_escalation import run_privilege_escalation_tests
from .test_c06_injection import run_injection_tests


async def run_stride_tests(config, client: httpx.AsyncClient) -> List[Dict]:
    """
    Run all STRIDE security tests.
    
    Executes comprehensive security testing covering:
    - Spoofing & Tampering (signature validation)
    - Repudiation (replay attack prevention)
    - Information Disclosure (HTTPS, verbose headers, error messages)
    - Denial of Service (large payloads, rate limiting)
    - Elevation of Privilege (unauthorized fields, parameter pollution)
    - Injection Attacks (SQL, NoSQL, Command, XSS, Path Traversal, Template)
    
    Args:
        config: Scanner configuration object
        client: HTTP client for making requests
    
    Returns:
        List of all test result dictionaries
    """
    results = []
    
    # Run all STRIDE test categories
    results.extend(await run_spoofing_tampering_tests(config, client))
    results.extend(await run_repudiation_tests(config, client))
    results.extend(await run_info_disclosure_tests(config, client))
    results.extend(await run_dos_tests(config, client))
    results.extend(await run_privilege_escalation_tests(config, client))
    results.extend(await run_injection_tests(config, client))
    
    return results
