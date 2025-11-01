"""
Information Disclosure Tests for STRIDE Threat Model

Tests for HTTPS usage, verbose headers, and error message leaks.
"""

import re
from typing import Dict, List
import httpx
from ...utils.crypto import calculate_hmac_signature


def capture_response_data(response) -> dict:
    """
    Capture response data for later analysis.
    
    Args:
        response: HTTP response object
    
    Returns:
        Dictionary containing response details
    """
    try:
        return {
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "body": response.text[:10000],  # Limit to 10KB to avoid memory issues
            "elapsed_ms": response.elapsed.total_seconds() * 1000
        }
    except Exception as e:
        return {
            "status_code": getattr(response, 'status_code', None),
            "error": str(e)
        }


async def run_info_disclosure_tests(config, client: httpx.AsyncClient) -> List[Dict]:
    """
    Run tests for Information Disclosure threats.
    
    Tests for HTTPS usage, verbose headers, and detailed error messages.
    
    Args:
        config: Scanner configuration object
        client: HTTP client for making requests
    
    Returns:
        List of test result dictionaries
    """
    results = []
    payload_bytes = config.sample_valid_payload.encode('utf-8')
    
    # Check if shared secret is provided - some tests need it
    if not config.shared_secret:
        secret_bytes = None
    else:
        secret_bytes = config.shared_secret.encode('utf-8')
    
    # Test 1: HTTPS check
    if config.target_url.lower().startswith('https://'):
        results.append({
            "category": "STRIDE - C03 Information Disclosure",
            "name": "HTTPS Usage Check",
            "status": "PASS",
            "details": "Endpoint uses HTTPS for encrypted communication"
        })
    elif config.target_url.lower().startswith('http://'):
        results.append({
            "category": "STRIDE - C03 Information Disclosure",
            "name": "HTTPS Usage Check",
            "status": "FAIL",
            "details": "Endpoint uses unencrypted HTTP",
            "risk": "Webhook data transmitted in plaintext, vulnerable to eavesdropping and man-in-the-middle attacks",
            "mitigation": "Use HTTPS for all webhook endpoints to encrypt data in transit"
        })
    else:
        results.append({
            "category": "STRIDE - C03 Information Disclosure",
            "name": "HTTPS Usage Check",
            "status": "WARN",
            "details": "Could not determine protocol from URL"
        })
    
    # Test 2: Verbose server header
    if not secret_bytes:
        results.append({
            "category": "STRIDE - C03 Information Disclosure",
            "name": "Verbose Server Header & Error Messages",
            "status": "WARN",
            "details": "Skipped - No shared secret provided. These tests require HMAC signature validation."
        })
        return results
    
    try:
        valid_signature = calculate_hmac_signature(secret_bytes, payload_bytes, config.signature_prefix)
        headers = {
            "Content-Type": "application/json",
            config.signature_header_name: valid_signature
        }
        
        response = await client.request(
            config.http_method,
            config.target_url,
            content=payload_bytes,
            headers=headers,
            timeout=10.0
        )
        
        # Capture response for analysis
        response_data = capture_response_data(response)

        
        server_header = response.headers.get('Server', '')
        
        # Check for verbose server information (version numbers, OS details)
        verbose_patterns = [
            r'\d+\.\d+',  # Version numbers
            r'Ubuntu|Debian|CentOS|Windows|Linux',  # OS names
            r'Apache|nginx|IIS|Tomcat|Jetty',  # Server software with potential versions
        ]
        
        is_verbose = any(re.search(pattern, server_header, re.IGNORECASE) for pattern in verbose_patterns)
        
        if server_header and is_verbose:
            results.append({
                "category": "STRIDE - C03 Information Disclosure",
                "name": "Verbose Server Header",
                "status": "WARN",
                "details": f"Server header reveals detailed information: '{server_header}'",
                "risk": "Server version information can help attackers identify known vulnerabilities",
                "mitigation": "Configure server to return generic or minimal server header information"
            })
        else:
            results.append({
                "category": "STRIDE - C03 Information Disclosure",
                "name": "Verbose Server Header",
                "status": "PASS",
                "details": f"Server header does not reveal sensitive information ('{server_header}' or not present)"
            })
    except Exception as e:
        results.append({
            "category": "STRIDE - C03 Information Disclosure",
            "name": "Verbose Server Header",
            "status": "WARN",
            "details": f"Test failed with error: {str(e)}"
        })
    
    # Test 3: Detailed error messages
    try:
        # Send malformed JSON
        malformed_payload = b'{"invalid_json": '
        
        headers = {
            "Content-Type": "application/json"
        }
        
        response = await client.request(
            config.http_method,
            config.target_url,
            content=malformed_payload,
            headers=headers,
            timeout=10.0
        )
        
        # Capture response for analysis
        response_data = capture_response_data(response)

        
        response_text = response.text.lower()
        
        # Check for detailed error information
        sensitive_patterns = [
            r'traceback',
            r'stack trace',
            r'\.py',  # Python file references
            r'\.java',  # Java file references
            r'\.cs',  # C# file references
            r'/home/',
            r'c:\\',
            r'/var/',
            r'/usr/',
            r'line \d+',
            r'at line',
            r'error in',
            r'exception',
        ]
        
        has_sensitive_info = any(re.search(pattern, response_text, re.IGNORECASE) for pattern in sensitive_patterns)
        
        if has_sensitive_info:
            results.append({
                "category": "STRIDE - C03 Information Disclosure",
                "name": "Detailed Error Messages",
                "status": "FAIL",
                "details": "Server returns detailed error messages that may leak internal information",
                "risk": "Error messages reveal system internals, file paths, or stack traces",
                "mitigation": "Return generic error messages to users, log detailed errors internally"
            })
        else:
            results.append({
                "category": "STRIDE - C03 Information Disclosure",
                "name": "Detailed Error Messages",
                "status": "PASS",
                "details": "Server returns generic error messages without sensitive details"
            })
    except Exception as e:
        results.append({
            "category": "STRIDE - C03 Information Disclosure",
            "name": "Detailed Error Messages",
            "status": "WARN",
            "details": f"Test failed with error: {str(e)}"
        })
    
    return results
