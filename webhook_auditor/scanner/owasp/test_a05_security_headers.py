"""OWASP A05: Security Misconfiguration - Headers test."""
import httpx
import json
from typing import Dict
from ..config import ScannerSettings


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
            response_data = capture_response_data(response)
            
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
                    "mitigation": "Add missing security headers to HTTP responses.",
                    "response": response_data
                }
            elif len(missing) > 0:
                return {
                    "category": "OWASP - A05 Security Misconfiguration",
                    "name": "Security Headers Configuration",
                    "status": "WARN",
                    "details": f"Some security headers missing: {'; '.join(missing)}",
                    "risk": "Reduced protection against certain attack vectors.",
                    "mitigation": "Add recommended security headers.",
                    "response": response_data
                }
            else:
                return {
                    "category": "OWASP - A05 Security Misconfiguration",
                    "name": "Security Headers Configuration",
                    "status": "PASS",
                    "details": "All recommended security headers are present.",
                    "risk": None,
                    "mitigation": None,
                    "response": response_data
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
