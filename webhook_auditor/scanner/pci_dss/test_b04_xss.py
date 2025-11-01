"""PCI DSS Requirement 6: XSS Protection test."""
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
            response_data = capture_response_data(response)
            
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
                    "category": "PCI DSS - B04 XSS Protection",
                    "name": "XSS Protection Headers",
                    "status": "FAIL",
                    "details": f"Missing important security headers: {', '.join(missing_headers)}",
                    "risk": "Application may be vulnerable to Cross-Site Scripting attacks.",
                    "mitigation": "Add security headers: X-XSS-Protection, X-Content-Type-Options, Content-Security-Policy",
                    "response": response_data
                }
            elif len(missing_headers) == 1:
                return {
                    "category": "PCI DSS - B04 XSS Protection",
                    "name": "XSS Protection Headers",
                    "status": "WARN",
                    "details": f"Missing security header: {missing_headers[0]}",
                    "risk": "Reduced protection against XSS attacks.",
                    "mitigation": f"Add missing header: {missing_headers[0]}",
                    "response": response_data
                }
            else:
                return {
                    "category": "PCI DSS - B04 XSS Protection",
                    "name": "XSS Protection Headers",
                    "status": "PASS",
                    "details": "All recommended XSS protection headers are present.",
                    "risk": None,
                    "mitigation": None,
                    "response": response_data
                }
    except Exception as e:
        return {
            "category": "PCI DSS - B04 XSS Protection",
            "name": "XSS Protection Headers",
            "status": "WARN",
            "details": f"Error checking security headers: {str(e)}",
            "risk": "Unable to verify XSS protection.",
            "mitigation": "Ensure XSS protection headers are properly configured."
        }
