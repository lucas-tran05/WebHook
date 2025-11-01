"""OWASP A01: Broken Access Control test."""
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
            response_data_no_auth = capture_response_data(response_no_auth)
            
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
            response_data_invalid = capture_response_data(response_invalid)
            
            # Check if unauthorized access is rejected
            if response_no_auth.status_code == 200 or response_invalid.status_code == 200:
                return {
                    "category": "OWASP - A01 Broken Access Control",
                    "name": "Access Control Enforcement",
                    "status": "FAIL",
                    "details": "Webhook accepts requests without proper authentication/authorization.",
                    "risk": "Unauthorized users can trigger webhook actions, potentially causing data breaches or system compromise.",
                    "mitigation": "Implement proper authentication (HMAC signatures, API keys) and reject unauthenticated requests with 401/403 status codes.",
                    "responses": [response_data_no_auth, response_data_invalid]
                }
            else:
                return {
                    "category": "OWASP - A01 Broken Access Control",
                    "name": "Access Control Enforcement",
                    "status": "PASS",
                    "details": "Webhook properly rejects unauthenticated/unauthorized requests.",
                    "risk": None,
                    "mitigation": None,
                    "responses": [response_data_no_auth, response_data_invalid]
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
