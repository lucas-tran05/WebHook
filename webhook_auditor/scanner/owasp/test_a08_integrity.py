"""OWASP A08: Software and Data Integrity Failures test."""
import httpx
import json
from typing import Dict
from ...utils.crypto import calculate_hmac_signature
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
            
            # Capture response for analysis
            response_data = capture_response_data(response)

            
            # Endpoint should reject tampered data
            if response.status_code == 200:
                return {
                    "category": "OWASP - A08 Integrity Failures",
                    "name": "Data Integrity Verification",
                    "status": "FAIL",
                    "details": "Endpoint accepts tampered data. Signature validation not working properly.",
                    "risk": "Attackers can modify webhook payloads without detection.",
                    "mitigation": "Properly implement signature verification and reject requests with invalid signatures.",
                "response": response_data
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
