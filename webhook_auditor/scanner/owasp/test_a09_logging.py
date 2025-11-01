"""OWASP A09: Security Logging and Monitoring Failures test."""
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
            response_data = capture_response_data(response)
            
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
                    "mitigation": None,
                    "response": response_data
                }
            else:
                return {
                    "category": "OWASP - A09 Logging Failures",
                    "name": "Security Logging and Monitoring",
                    "status": "WARN",
                    "details": "No request tracking headers detected. Cannot verify logging implementation.",
                    "risk": "Insufficient logging may prevent detection of security incidents.",
                    "mitigation": "Implement comprehensive logging with request IDs, timestamps, IP addresses, and security events.",
                    "response": response_data
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
