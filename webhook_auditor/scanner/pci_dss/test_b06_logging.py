"""PCI DSS Requirement 10: Audit Trail Logging test."""
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


async def test_logging_capability(config: ScannerSettings) -> Dict:
    """
    Test if endpoint provides logging/audit trail capabilities.
    PCI DSS Requirement 10.2
    """
    try:
        headers = config.custom_headers.copy() if config.custom_headers else {}
        
        if config.shared_secret:
            timestamp = str(int(httpx.get("https://worldtimeapi.org/api/timezone/Etc/UTC", timeout=5).json()["unixtime"]))
            signature = calculate_hmac_signature(config.shared_secret, config.sample_valid_payload)
            headers[config.signature_header_name] = f"{config.signature_prefix}{signature}"
            if config.timestamp_header_name:
                headers[config.timestamp_header_name] = timestamp
        
        async with httpx.AsyncClient(verify=False) as client:
            response = await client.request(
                config.http_method,
                config.target_url,
                json=json.loads(config.sample_valid_payload),
                headers=headers,
                timeout=10.0
            )
            response_data = capture_response_data(response)
            
            # Check for logging indicators in headers
            logging_headers = ["x-request-id", "x-correlation-id", "x-trace-id"]
            has_logging = any(h.lower() in [k.lower() for k in response.headers.keys()] for h in logging_headers)
            
            if has_logging:
                return {
                    "category": "PCI DSS - B06 Audit Logging",
                    "name": "Audit Trail Logging",
                    "status": "PASS",
                    "details": "Request tracking headers detected. Endpoint appears to implement audit logging.",
                    "risk": None,
                    "mitigation": None,
                    "response": response_data
                }
            else:
                return {
                    "category": "PCI DSS - B06 Audit Logging",
                    "name": "Audit Trail Logging",
                    "status": "WARN",
                    "details": "No request tracking headers detected. Cannot verify audit logging implementation.",
                    "risk": "Insufficient audit trail may prevent detection of security incidents.",
                    "mitigation": "Implement comprehensive logging with request IDs, timestamps, and user identification.",
                    "response": response_data
                }
    except Exception as e:
        return {
            "category": "PCI DSS - B06 Audit Logging",
            "name": "Audit Trail Logging",
            "status": "WARN",
            "details": f"Error checking logging capability: {str(e)}",
            "risk": "Unable to verify audit trail implementation.",
            "mitigation": "Ensure all access to webhook endpoint is logged with timestamps and user identification."
        }
