"""PCI DSS Requirement 8: Authentication Strength test."""
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


async def test_authentication_strength(config: ScannerSettings) -> Dict:
    """
    Test authentication mechanism strength.
    PCI DSS Requirement 8.2
    """
    try:
        has_signature = config.shared_secret is not None and len(config.shared_secret) > 0
        has_custom_auth = False
        
        if config.custom_headers:
            auth_headers = ["authorization", "x-api-key", "api-key", "x-auth-token"]
            has_custom_auth = any(h.lower() in [k.lower() for k in config.custom_headers.keys()] for h in auth_headers)
        
        if not has_signature and not has_custom_auth:
            return {
                "category": "PCI DSS - B05 Authentication",
                "name": "Authentication Strength",
                "status": "FAIL",
                "details": "No authentication mechanism detected (no signature, no API key).",
                "risk": "Unauthorized access to webhook endpoint could expose cardholder data.",
                "mitigation": "Implement HMAC signature validation or API key authentication."
            }
        
        if has_signature and len(config.shared_secret) < 32:
            return {
                "category": "PCI DSS - B05 Authentication",
                "name": "Authentication Strength",
                "status": "WARN",
                "details": f"Shared secret is too short ({len(config.shared_secret)} characters). PCI DSS recommends 256-bit keys (32+ characters).",
                "risk": "Weak keys are easier to brute force.",
                "mitigation": "Use a shared secret of at least 32 characters (256 bits)."
            }
        
        return {
            "category": "PCI DSS - B05 Authentication",
            "name": "Authentication Strength",
            "status": "PASS",
            "details": "Strong authentication mechanism detected.",
            "risk": None,
            "mitigation": None
        }
    except Exception as e:
        return {
            "category": "PCI DSS - B05 Authentication",
            "name": "Authentication Strength",
            "status": "WARN",
            "details": f"Error evaluating authentication: {str(e)}",
            "risk": "Unable to verify authentication strength.",
            "mitigation": "Review authentication implementation."
        }
