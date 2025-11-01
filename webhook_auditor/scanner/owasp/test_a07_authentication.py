"""OWASP A07: Identification and Authentication Failures test."""
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


async def test_weak_authentication(config: ScannerSettings) -> Dict:
    """
    Test for weak authentication mechanisms (OWASP A07).
    """
    try:
        if not config.shared_secret and not config.custom_headers:
            return {
                "category": "OWASP - A07 Auth Failures",
                "name": "Authentication Mechanism Strength",
                "status": "FAIL",
                "details": "No authentication mechanism configured.",
                "risk": "Anyone can send requests to your webhook endpoint.",
                "mitigation": "Implement HMAC signature validation or API key authentication."
            }
        
        if config.shared_secret:
            if len(config.shared_secret) < 16:
                return {
                    "category": "OWASP - A07 Auth Failures",
                    "name": "Authentication Mechanism Strength",
                    "status": "FAIL",
                    "details": f"Shared secret is too weak ({len(config.shared_secret)} characters). Minimum 16 characters recommended.",
                    "risk": "Weak secrets can be brute-forced or guessed.",
                    "mitigation": "Use a cryptographically random secret of at least 32 characters."
                }
            elif len(config.shared_secret) < 32:
                return {
                    "category": "OWASP - A07 Auth Failures",
                    "name": "Authentication Mechanism Strength",
                    "status": "WARN",
                    "details": f"Shared secret length is moderate ({len(config.shared_secret)} characters). 32+ characters recommended.",
                    "risk": "Moderate secrets provide less security margin.",
                    "mitigation": "Consider using a 256-bit (32+ character) secret for maximum security."
                }
        
        return {
            "category": "OWASP - A07 Auth Failures",
            "name": "Authentication Mechanism Strength",
            "status": "PASS",
            "details": "Strong authentication mechanism configured.",
            "risk": None,
            "mitigation": None
        }
    except Exception as e:
        return {
            "category": "OWASP - A07 Auth Failures",
            "name": "Authentication Mechanism Strength",
            "status": "WARN",
            "details": f"Error evaluating authentication: {str(e)}",
            "risk": "Unable to verify authentication strength.",
            "mitigation": "Review authentication implementation."
        }
