"""OWASP A02: Cryptographic Failures test."""
import httpx
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


async def test_encryption_transit(config: ScannerSettings) -> Dict:
    """
    Test for cryptographic failures in transit (OWASP A02).
    """
    try:
        if not config.target_url.startswith("https://"):
            return {
                "category": "OWASP - A02 Cryptographic Failures",
                "name": "Encryption in Transit",
                "status": "FAIL",
                "details": "Webhook does not use HTTPS. Data transmitted in plaintext.",
                "risk": "Sensitive data can be intercepted by attackers through man-in-the-middle attacks.",
                "mitigation": "Enable HTTPS with TLS 1.2+ and redirect all HTTP traffic to HTTPS."
            }
        
        # Test if HTTP is also accessible (should not be)
        http_url = config.target_url.replace("https://", "http://")
        try:
            async with httpx.AsyncClient(verify=False) as client:
                response = await client.get(http_url, timeout=5.0, follow_redirects=False)
                
                if response.status_code in [301, 302, 307, 308]:
                    # HTTP redirects to HTTPS - good
                    return {
                        "category": "OWASP - A02 Cryptographic Failures",
                        "name": "Encryption in Transit",
                        "status": "PASS",
                        "details": "HTTPS enforced. HTTP requests are redirected to HTTPS.",
                        "risk": None,
                        "mitigation": None
                    }
                elif response.status_code == 200:
                    return {
                        "category": "OWASP - A02 Cryptographic Failures",
                        "name": "Encryption in Transit",
                        "status": "WARN",
                        "details": "HTTP endpoint is accessible without redirect to HTTPS.",
                        "risk": "Users might accidentally use unencrypted HTTP.",
                        "mitigation": "Configure server to redirect all HTTP traffic to HTTPS."
                    }
        except:
            pass
        
        return {
            "category": "OWASP - A02 Cryptographic Failures",
            "name": "Encryption in Transit",
            "status": "PASS",
            "details": "HTTPS endpoint used. HTTP endpoint not accessible.",
            "risk": None,
            "mitigation": None
        }
    except Exception as e:
        return {
            "category": "OWASP - A02 Cryptographic Failures",
            "name": "Encryption in Transit",
            "status": "WARN",
            "details": f"Error testing encryption: {str(e)}",
            "risk": "Unable to verify encryption configuration.",
            "mitigation": "Ensure HTTPS with TLS 1.2+ is properly configured."
        }
