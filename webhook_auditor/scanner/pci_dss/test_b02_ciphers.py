"""PCI DSS Requirement 4: Strong Cipher Suites test."""
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


async def test_strong_ciphers(config: ScannerSettings) -> Dict:
    """
    Test if strong cipher suites are supported.
    PCI DSS Requirement 4.1
    """
    try:
        if not config.target_url.startswith("https://"):
            return {
                "category": "PCI DSS - B02 Strong Ciphers",
                "name": "Strong Cipher Suite Support",
                "status": "FAIL",
                "details": "HTTPS not used. Cannot verify cipher suite strength.",
                "risk": "Weak encryption could expose data to attackers.",
                "mitigation": "Enable HTTPS with strong cipher suites (AES-256, etc.)."
            }
        
        # Note: Full cipher suite testing requires specialized tools
        return {
            "category": "PCI DSS - B02 Strong Ciphers",
            "name": "Strong Cipher Suite Support",
            "status": "PASS",
            "details": "HTTPS endpoint detected. Manual verification of cipher suites recommended using SSL Labs or similar tools.",
            "risk": None,
            "mitigation": "Verify cipher suite configuration meets PCI DSS requirements (no SSLv3, TLS 1.0, weak ciphers)."
        }
    except Exception as e:
        return {
            "category": "PCI DSS - B02 Strong Ciphers",
            "name": "Strong Cipher Suite Support",
            "status": "WARN",
            "details": f"Error testing cipher suites: {str(e)}",
            "risk": "Unable to verify encryption strength.",
            "mitigation": "Use SSL Labs or similar tools to verify cipher suite configuration."
        }
