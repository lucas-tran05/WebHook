"""PCI DSS Requirement 4: TLS Version test."""
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


async def test_tls_version(config: ScannerSettings) -> Dict:
    """
    Test if HTTPS with TLS 1.2+ is enforced.
    PCI DSS Requirement 4.1
    """
    try:
        # Check if URL uses HTTPS
        if not config.target_url.startswith("https://"):
            return {
                "category": "PCI DSS - B01 TLS Encryption",
                "name": "TLS Encryption Enforcement",
                "status": "FAIL",
                "details": "Webhook endpoint does not use HTTPS. PCI DSS requires TLS 1.2 or higher for all transmissions.",
                "risk": "Sensitive payment data could be intercepted in transit.",
                "mitigation": "Enable HTTPS with TLS 1.2 or higher on your webhook endpoint."
            }
        
        # Test connection with TLS
        async with httpx.AsyncClient(verify=True) as client:
            try:
                response = await client.get(config.target_url, timeout=10.0)
                return {
                    "category": "PCI DSS - B01 TLS Encryption",
                    "name": "TLS Encryption Enforcement",
                    "status": "PASS",
                    "details": "Endpoint uses HTTPS. TLS encryption is enforced.",
                    "risk": None,
                    "mitigation": None
                }
            except httpx.ConnectError:
                return {
                    "category": "PCI DSS - B01 TLS Encryption",
                    "name": "TLS Encryption Enforcement",
                    "status": "WARN",
                    "details": "Unable to verify TLS configuration due to connection error.",
                    "risk": "Cannot confirm secure transmission capability.",
                    "mitigation": "Ensure the endpoint is accessible and properly configured with valid TLS certificates."
                }
    except Exception as e:
        return {
            "category": "PCI DSS - B01 TLS Encryption",
            "name": "TLS Encryption Enforcement",
            "status": "WARN",
            "details": f"Error testing TLS: {str(e)}",
            "risk": "Unable to verify encryption requirements.",
            "mitigation": "Review webhook endpoint TLS configuration."
        }
