"""PCI DSS Requirement 11: Vulnerability Information Disclosure test."""
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


async def test_vulnerability_disclosure(config: ScannerSettings) -> Dict:
    """
    Test if endpoint discloses sensitive information about vulnerabilities.
    PCI DSS Requirement 11.3
    """
    try:
        headers = config.custom_headers.copy() if config.custom_headers else {}
        
        # Send invalid request to trigger error
        async with httpx.AsyncClient(verify=False) as client:
            response = await client.request(
                config.http_method,
                config.target_url,
                json={"invalid": "data"},
                headers=headers,
                timeout=10.0
            )
            
            # Capture response for analysis
            response_data = capture_response_data(response)

            
            response_text = response.text.lower()
            
            # Check for sensitive information disclosure
            sensitive_patterns = [
                "stack trace", "traceback", "exception",
                "line ", "file ", ".py", ".php", ".js",
                "version", "server:", "powered by"
            ]
            
            disclosed = [p for p in sensitive_patterns if p in response_text]
            
            if len(disclosed) >= 3:
                return {
                    "category": "PCI DSS - B07 Vulnerability Disclosure",
                    "name": "Vulnerability Information Disclosure",
                    "status": "FAIL",
                    "details": f"Error responses disclose sensitive information: {', '.join(disclosed[:3])}",
                    "risk": "Attackers can use disclosed information to identify and exploit vulnerabilities.",
                    "mitigation": "Implement generic error messages. Log detailed errors server-side only."
                }
            elif len(disclosed) > 0:
                return {
                    "category": "PCI DSS - B07 Vulnerability Disclosure",
                    "name": "Vulnerability Information Disclosure",
                    "status": "WARN",
                    "details": "Some technical details visible in error responses.",
                    "risk": "Minor information disclosure could aid attackers.",
                    "mitigation": "Review error handling to ensure minimal information disclosure."
                }
            else:
                return {
                    "category": "PCI DSS - B07 Vulnerability Disclosure",
                    "name": "Vulnerability Information Disclosure",
                    "status": "PASS",
                    "details": "Error responses do not disclose sensitive technical information.",
                    "risk": None,
                    "mitigation": None
                }
    except Exception as e:
        return {
            "category": "PCI DSS - B07 Vulnerability Disclosure",
            "name": "Vulnerability Information Disclosure",
            "status": "WARN",
            "details": f"Error testing vulnerability disclosure: {str(e)}",
            "risk": "Unable to verify information disclosure protection.",
            "mitigation": "Review error handling implementation."
        }
