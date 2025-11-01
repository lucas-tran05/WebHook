"""OWASP A05: Security Misconfiguration - Error Handling test."""
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


async def test_error_handling(config: ScannerSettings) -> Dict:
    """
    Test for security misconfiguration - verbose error messages (OWASP A05).
    """
    try:
        headers = config.custom_headers.copy() if config.custom_headers else {}
        
        # Send malformed request
        async with httpx.AsyncClient(verify=False) as client:
            response = await client.request(
                config.http_method,
                config.target_url,
                content="invalid json {{{",  # Malformed JSON
                headers={**headers, "Content-Type": "application/json"},
                timeout=10.0
            )
            
            # Capture response for analysis
            response_data = capture_response_data(response)

            
            response_lower = response.text.lower()
            
            # Check for verbose error information
            verbose_indicators = [
                "traceback", "stack trace", "exception",
                "line ", ".py:", ".js:", ".php:",
                "at ", "file ", "in function",
                "sql error", "database error"
            ]
            
            found_indicators = [ind for ind in verbose_indicators if ind in response_lower]
            
            if len(found_indicators) >= 2:
                return {
                    "category": "OWASP - A05 Security Misconfiguration",
                    "name": "Error Handling Configuration",
                    "status": "FAIL",
                    "details": "Verbose error messages expose internal application details.",
                    "risk": "Attackers can use error information to identify vulnerabilities and plan attacks.",
                    "mitigation": "Implement generic error messages for users. Log detailed errors server-side only."
                }
            elif len(found_indicators) > 0:
                return {
                    "category": "OWASP - A05 Security Misconfiguration",
                    "name": "Error Handling Configuration",
                    "status": "WARN",
                    "details": "Some technical details visible in error responses.",
                    "risk": "Minor information leakage could aid attackers.",
                    "mitigation": "Review error handling to minimize information disclosure."
                }
            else:
                return {
                    "category": "OWASP - A05 Security Misconfiguration",
                    "name": "Error Handling Configuration",
                    "status": "PASS",
                    "details": "Error messages do not expose sensitive technical information.",
                    "risk": None,
                    "mitigation": None
                }
    except Exception as e:
        return {
            "category": "OWASP - A05 Security Misconfiguration",
            "name": "Error Handling Configuration",
            "status": "WARN",
            "details": f"Error testing error handling: {str(e)}",
            "risk": "Unable to verify error handling configuration.",
            "mitigation": "Review error handling implementation."
        }
