"""OWASP A03: Injection (basic test)."""
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


async def test_injection_basics(config: ScannerSettings) -> Dict:
    """
    Basic injection test (OWASP A03).
    Detailed tests in STRIDE injection_tests.
    """
    try:
        import json
        
        # Malicious payloads to inject
        injection_values = [
            "<script>alert('xss')</script>",
            "'; DROP TABLE users; --",
            "cat /etc/passwd"
        ]
        
        headers = config.custom_headers.copy() if config.custom_headers else {}
        if config.shared_secret:
            headers[config.signature_header_name] = "dummy_for_test"
        
        vulnerable = False
        async with httpx.AsyncClient(verify=False) as client:
            for injection_value in injection_values:
                # Use user's configured payload as base
                try:
                    base_payload = json.loads(config.sample_valid_payload)
                except:
                    base_payload = {"event": "test", "data": "sample"}
                
                payload = base_payload.copy()
                
                # Inject malicious value into all string fields
                for key in payload:
                    if isinstance(payload[key], str):
                        payload[key] = injection_value
                
                # Add test field
                payload["_test_injection"] = injection_value
                try:
                    response = await client.request(
                        config.http_method,
                        config.target_url,
                        json=payload,
                        headers=headers,
                        timeout=10.0
                    )
                    
                    # Capture response for analysis
                    response_data = capture_response_data(response)

                    
                    # Check if malicious content is reflected
                    if "<script>" in response.text or "DROP TABLE" in response.text:
                        vulnerable = True
                        break
                except:
                    pass
        
        if vulnerable:
            return {
                "category": "OWASP - A03 Injection",
                "name": "Basic Injection Protection",
                "status": "FAIL",
                "details": "Endpoint may be vulnerable to injection attacks. Malicious input reflected in response.",
                "risk": "Attackers can execute arbitrary code, access databases, or steal data.",
                "mitigation": "Implement input validation, output encoding, and use parameterized queries."
            }
        else:
            return {
                "category": "OWASP - A03 Injection",
                "name": "Basic Injection Protection",
                "status": "PASS",
                "details": "No obvious injection vulnerabilities in basic tests. See detailed injection tests for comprehensive coverage.",
                "risk": None,
                "mitigation": None
            }
    except Exception as e:
        return {
            "category": "OWASP - A03 Injection",
            "name": "Basic Injection Protection",
            "status": "WARN",
            "details": f"Error testing injection protection: {str(e)}",
            "risk": "Unable to verify injection protection.",
            "mitigation": "Review input validation and sanitization practices."
        }
