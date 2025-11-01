"""OWASP A10: Server-Side Request Forgery (SSRF) test."""
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


async def test_ssrf_protection(config: ScannerSettings) -> Dict:
    """
    Test for Server-Side Request Forgery protection (OWASP A10).
    """
    try:
        import json
        
        # SSRF payloads targeting internal resources
        ssrf_urls = [
            "http://169.254.169.254/latest/meta-data/",  # AWS metadata
            "http://localhost:22",  # Internal SSH
            "http://127.0.0.1:6379",  # Internal Redis
            "file:///etc/passwd"  # Local file
        ]
        
        headers = config.custom_headers.copy() if config.custom_headers else {}
        if config.shared_secret:
            headers[config.signature_header_name] = "dummy_for_test"
        
        vulnerable = False
        async with httpx.AsyncClient(verify=False) as client:
            for ssrf_url in ssrf_urls:
                # Use user's configured payload as base
                try:
                    base_payload = json.loads(config.sample_valid_payload)
                except:
                    base_payload = {"event": "test", "data": "sample"}
                
                payload = base_payload.copy()
                
                # Inject SSRF URL into all string fields
                for key in payload:
                    if isinstance(payload[key], str):
                        payload[key] = ssrf_url
                
                # Add test-specific fields
                payload["_test_url"] = ssrf_url
                payload["_test_callback_url"] = ssrf_url
                payload["_test_webhook"] = ssrf_url
                payload["_test_redirect"] = ssrf_url
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

                    
                    # Check if SSRF attempt succeeded (look for metadata or internal content)
                    response_lower = response.text.lower()
                    if any(indicator in response_lower for indicator in ["ami-id", "instance-id", "redis", "ssh", "root:"]):
                        vulnerable = True
                        break
                except:
                    pass
        
        if vulnerable:
            return {
                "category": "OWASP - A10 SSRF",
                "name": "Server-Side Request Forgery Protection",
                "status": "FAIL",
                "details": "Endpoint may be vulnerable to SSRF attacks. Internal resources accessible.",
                "risk": "Attackers can access internal services, cloud metadata, or local files.",
                "mitigation": "Validate and sanitize all URLs. Block access to internal IP ranges and cloud metadata endpoints."
            }
        else:
            return {
                "category": "OWASP - A10 SSRF",
                "name": "Server-Side Request Forgery Protection",
                "status": "PASS",
                "details": "No obvious SSRF vulnerabilities detected in basic tests.",
                "risk": None,
                "mitigation": None
            }
    except Exception as e:
        return {
            "category": "OWASP - A10 SSRF",
            "name": "Server-Side Request Forgery Protection",
            "status": "WARN",
            "details": f"Error testing SSRF protection: {str(e)}",
            "risk": "Unable to verify SSRF protection.",
            "mitigation": "Implement URL validation and block internal/metadata endpoints."
        }
