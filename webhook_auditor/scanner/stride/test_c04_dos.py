"""
Denial of Service Tests for STRIDE Threat Model

Tests for large payload handling and rate limiting.
"""

import asyncio
from typing import Dict, List
import httpx
from ...utils.crypto import calculate_hmac_signature


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


async def run_dos_tests(config, client: httpx.AsyncClient) -> List[Dict]:
    """
    Run tests for Denial of Service threats.
    
    Tests for large payload handling and rate limiting.
    
    Args:
        config: Scanner configuration object
        client: HTTP client for making requests
    
    Returns:
        List of test result dictionaries
    """
    results = []
    
    # Check if shared secret is provided
    if not config.shared_secret:
        results.append({
            "category": "STRIDE - C04 Denial of Service",
            "name": "DoS Tests",
            "status": "WARN",
            "details": "Skipped - No shared secret provided. These tests require HMAC signature validation."
        })
        return results
    
    secret_bytes = config.shared_secret.encode('utf-8')
    
    # Test 1: Large payload handling
    try:
        # Create a 10MB payload
        large_payload_size = 10 * 1024 * 1024  # 10 MB
        large_payload = ('{"data": "' + 'x' * (large_payload_size - 20) + '"}').encode('utf-8')
        
        valid_signature = calculate_hmac_signature(secret_bytes, large_payload, config.signature_prefix)
        headers = {
            "Content-Type": "application/json",
            config.signature_header_name: valid_signature
        }
        
        try:
            response = await client.request(
                config.http_method,
                config.target_url,
                content=large_payload,
                headers=headers,
                timeout=30.0  # Longer timeout for large payload
            )
            
            # Capture response for analysis
            response_data = capture_response_data(response)

            
            # Expect 413 Payload Too Large
            if response.status_code == 413:
                results.append({
                    "category": "STRIDE - C04 Denial of Service",
                    "name": "Large Payload Handling",
                    "status": "PASS",
                    "details": "Server correctly rejected large payload with HTTP 413",
                "response": response_data
                })
            elif response.status_code == 400:
                results.append({
                    "category": "STRIDE - C04 Denial of Service",
                    "name": "Large Payload Handling",
                    "status": "PASS",
                    "details": "Server rejected large payload with HTTP 400",
                "response": response_data
                })
            elif 200 <= response.status_code < 300:
                results.append({
                    "category": "STRIDE - C04 Denial of Service",
                    "name": "Large Payload Handling",
                    "status": "FAIL",
                    "details": f"Server accepted 10MB payload (HTTP {response.status_code})",
                    "risk": "No payload size limits - attackers can exhaust server resources with large requests",
                    "mitigation": "Implement payload size limits (e.g., 1-5MB) and reject oversized requests with HTTP 413"
                })
            else:
                results.append({
                    "category": "STRIDE - C04 Denial of Service",
                    "name": "Large Payload Handling",
                    "status": "WARN",
                    "details": f"Unexpected response to large payload: HTTP {response.status_code}"
                })
        except (httpx.TimeoutException, asyncio.TimeoutError):
            results.append({
                "category": "STRIDE - C04 Denial of Service",
                "name": "Large Payload Handling",
                "status": "FAIL",
                "details": "Server timed out processing large payload",
                "risk": "Large payloads cause server to hang - vulnerable to resource exhaustion",
                "mitigation": "Implement payload size limits before processing the request body"
            })
        except httpx.RemoteProtocolError as e:
            # Connection reset or similar - might indicate a firewall/proxy blocking
            results.append({
                "category": "STRIDE - C04 Denial of Service",
                "name": "Large Payload Handling",
                "status": "PASS",
                "details": "Connection closed (likely due to size limit at proxy/firewall level)"
            })
    except Exception as e:
        results.append({
            "category": "STRIDE - C04 Denial of Service",
            "name": "Large Payload Handling",
            "status": "WARN",
            "details": f"Test failed with error: {str(e)}"
        })
    
    # Test 2: Rate limiting
    try:
        payload_bytes = config.sample_valid_payload.encode('utf-8')
        valid_signature = calculate_hmac_signature(secret_bytes, payload_bytes, config.signature_prefix)
        headers = {
            "Content-Type": "application/json",
            config.signature_header_name: valid_signature
        }
        
        # Send 15 requests concurrently
        async def send_request(index):
            try:
                response = await client.request(
                    config.http_method,
                    config.target_url,
                    content=payload_bytes,
                    headers=headers,
                    timeout=10.0
                )
                # Capture response for analysis
                response_data = capture_response_data(response)

                return response.status_code
            except Exception:
                return None
        
        tasks = [send_request(i) for i in range(15)]
        status_codes = await asyncio.gather(*tasks)
        
        # Check if any requests were rate limited (429 status code)
        rate_limited = any(code == 429 for code in status_codes if code)
        successful = sum(1 for code in status_codes if code and 200 <= code < 300)
        
        if rate_limited:
            results.append({
                "category": "STRIDE - C04 Denial of Service",
                "name": "Rate Limiting",
                "status": "PASS",
                "details": f"Rate limiting detected - some requests returned HTTP 429"
            })
        elif successful >= 12:
            results.append({
                "category": "STRIDE - C04 Denial of Service",
                "name": "Rate Limiting",
                "status": "WARN",
                "details": f"All 15 burst requests accepted - no rate limiting detected",
                "risk": "No rate limiting allows attackers to overwhelm the endpoint with requests",
                "mitigation": "Implement rate limiting (e.g., max 100 requests per minute per IP/API key)"
            })
        else:
            results.append({
                "category": "STRIDE - C04 Denial of Service",
                "name": "Rate Limiting",
                "status": "WARN",
                "details": f"Inconclusive - {successful}/15 requests successful, no clear rate limiting pattern"
            })
    except Exception as e:
        results.append({
            "category": "STRIDE - C04 Denial of Service",
            "name": "Rate Limiting",
            "status": "WARN",
            "details": f"Test failed with error: {str(e)}"
        })
    
    return results
