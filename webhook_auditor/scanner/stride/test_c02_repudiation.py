"""
Repudiation Tests for STRIDE Threat Model

Tests for replay attack prevention and timestamp validation.
"""

import time
from datetime import datetime, timedelta
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


async def run_repudiation_tests(config, client: httpx.AsyncClient) -> List[Dict]:
    """
    Run tests for Repudiation threats.
    
    Tests timestamp validation and replay attack prevention.
    
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
            "category": "STRIDE - C02 Repudiation",
            "name": "Replay Attack Tests",
            "status": "WARN",
            "details": "Skipped - No shared secret provided. These tests require HMAC signature validation."
        })
        return results
    
    payload_bytes = config.sample_valid_payload.encode('utf-8')
    secret_bytes = config.shared_secret.encode('utf-8')
    
    # Test 1: Old timestamp check
    if config.timestamp_header_name:
        try:
            # Generate timestamp from 10 minutes ago
            old_timestamp = (datetime.utcnow() - timedelta(minutes=10)).isoformat()
            
            # Create payload with timestamp if needed for signature
            signature_payload = payload_bytes
            valid_signature = calculate_hmac_signature(secret_bytes, signature_payload, config.signature_prefix)
            
            headers = {
                "Content-Type": "application/json",
                config.signature_header_name: valid_signature,
                config.timestamp_header_name: old_timestamp
            }
            
            response = await client.request(
                config.http_method,
                config.target_url,
                content=payload_bytes,
                headers=headers,
                timeout=10.0
            )
            
            # Capture response for analysis
            response_data = capture_response_data(response)

            
            if 400 <= response.status_code < 500:
                results.append({
                    "category": "STRIDE - C02 Repudiation",
                    "name": "Old Timestamp Check",
                    "status": "PASS",
                    "details": f"Server correctly rejected request with old timestamp (HTTP {response.status_code})"
                })
            else:
                results.append({
                    "category": "STRIDE - C02 Repudiation",
                    "name": "Old Timestamp Check",
                    "status": "FAIL",
                    "details": f"Server accepted request with old timestamp (Expected 4xx, Got {response.status_code})",
                    "risk": "Replay attacks possible - old requests can be resent and processed",
                    "mitigation": "Implement timestamp validation - reject requests older than a threshold (e.g., 5 minutes)"
                })
        except Exception as e:
            results.append({
                "category": "STRIDE - C02 Repudiation",
                "name": "Old Timestamp Check",
                "status": "WARN",
                "details": f"Test failed with error: {str(e)}"
            })
    else:
        results.append({
            "category": "STRIDE - C02 Repudiation",
            "name": "Old Timestamp Check",
            "status": "WARN",
            "details": "Skipped - no timestamp header configured"
        })
    
    # Test 2: Replay attack detection
    try:
        # Send a valid request
        timestamp = datetime.utcnow().isoformat()
        signature_payload = payload_bytes
        valid_signature = calculate_hmac_signature(secret_bytes, signature_payload, config.signature_prefix)
        
        headers = {
            "Content-Type": "application/json",
            config.signature_header_name: valid_signature
        }
        
        if config.timestamp_header_name:
            headers[config.timestamp_header_name] = timestamp
        
        # Send the same request twice
        response1 = await client.request(
            config.http_method,
            config.target_url,
            content=payload_bytes,
            headers=headers,
            timeout=10.0
        )
        
        # Capture response for analysis
        response_data = capture_response_data(response)

        
        # Small delay
        time.sleep(0.5)
        
        response2 = await client.request(
            config.http_method,
            config.target_url,
            content=payload_bytes,
            headers=headers,
            timeout=10.0
        )
        
        # Capture response for analysis
        response_data = capture_response_data(response)

        
        # Check if the second request was rejected
        if response1.status_code < 300 and response2.status_code >= 400:
            results.append({
                "category": "STRIDE - C02 Repudiation",
                "name": "Replay Attack Detection",
                "status": "PASS",
                "details": "Server detected and rejected replayed request",
                "response": response_data
            })
        elif response1.status_code >= 400:
            results.append({
                "category": "STRIDE - C02 Repudiation",
                "name": "Replay Attack Detection",
                "status": "WARN",
                "details": "Could not test - initial valid request was rejected",
                "response": response_data
            })
        else:
            results.append({
                "category": "STRIDE - C02 Repudiation",
                "name": "Replay Attack Detection",
                "status": "WARN",
                "details": f"Both requests accepted (HTTP {response1.status_code}, {response2.status_code}) - consider implementing nonce-based replay protection",
                "risk": "Identical requests can be replayed multiple times",
                "mitigation": "Implement nonce/request ID tracking to prevent replay attacks"
            })
    except Exception as e:
        results.append({
            "category": "STRIDE - C02 Repudiation",
            "name": "Replay Attack Detection",
            "status": "WARN",
            "details": f"Test failed with error: {str(e)}"
        })
    
    return results
