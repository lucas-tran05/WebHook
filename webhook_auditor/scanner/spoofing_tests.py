"""Spoofing and Tampering security tests."""
import httpx
from typing import List, Dict
from ..utils.crypto import calculate_hmac_signature
import json


async def run_spoofing_tampering_tests(config, client: httpx.AsyncClient) -> List[Dict]:
    """
    Run tests for Spoofing and Tampering threats.
    
    Tests signature validation and payload integrity checks.
    
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
            "category": "Spoofing & Tampering",
            "name": "Signature Tests",
            "status": "WARN",
            "details": "Skipped - No shared secret provided. These tests require HMAC signature validation."
        })
        return results
    
    payload_bytes = config.sample_valid_payload.encode('utf-8')
    secret_bytes = config.shared_secret.encode('utf-8')
    
    # Test 1: Request with no signature
    try:
        headers = {"Content-Type": "application/json"}
        response = await client.request(
            config.http_method,
            config.target_url,
            content=payload_bytes,
            headers=headers,
            timeout=10.0
        )
        
        # Expect 4xx error (unauthorized/forbidden)
        if 400 <= response.status_code < 500:
            results.append({
                "category": "Spoofing & Tampering",
                "name": "Request with No Signature",
                "status": "PASS",
                "details": f"Server correctly rejected request without signature (HTTP {response.status_code})"
            })
        else:
            results.append({
                "category": "Spoofing & Tampering",
                "name": "Request with No Signature",
                "status": "FAIL",
                "details": f"Server accepted request without signature (Expected 4xx, Got {response.status_code})",
                "risk": "Attackers can send unsigned requests that will be processed as legitimate",
                "mitigation": "Enforce signature validation - reject all requests without a valid signature header"
            })
    except Exception as e:
        results.append({
            "category": "Spoofing & Tampering",
            "name": "Request with No Signature",
            "status": "WARN",
            "details": f"Test failed with error: {str(e)}"
        })
    
    # Test 2: Request with invalid signature
    try:
        headers = {
            "Content-Type": "application/json",
            config.signature_header_name: f"{config.signature_prefix}invalid_signature_12345"
        }
        response = await client.request(
            config.http_method,
            config.target_url,
            content=payload_bytes,
            headers=headers,
            timeout=10.0
        )
        
        if 400 <= response.status_code < 500:
            results.append({
                "category": "Spoofing & Tampering",
                "name": "Request with Invalid Signature",
                "status": "PASS",
                "details": f"Server correctly rejected request with invalid signature (HTTP {response.status_code})"
            })
        else:
            results.append({
                "category": "Spoofing & Tampering",
                "name": "Request with Invalid Signature",
                "status": "FAIL",
                "details": f"Server accepted request with invalid signature (Expected 4xx, Got {response.status_code})",
                "risk": "Attackers can forge requests to trigger unauthorized actions",
                "mitigation": "Enforce HMAC signature validation - verify the signature matches the expected value"
            })
    except Exception as e:
        results.append({
            "category": "Spoofing & Tampering",
            "name": "Request with Invalid Signature",
            "status": "WARN",
            "details": f"Test failed with error: {str(e)}"
        })
    
    # Test 3: Tampered payload with valid signature for original
    try:
        # Calculate signature for original payload
        valid_signature = calculate_hmac_signature(secret_bytes, payload_bytes, config.signature_prefix)
        
        # Modify the payload
        try:
            payload_dict = json.loads(config.sample_valid_payload)
            payload_dict["tampered"] = True
            tampered_payload = json.dumps(payload_dict).encode('utf-8')
        except:
            tampered_payload = (config.sample_valid_payload + " TAMPERED").encode('utf-8')
        
        headers = {
            "Content-Type": "application/json",
            config.signature_header_name: valid_signature
        }
        response = await client.request(
            config.http_method,
            config.target_url,
            content=tampered_payload,
            headers=headers,
            timeout=10.0
        )
        
        if 400 <= response.status_code < 500:
            results.append({
                "category": "Spoofing & Tampering",
                "name": "Tampered Payload with Mismatched Signature",
                "status": "PASS",
                "details": f"Server correctly rejected tampered payload (HTTP {response.status_code})"
            })
        else:
            results.append({
                "category": "Spoofing & Tampering",
                "name": "Tampered Payload with Mismatched Signature",
                "status": "FAIL",
                "details": f"Server accepted tampered payload (Expected 4xx, Got {response.status_code})",
                "risk": "Payload integrity not verified - attackers can modify webhook data in transit",
                "mitigation": "Calculate signature from received payload and verify it matches the provided signature"
            })
    except Exception as e:
        results.append({
            "category": "Spoofing & Tampering",
            "name": "Tampered Payload with Mismatched Signature",
            "status": "WARN",
            "details": f"Test failed with error: {str(e)}"
        })
    
    return results
