"""Elevation of Privilege security tests."""
import httpx
from typing import List, Dict
from ..utils.crypto import calculate_hmac_signature
import json


async def run_privilege_escalation_tests(config, client: httpx.AsyncClient) -> List[Dict]:
    """
    Run tests for Elevation of Privilege threats.
    
    Tests for handling of unauthorized fields and privilege escalation attempts.
    
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
            "category": "Elevation of Privilege",
            "name": "Privilege Escalation Tests",
            "status": "WARN",
            "details": "Skipped - No shared secret provided. These tests require HMAC signature validation."
        })
        return results
    
    secret_bytes = config.shared_secret.encode('utf-8')
    
    # Test 1: Superfluous privileged fields
    try:
        # Parse the sample payload and add privileged-looking fields
        try:
            payload_dict = json.loads(config.sample_valid_payload)
        except:
            payload_dict = {"event": "test"}
        
        # Add potentially dangerous fields
        payload_dict["is_admin"] = True
        payload_dict["role"] = "administrator"
        payload_dict["permissions"] = ["all"]
        
        modified_payload = json.dumps(payload_dict).encode('utf-8')
        
        # Calculate valid signature for the modified payload
        valid_signature = calculate_hmac_signature(secret_bytes, modified_payload, config.signature_prefix)
        
        headers = {
            "Content-Type": "application/json",
            config.signature_header_name: valid_signature
        }
        
        response = await client.request(
            config.http_method,
            config.target_url,
            content=modified_payload,
            headers=headers,
            timeout=10.0
        )
        
        # Test passes if server accepts gracefully (2xx) or rejects unknown fields (4xx)
        # Test fails on 5xx (server error)
        if 200 <= response.status_code < 300:
            results.append({
                "category": "Elevation of Privilege",
                "name": "Superfluous Privileged Fields",
                "status": "PASS",
                "details": f"Server accepted request with extra fields (HTTP {response.status_code}) - likely ignores unknown fields"
            })
        elif 400 <= response.status_code < 500:
            results.append({
                "category": "Elevation of Privilege",
                "name": "Superfluous Privileged Fields",
                "status": "PASS",
                "details": f"Server rejected request with extra fields (HTTP {response.status_code})"
            })
        elif 500 <= response.status_code < 600:
            results.append({
                "category": "Elevation of Privilege",
                "name": "Superfluous Privileged Fields",
                "status": "FAIL",
                "details": f"Server error when processing extra fields (HTTP {response.status_code})",
                "risk": "Server crashes or errors on unexpected fields - may indicate poor input validation",
                "mitigation": "Implement strict schema validation and safely ignore or reject unknown fields"
            })
        else:
            results.append({
                "category": "Elevation of Privilege",
                "name": "Superfluous Privileged Fields",
                "status": "WARN",
                "details": f"Unexpected response: HTTP {response.status_code}"
            })
    except Exception as e:
        results.append({
            "category": "Elevation of Privilege",
            "name": "Superfluous Privileged Fields",
            "status": "WARN",
            "details": f"Test failed with error: {str(e)}"
        })
    
    # Test 2: Parameter pollution
    try:
        payload_dict = json.loads(config.sample_valid_payload) if config.sample_valid_payload else {}
        
        # Add duplicate/conflicting values
        payload_dict["user_id"] = "123"
        payload_dict["userId"] = "456"  # Common in case sensitivity issues
        payload_dict["USER_ID"] = "789"
        
        modified_payload = json.dumps(payload_dict).encode('utf-8')
        valid_signature = calculate_hmac_signature(secret_bytes, modified_payload, config.signature_prefix)
        
        headers = {
            "Content-Type": "application/json",
            config.signature_header_name: valid_signature
        }
        
        response = await client.request(
            config.http_method,
            config.target_url,
            content=modified_payload,
            headers=headers,
            timeout=10.0
        )
        
        if 200 <= response.status_code < 500:
            results.append({
                "category": "Elevation of Privilege",
                "name": "Parameter Pollution",
                "status": "PASS",
                "details": f"Server handled conflicting parameter names (HTTP {response.status_code})"
            })
        else:
            results.append({
                "category": "Elevation of Privilege",
                "name": "Parameter Pollution",
                "status": "WARN",
                "details": f"Server error with conflicting parameters (HTTP {response.status_code})"
            })
    except Exception as e:
        results.append({
            "category": "Elevation of Privilege",
            "name": "Parameter Pollution",
            "status": "WARN",
            "details": f"Test failed with error: {str(e)}"
        })
    
    return results
