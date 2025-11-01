"""
Injection Attack Tests for STRIDE Threat Model

Comprehensive tests for SQL, NoSQL, Command, XSS, Path Traversal, and Template injection.
"""

import json
from typing import Dict, List
import httpx
from ...utils.crypto import calculate_hmac_signature


def capture_response_data(response: httpx.Response) -> Dict:
    """
    Capture response data for later analysis.
    
    Args:
        response: HTTP response object
    
    Returns:
        Dictionary containing response details
    """
    return {
        "status_code": response.status_code,
        "headers": dict(response.headers),
        "body": response.text[:10000],  # Limit to 10KB to avoid memory issues
        "elapsed_ms": response.elapsed.total_seconds() * 1000
    }


# Injection test payloads
INJECTION_PAYLOADS = {
    "sql": [
        "' OR '1'='1",
        "admin'--",
        "' OR '1'='1' --",
        "1' UNION SELECT NULL--",
        "'; DROP TABLE users--",
        "1' AND '1'='1",
        "' OR 1=1--",
        "admin' OR '1'='1'/*",
    ],
    "nosql": [
        '{"$gt": ""}',
        '{"$ne": null}',
        '{"$where": "1==1"}',
        '{"$regex": ".*"}',
        '{"username": {"$ne": null}, "password": {"$ne": null}}',
    ],
    "command": [
        "; ls -la",
        "| cat /etc/passwd",
        "`whoami`",
        "$(whoami)",
        "&& dir",
        "; ping -c 10 127.0.0.1",
        "| nc -e /bin/sh 127.0.0.1 4444",
    ],
    "xss": [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg/onload=alert('XSS')>",
        "javascript:alert('XSS')",
        "<iframe src=javascript:alert('XSS')>",
        "<body onload=alert('XSS')>",
        "'-alert('XSS')-'",
        '"><script>alert(String.fromCharCode(88,83,83))</script>',
    ],
    "path_traversal": [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\config\\sam",
        "....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "../../../../../../etc/shadow",
    ],
    "template": [
        "{{7*7}}",
        "${7*7}",
        "<%= 7*7 %>",
        "{{config.items()}}",
        "${T(java.lang.Runtime).getRuntime().exec('calc')}",
        "#{7*7}",
    ],
}


async def run_injection_tests(config, client: httpx.AsyncClient) -> List[Dict]:
    """
    Run comprehensive injection security tests.
    
    Tests for various injection vulnerabilities by sending crafted payloads
    and checking if the server properly sanitizes/rejects them.
    
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
            "category": "STRIDE - C06 Injection Attacks",
            "name": "Injection Tests",
            "status": "WARN",
            "details": "Skipped - No shared secret provided. These tests require HMAC signature validation."
        })
        return results
    
    secret_bytes = config.shared_secret.encode('utf-8')
    
    # Test 1: SQL Injection in JSON fields
    try:
        sql_test_passed = True
        sql_details = []
        sql_responses = []
        
        # Parse user's payload
        try:
            base_payload = json.loads(config.sample_valid_payload)
        except:
            base_payload = {"data": "test"}
        
        for sql_payload in INJECTION_PAYLOADS["sql"][:3]:  # Test first 3
            # Inject SQL payload into all string fields in user's payload
            payload_dict = base_payload.copy()
            for key in payload_dict:
                if isinstance(payload_dict[key], str):
                    payload_dict[key] = sql_payload
            # Also add as new fields to test additional injection points
            payload_dict["_test_username"] = sql_payload
            payload_dict["_test_query"] = sql_payload
            
            payload_bytes = json.dumps(payload_dict).encode('utf-8')
            valid_signature = calculate_hmac_signature(secret_bytes, payload_bytes, config.signature_prefix)
            
            headers = {
                "Content-Type": "application/json",
                config.signature_header_name: valid_signature
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

            
            # Capture response for analysis
            response_data = capture_response_data(response)
            response_data["payload"] = sql_payload
            sql_responses.append(response_data)
            
            # Server should reject (4xx) or safely handle (2xx) but NOT crash (5xx)
            if 500 <= response.status_code < 600:
                sql_test_passed = False
                sql_details.append(f"SQL payload caused server error: {sql_payload[:30]}")
                break
            elif 200 <= response.status_code < 300:
                # Check response for SQL error messages
                response_text = response.text.lower()
                sql_keywords = ['sql', 'mysql', 'postgresql', 'oracle', 'syntax error', 'database']
                if any(keyword in response_text for keyword in sql_keywords):
                    sql_test_passed = False
                    sql_details.append(f"SQL error leaked in response")
                    break
        
        if sql_test_passed:
            results.append({
                "category": "STRIDE - C06 Injection Attacks",
                "name": "SQL Injection Resistance",
                "status": "PASS",
                "details": "Server handled SQL injection attempts without errors or information disclosure",
                "responses": sql_responses
            })
        else:
            results.append({
                "category": "STRIDE - C06 Injection Attacks",
                "name": "SQL Injection Resistance",
                "status": "FAIL",
                "details": f"SQL injection vulnerability detected: {', '.join(sql_details)}",
                "risk": "Attackers can manipulate database queries to access or modify data",
                "mitigation": "Use parameterized queries/prepared statements, never concatenate user input into SQL",
                "responses": sql_responses
            })
    except Exception as e:
        results.append({
            "category": "STRIDE - C06 Injection Attacks",
            "name": "SQL Injection Resistance",
            "status": "WARN",
            "details": f"Test failed with error: {str(e)}"
        })
    
    # Test 2: NoSQL Injection
    try:
        nosql_test_passed = True
        nosql_responses = []
        
        # Parse user's payload
        try:
            base_payload = json.loads(config.sample_valid_payload)
        except:
            base_payload = {"data": "test"}
        
        for nosql_payload in INJECTION_PAYLOADS["nosql"][:2]:
            # Inject NoSQL payload into user's payload
            payload_dict = base_payload.copy()
            for key in payload_dict:
                if isinstance(payload_dict[key], str):
                    payload_dict[key] = nosql_payload
            payload_dict["_test_filter"] = nosql_payload
            
            payload_bytes = json.dumps(payload_dict).encode('utf-8')
            valid_signature = calculate_hmac_signature(secret_bytes, payload_bytes, config.signature_prefix)
            
            headers = {
                "Content-Type": "application/json",
                config.signature_header_name: valid_signature
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

            
            if 500 <= response.status_code < 600:
                nosql_test_passed = False
                break
        
        if nosql_test_passed:
            results.append({
                "category": "STRIDE - C06 Injection Attacks",
                "name": "NoSQL Injection Resistance",
                "status": "PASS",
                "details": "Server handled NoSQL injection attempts safely",
                "response": response_data
            })
        else:
            results.append({
                "category": "STRIDE - C06 Injection Attacks",
                "name": "NoSQL Injection Resistance",
                "status": "FAIL",
                "details": "NoSQL injection caused server errors",
                "risk": "Attackers can bypass authentication or access unauthorized data in NoSQL databases",
                "mitigation": "Validate and sanitize all user input, use proper query builders, avoid direct object injection"
            })
    except Exception as e:
        results.append({
            "category": "STRIDE - C06 Injection Attacks",
            "name": "NoSQL Injection Resistance",
            "status": "WARN",
            "details": f"Test failed with error: {str(e)}"
        })
    
    # Test 3: Command Injection
    try:
        cmd_test_passed = True
        
        # Parse user's payload
        try:
            base_payload = json.loads(config.sample_valid_payload)
        except Exception as e:
            # If user's payload is invalid, use fallback
            base_payload = {"event": "test", "data": "sample"}
        
        for cmd_payload in INJECTION_PAYLOADS["command"][:3]:
            payload_dict = base_payload.copy()
            
            # Inject command payload into all string fields
            for key in payload_dict:
                if isinstance(payload_dict[key], str):
                    payload_dict[key] = cmd_payload
            
            # Add test-specific fields
            payload_dict["_test_filename"] = cmd_payload
            payload_dict["_test_command"] = cmd_payload
            
            payload_bytes = json.dumps(payload_dict).encode('utf-8')
            valid_signature = calculate_hmac_signature(secret_bytes, payload_bytes, config.signature_prefix)
            
            headers = {
                "Content-Type": "application/json",
                config.signature_header_name: valid_signature
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

            
            # Check for command execution evidence in response
            response_text = response.text.lower()
            cmd_keywords = ['root:', 'bin/bash', 'command not found', 'system32', 'volume']
            if any(keyword in response_text for keyword in cmd_keywords):
                cmd_test_passed = False
                break
        
        if cmd_test_passed:
            results.append({
                "category": "STRIDE - C06 Injection Attacks",
                "name": "Command Injection Resistance",
                "status": "PASS",
                "details": "Server handled command injection attempts safely",
                "response": response_data
            })
        else:
            results.append({
                "category": "STRIDE - C06 Injection Attacks",
                "name": "Command Injection Resistance",
                "status": "FAIL",
                "details": "Command injection may be possible - suspicious output detected",
                "risk": "Attackers can execute arbitrary system commands on the server",
                "mitigation": "Never pass user input to system commands, use safe APIs, validate and whitelist input"
            })
    except Exception as e:
        results.append({
            "category": "STRIDE - C06 Injection Attacks",
            "name": "Command Injection Resistance",
            "status": "WARN",
            "details": f"Test failed with error: {str(e)}"
        })
    
    # Test 4: XSS (Cross-Site Scripting)
    try:
        xss_test_passed = True
        reflected_xss = []
        
        # Parse user's payload
        try:
            base_payload = json.loads(config.sample_valid_payload)
        except Exception as e:
            base_payload = {"event": "test", "data": "sample"}
        
        for xss_payload in INJECTION_PAYLOADS["xss"][:3]:
            payload_dict = base_payload.copy()
            
            # Inject XSS payload into all string fields
            for key in payload_dict:
                if isinstance(payload_dict[key], str):
                    payload_dict[key] = xss_payload
            
            # Add test-specific fields
            payload_dict["_test_comment"] = xss_payload
            payload_dict["_test_message"] = xss_payload
            
            payload_bytes = json.dumps(payload_dict).encode('utf-8')
            valid_signature = calculate_hmac_signature(secret_bytes, payload_bytes, config.signature_prefix)
            
            headers = {
                "Content-Type": "application/json",
                config.signature_header_name: valid_signature
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

            
            # Check if XSS payload is reflected in response without encoding
            if xss_payload in response.text or '<script>' in response.text.lower():
                xss_test_passed = False
                reflected_xss.append(xss_payload[:30])
        
        if xss_test_passed:
            results.append({
                "category": "STRIDE - C06 Injection Attacks",
                "name": "XSS (Cross-Site Scripting) Protection",
                "status": "PASS",
                "details": "Server properly encodes output, no XSS payloads reflected"
            })
        else:
            results.append({
                "category": "STRIDE - C06 Injection Attacks",
                "name": "XSS (Cross-Site Scripting) Protection",
                "status": "FAIL",
                "details": f"XSS vulnerability detected - payloads reflected unencoded: {', '.join(reflected_xss)}",
                "risk": "Attackers can inject malicious scripts to steal user data or perform actions on behalf of users",
                "mitigation": "Encode all user input in output, use Content-Security-Policy headers, validate input"
            })
    except Exception as e:
        results.append({
            "category": "STRIDE - C06 Injection Attacks",
            "name": "XSS (Cross-Site Scripting) Protection",
            "status": "WARN",
            "details": f"Test failed with error: {str(e)}"
        })
    
    # Test 5: Path Traversal
    try:
        path_test_passed = True
        
        # Parse user's payload
        try:
            base_payload = json.loads(config.sample_valid_payload)
        except Exception as e:
            base_payload = {"event": "test", "data": "sample"}
        
        for path_payload in INJECTION_PAYLOADS["path_traversal"][:3]:
            payload_dict = base_payload.copy()
            
            # Inject path traversal payload into all string fields
            for key in payload_dict:
                if isinstance(payload_dict[key], str):
                    payload_dict[key] = path_payload
            
            # Add test-specific fields
            payload_dict["_test_filename"] = path_payload
            payload_dict["_test_path"] = path_payload
            
            payload_bytes = json.dumps(payload_dict).encode('utf-8')
            valid_signature = calculate_hmac_signature(secret_bytes, payload_bytes, config.signature_prefix)
            
            headers = {
                "Content-Type": "application/json",
                config.signature_header_name: valid_signature
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

            
            # Check for file content in response
            response_text = response.text.lower()
            path_keywords = ['root:', '[boot loader]', 'system32', '/etc/', 'windows']
            if any(keyword in response_text for keyword in path_keywords):
                path_test_passed = False
                break
        
        if path_test_passed:
            results.append({
                "category": "STRIDE - C06 Injection Attacks",
                "name": "Path Traversal Protection",
                "status": "PASS",
                "details": "Server protected against path traversal attempts",
                "response": response_data
            })
        else:
            results.append({
                "category": "STRIDE - C06 Injection Attacks",
                "name": "Path Traversal Protection",
                "status": "FAIL",
                "details": "Path traversal vulnerability detected - system files may be accessible",
                "risk": "Attackers can read sensitive files from the server file system",
                "mitigation": "Validate file paths, use whitelists, avoid direct file path construction from user input"
            })
    except Exception as e:
        results.append({
            "category": "STRIDE - C06 Injection Attacks",
            "name": "Path Traversal Protection",
            "status": "WARN",
            "details": f"Test failed with error: {str(e)}"
        })
    
    # Test 6: Template Injection
    try:
        template_test_passed = True
        
        # Parse user's payload
        try:
            base_payload = json.loads(config.sample_valid_payload)
        except Exception as e:
            base_payload = {"event": "test", "data": "sample"}
        
        for template_payload in INJECTION_PAYLOADS["template"][:3]:
            payload_dict = base_payload.copy()
            
            # Inject template payload into all string fields
            for key in payload_dict:
                if isinstance(payload_dict[key], str):
                    payload_dict[key] = template_payload
            
            # Add test-specific fields
            payload_dict["_test_template"] = template_payload
            payload_dict["_test_message"] = template_payload
            
            payload_bytes = json.dumps(payload_dict).encode('utf-8')
            valid_signature = calculate_hmac_signature(secret_bytes, payload_bytes, config.signature_prefix)
            
            headers = {
                "Content-Type": "application/json",
                config.signature_header_name: valid_signature
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

            
            # Check if template was evaluated (e.g., {{7*7}} becomes 49)
            if '49' in response.text or 'config' in response.text.lower():
                template_test_passed = False
                break
        
        if template_test_passed:
            results.append({
                "category": "STRIDE - C06 Injection Attacks",
                "name": "Template Injection Protection",
                "status": "PASS",
                "details": "Server protected against template injection",
                "response": response_data
            })
        else:
            results.append({
                "category": "STRIDE - C06 Injection Attacks",
                "name": "Template Injection Protection",
                "status": "FAIL",
                "details": "Template injection vulnerability detected",
                "risk": "Attackers can execute arbitrary code through template engines",
                "mitigation": "Use safe template rendering, sandbox template execution, validate template input"
            })
    except Exception as e:
        results.append({
            "category": "STRIDE - C06 Injection Attacks",
            "name": "Template Injection Protection",
            "status": "WARN",
            "details": f"Test failed with error: {str(e)}"
        })
    
    return results
