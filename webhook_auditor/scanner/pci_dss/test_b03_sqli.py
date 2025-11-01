"""PCI DSS Requirement 6: SQL Injection Protection test."""
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


async def test_sql_injection_protection(config: ScannerSettings) -> Dict:
    """
    Test if endpoint properly handles SQL injection attempts.
    PCI DSS Requirement 6.5.1
    """
    try:
        import json
        
        # SQL injection payloads
        sql_injection_values = [
            "' OR '1'='1",
            "test'; DROP TABLE users; --"
        ]
        
        headers = config.custom_headers.copy() if config.custom_headers else {}
        
        async with httpx.AsyncClient(verify=False) as client:
            vulnerable = False
            for sql_payload in sql_injection_values:
                # Use user's configured payload as base
                try:
                    base_payload = json.loads(config.sample_valid_payload)
                except:
                    base_payload = {"event": "test", "data": "sample"}
                
                payload = base_payload.copy()
                
                # Inject SQL payload into all string fields
                for key in payload:
                    if isinstance(payload[key], str):
                        payload[key] = sql_payload
                
                # Add test field
                payload["_test_sql"] = sql_payload
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

                    
                    # Check for SQL error messages in response
                    response_text = response.text.lower()
                    sql_errors = ["sql", "syntax error", "mysql", "postgresql", "ora-", "database error"]
                    if any(error in response_text for error in sql_errors):
                        vulnerable = True
                        break
                except:
                    pass
            
            if vulnerable:
                return {
                    "category": "PCI DSS - B03 SQL Injection Protection",
                    "name": "SQL Injection Protection",
                    "status": "FAIL",
                    "details": "Endpoint may be vulnerable to SQL injection. Database error messages detected.",
                    "risk": "Attackers could access, modify, or delete cardholder data.",
                    "mitigation": "Use parameterized queries and input validation. Never concatenate user input into SQL queries."
                }
            else:
                return {
                    "category": "PCI DSS - B03 SQL Injection Protection",
                    "name": "SQL Injection Protection",
                    "status": "PASS",
                    "details": "No SQL injection vulnerabilities detected in basic tests.",
                    "risk": None,
                    "mitigation": None
                }
    except Exception as e:
        return {
            "category": "PCI DSS - B03 SQL Injection Protection",
            "name": "SQL Injection Protection",
            "status": "WARN",
            "details": f"Error testing SQL injection protection: {str(e)}",
            "risk": "Unable to verify input validation.",
            "mitigation": "Ensure proper input validation and parameterized queries are used."
        }
