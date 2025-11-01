"""Helper functions for test result formatting and payload handling."""
import json
from typing import Dict, Any, Union


def add_payload_to_result(result: Dict[str, Any], payload: Union[str, bytes, dict, None], config=None) -> Dict[str, Any]:
    """
    Add payloadTest field to a test result dictionary.
    
    Args:
        result: The test result dictionary
        payload: The payload used in the test (can be string, bytes, dict, or None)
        config: Optional ScannerSettings config object (used as fallback)
    
    Returns:
        The result dictionary with payloadTest field added
    
    Examples:
        >>> result = {"category": "Test", "name": "Test Name", "status": "PASS"}
        >>> add_payload_to_result(result, {"test": "data"})
        {"category": "Test", "name": "Test Name", "status": "PASS", "payloadTest": '{"test": "data"}'}
        
        >>> add_payload_to_result(result, b'{"test": "data"}')
        {"category": "Test", "name": "Test Name", "status": "PASS", "payloadTest": '{"test": "data"}'}
    """
    if payload is None:
        # Use config.sample_valid_payload as fallback
        if config and hasattr(config, 'sample_valid_payload'):
            result["payloadTest"] = config.sample_valid_payload
        else:
            result["payloadTest"] = '{"event": "test", "data": "sample"}'
    elif isinstance(payload, bytes):
        # Decode bytes to string
        result["payloadTest"] = payload.decode('utf-8')
    elif isinstance(payload, dict):
        # Convert dict to JSON string
        result["payloadTest"] = json.dumps(payload)
    else:
        # Already a string or other type
        result["payloadTest"] = str(payload)
    
    return result


def create_test_result(
    category: str,
    name: str,
    status: str,
    details: str,
    payload: Union[str, bytes, dict, None] = None,
    config=None,
    **kwargs
) -> Dict[str, Any]:
    """
    Create a test result dictionary with all standard fields including payloadTest.
    
    Args:
        category: Test category (e.g., "STRIDE - Spoofing")
        name: Test name (e.g., "Request with No Signature")
        status: Test status ("PASS", "FAIL", or "WARN")
        details: Test details/description
        payload: The payload used in the test
        config: Optional ScannerSettings config object
        **kwargs: Additional fields (risk, mitigation, response, etc.)
    
    Returns:
        Complete test result dictionary with payloadTest
    
    Examples:
        >>> create_test_result(
        ...     category="Injection Attacks",
        ...     name="SQL Injection Resistance",
        ...     status="PASS",
        ...     details="Server handled SQL injection attempts safely",
        ...     payload={"test": "data"},
        ...     risk="High risk of data breach",
        ...     mitigation="Use parameterized queries"
        ... )
    """
    result = {
        "category": category,
        "name": name,
        "status": status,
        "details": details
    }
    
    # Add optional fields
    for key, value in kwargs.items():
        if value is not None:
            result[key] = value
    
    # Add payloadTest
    add_payload_to_result(result, payload, config)
    
    return result


def format_payload_for_display(payload: Union[str, bytes, dict, None], max_length: int = 100) -> str:
    """
    Format payload for display in test results (truncate if too long).
    
    Args:
        payload: The payload to format
        max_length: Maximum length for display
    
    Returns:
        Formatted payload string
    """
    if payload is None:
        return "None"
    
    if isinstance(payload, bytes):
        payload_str = payload.decode('utf-8', errors='replace')
    elif isinstance(payload, dict):
        payload_str = json.dumps(payload)
    else:
        payload_str = str(payload)
    
    if len(payload_str) > max_length:
        return payload_str[:max_length] + "..."
    
    return payload_str
