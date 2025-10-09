"""Cryptographic utilities for webhook signature validation."""
import hmac
import hashlib


def calculate_hmac_signature(secret: bytes, payload: bytes, prefix: str = "sha256=") -> str:
    """
    Calculate HMAC-SHA256 signature for a payload.
    
    Args:
        secret: The shared secret key as bytes
        payload: The payload body as bytes
        prefix: Optional prefix for the signature (e.g., 'sha256=')
    
    Returns:
        The HMAC signature as a hex digest string, with optional prefix
    """
    signature = hmac.new(secret, payload, hashlib.sha256).hexdigest()
    return f"{prefix}{signature}" if prefix else signature


def verify_signature(secret: bytes, payload: bytes, provided_signature: str) -> bool:
    """
    Verify a provided HMAC signature against the expected signature.
    
    Args:
        secret: The shared secret key as bytes
        payload: The payload body as bytes
        provided_signature: The signature to verify
    
    Returns:
        True if signatures match, False otherwise
    """
    # Determine if there's a prefix
    prefix = ""
    if "=" in provided_signature:
        prefix = provided_signature.split("=")[0] + "="
    
    expected_signature = calculate_hmac_signature(secret, payload, prefix)
    return hmac.compare_digest(expected_signature, provided_signature)
