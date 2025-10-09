"""Configuration settings for the webhook security scanner."""
from pydantic import BaseModel, Field, HttpUrl
from typing import Optional, Dict, List


class ScannerSettings(BaseModel):
    """Configuration settings for webhook security scanning."""
    
    target_url: str = Field(
        ...,
        description="The webhook endpoint URL to test"
    )
    
    http_method: str = Field(
        default="POST",
        description="HTTP method to use (default: POST)"
    )
    
    shared_secret: Optional[str] = Field(
        default=None,
        description="The shared secret key for HMAC signature generation (optional)"
    )
    
    signature_header_name: str = Field(
        default="X-Webhook-Signature",
        description="The HTTP header name for the signature"
    )
    
    timestamp_header_name: Optional[str] = Field(
        default="X-Webhook-Timestamp",
        description="The HTTP header name for the timestamp (optional)"
    )
    
    sample_valid_payload: str = Field(
        default='{"event": "test", "data": "sample"}',
        description="A sample valid JSON payload for testing"
    )
    
    signature_prefix: str = Field(
        default="sha256=",
        description="Prefix for the signature (e.g., 'sha256=')"
    )
    
    custom_headers: Optional[Dict[str, str]] = Field(
        default=None,
        description="Additional custom headers to include in requests (e.g., {'X-API-Key': 'value', 'User-Agent': 'MyApp/1.0'})"
    )
    
    test_standards: List[str] = Field(
        default=["STRIDE"],
        description="Security testing standards to apply (STRIDE, PCI-DSS, OWASP, ISO27001, NIST)"
    )
    
    class Config:
        """Pydantic configuration."""
        json_schema_extra = {
            "example": {
                "target_url": "https://api.example.com/webhook",
                "http_method": "POST",
                "shared_secret": "your-secret-key",
                "signature_header_name": "X-Webhook-Signature",
                "timestamp_header_name": "X-Webhook-Timestamp",
                "sample_valid_payload": '{"event": "test", "data": "sample"}'
            }
        }
