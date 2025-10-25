"""
Pydantic Models for Webhook Security Scanner API
"""
from pydantic import BaseModel, Field
from typing import Optional, List, Dict


class FieldSchema(BaseModel):
    """Model for field definition in payload schema."""
    name: str = Field(..., description="Field name")
    type: str = Field(..., description="Data type: string, integer, float, boolean, email, url, json, array")
    sample_value: Optional[str] = Field(default=None, description="Sample value for this field")


class TestPayload(BaseModel):
    """Model for individual test payload."""
    name: str = Field(..., description="Name/description of the payload")
    data: str = Field(..., description="Payload data (JSON string)")


class ScanRequest(BaseModel):
    """Request model for security scan."""
    target_url: str = Field(..., description="Webhook endpoint URL to scan")
    shared_secret: Optional[str] = Field(default=None, description="Shared secret for HMAC signatures (optional)")
    http_method: str = Field(default="POST", description="HTTP method")
    signature_header_name: str = Field(default="X-Webhook-Signature", description="Signature header name")
    timestamp_header_name: Optional[str] = Field(default="X-Webhook-Timestamp", description="Timestamp header name")
    sample_valid_payload: str = Field(default='{"event": "test", "data": "sample"}', description="Sample payload (fallback)")
    payload_schema: Optional[List[FieldSchema]] = Field(default=None, description="Field-based schema for automatic test generation")
    test_payloads: Optional[List[TestPayload]] = Field(default=None, description="List of test payloads to use (deprecated)")
    signature_prefix: str = Field(default="sha256=", description="Signature prefix")
    custom_headers: Optional[Dict[str, str]] = Field(default=None, description="Additional custom headers")
    test_standards: Optional[List[str]] = Field(
        default=None,
        description="Security standards to test (STRIDE, PCI-DSS, OWASP). If empty, defaults to STRIDE."
    )


class ScanResponse(BaseModel):
    """Response model for security scan."""
    scan_id: str
    target_url: str
    timestamp: str
    total_tests: int
    passed: int
    failed: int
    warnings: int
    security_score: float = Field(default=10.0, description="Security score from 0-10")
    score_rating: str = Field(default="🟢 EXCELLENT", description="Rating based on score")
    results: List[Dict]
    summary: str
