"""
FastAPI Web Interface for Webhook Security Scanner

A web-based interface to run security scans against webhook endpoints.
"""
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl, Field
from typing import Optional, List, Dict
import asyncio
import httpx
import json
from datetime import datetime

# Import scanner components
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from webhook_auditor.scanner.config import ScannerSettings
from webhook_auditor.scanner.orchestrator import run_all_tests as run_stride_tests


app = FastAPI(
    title="Webhook Security Scanner API",
    description="STRIDE-based security testing for webhook endpoints",
    version="1.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


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
    results: List[Dict]
    summary: str


# Store scan results in memory (in production, use a database)
scan_results_cache = {}


@app.get("/", response_class=HTMLResponse)
async def root():
    """Serve the main web interface with Bootstrap."""
    return """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Webhook Security Scanner</title>
        
        <!-- Bootstrap CSS -->
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <!-- Bootstrap Icons -->
        <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.0/font/bootstrap-icons.css" rel="stylesheet">
        <!-- Google Fonts -->
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
        
        <style>
            * { font-family: 'Inter', sans-serif; }
            
            body {
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                padding: 20px 0;
            }
            
            .main-card {
                background: white;
                border-radius: 20px;
                box-shadow: 0 20px 60px rgba(0,0,0,0.3);
                overflow: hidden;
                margin-bottom: 30px;
            }
            
            .header-section {
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                padding: 40px;
                text-align: center;
            }
            
            .header-section h1 {
                font-size: 2.5rem;
                font-weight: 700;
                margin-bottom: 10px;
            }
            
            .header-section p {
                font-size: 1.1rem;
                opacity: 0.9;
                margin-bottom: 0;
            }
            
            .content-section {
                padding: 40px;
            }
            
            .form-label {
                font-weight: 600;
                color: #333;
                margin-bottom: 8px;
            }
            
            .form-control:focus, .form-select:focus {
                border-color: #667eea;
                box-shadow: 0 0 0 0.25rem rgba(102, 126, 234, 0.25);
            }
            
            .btn-scan {
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                border: none;
                padding: 15px;
                font-weight: 600;
                font-size: 1.1rem;
                transition: transform 0.2s;
            }
            
            .btn-scan:hover {
                transform: translateY(-2px);
                box-shadow: 0 10px 20px rgba(102, 126, 234, 0.4);
            }
            
            .stat-card {
                text-align: center;
                padding: 25px;
                border-radius: 15px;
                background: white;
                border: 2px solid #e9ecef;
                transition: all 0.3s;
            }
            
            .stat-card:hover {
                transform: translateY(-5px);
                box-shadow: 0 10px 25px rgba(0,0,0,0.1);
            }
            
            .stat-number {
                font-size: 3rem;
                font-weight: 700;
                margin-bottom: 5px;
            }
            
            .stat-label {
                color: #6c757d;
                font-size: 0.95rem;
                font-weight: 500;
                text-transform: uppercase;
            }
            
            .result-card {
                border-left: 5px solid #dee2e6;
                margin-bottom: 20px;
                transition: all 0.3s;
            }
            
            .result-card:hover {
                transform: translateX(5px);
                box-shadow: 0 5px 15px rgba(0,0,0,0.1);
            }
            
            .result-card.pass { border-left-color: #28a745; }
            .result-card.fail { border-left-color: #dc3545; }
            .result-card.warn { border-left-color: #ffc107; }
            
            .badge-category {
                font-size: 0.75rem;
                padding: 5px 12px;
                border-radius: 20px;
                font-weight: 600;
            }
            
            .spinner-border-custom {
                width: 3rem;
                height: 3rem;
                border-width: 0.3rem;
            }
            
            .advanced-options {
                background: #f8f9fa;
                padding: 20px;
                border-radius: 10px;
                margin-top: 20px;
            }
            
            .test-category-checkbox {
                margin-right: 15px;
            }
            
            #results {
                animation: fadeIn 0.5s;
            }
            
            @keyframes fadeIn {
                from { opacity: 0; transform: translateY(20px); }
                to { opacity: 1; transform: translateY(0); }
            }
            
            .progress-bar-animated {
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            }
            
            .alert-custom {
                border-left: 5px solid;
                border-radius: 10px;
            }
            
            .field-item {
                background: #f8f9fa;
                transition: all 0.3s ease;
            }
            
            .field-item:hover {
                background: #e9ecef;
                box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            }
            
            .field-name, .field-type, .field-value {
                font-weight: 500;
            }
            
            .remove-field {
                transition: all 0.2s;
            }
            
            .remove-field:hover {
                transform: scale(1.1);
            }
            
            .small {
                font-size: 0.85rem;
                font-weight: 600;
                color: #495057;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <!-- Main Card -->
            <div class="main-card">
                <!-- Header -->
                <div class="header-section">
                    <h1><i class="bi bi-shield-lock"></i> Webhook Security Scanner</h1>
                    <p>STRIDE, PCI DSS & OWASP Top 10 security testing</p>
                </div>
                
                <!-- Content -->
                <div class="content-section">
                    <!-- Scan Form -->
                    <form id="scanForm">
                        <div class="row">
                            <div class="col-md-12 mb-3">
                                <label for="target_url" class="form-label">
                                    <i class="bi bi-bullseye"></i> Target Webhook URL *
                                </label>
                                <input type="url" class="form-control form-control-lg" id="target_url" 
                                       placeholder="https://api.example.com/webhook" required>
                                <div class="form-text">Enter the webhook endpoint you want to test</div>
                            </div>
                        </div>
                        
                        <div class="row">
                            <div class="col-md-6 mb-3">
                                <label for="shared_secret" class="form-label">
                                    <i class="bi bi-key"></i> Shared Secret <small class="text-muted">(optional)</small>
                                </label>
                                <div class="input-group">
                                    <input type="password" class="form-control" id="shared_secret" 
                                           placeholder="your-webhook-secret">
                                    <button class="btn btn-outline-secondary" type="button" id="toggleSecret">
                                        <i class="bi bi-eye"></i>
                                    </button>
                                </div>
                                <div class="form-text">Leave empty if webhook doesn't require authentication</div>
                            </div>
                            
                            <div class="col-md-6 mb-3">
                                <label for="http_method" class="form-label">
                                    <i class="bi bi-arrow-left-right"></i> HTTP Method
                                </label>
                                <select class="form-select" id="http_method">
                                    <option value="POST" selected>POST</option>
                                    <option value="PUT">PUT</option>
                                    <option value="PATCH">PATCH</option>
                                </select>
                            </div>
                        </div>
                        
                        <div class="row">
                            <div class="col-md-12 mb-3">
                                <label class="form-label">
                                    <i class="bi bi-file-code"></i> Payload Schema (Field Definitions)
                                </label>
                                <div class="alert alert-info">
                                    <i class="bi bi-info-circle"></i> Define your webhook payload structure. 
                                    The scanner will automatically generate injection test cases for each field based on its data type.
                                </div>
                                <div id="fields_container">
                                    <!-- Field items will be added here -->
                                    <div class="field-item border rounded p-3 mb-2">
                                        <div class="row align-items-end">
                                            <div class="col-md-4">
                                                <label class="form-label small">Field Name</label>
                                                <input type="text" class="form-control form-control-sm field-name" 
                                                       placeholder="e.g., event" value="event">
                                            </div>
                                            <div class="col-md-3">
                                                <label class="form-label small">Data Type</label>
                                                <select class="form-select form-select-sm field-type">
                                                    <option value="string" selected>String</option>
                                                    <option value="integer">Integer</option>
                                                    <option value="float">Float</option>
                                                    <option value="boolean">Boolean</option>
                                                    <option value="email">Email</option>
                                                    <option value="url">URL</option>
                                                    <option value="json">JSON Object</option>
                                                    <option value="array">Array</option>
                                                </select>
                                            </div>
                                            <div class="col-md-4">
                                                <label class="form-label small">Sample Value</label>
                                                <input type="text" class="form-control form-control-sm field-value" 
                                                       placeholder="e.g., user.created" value="user.created">
                                            </div>
                                            <div class="col-md-1">
                                                <button type="button" class="btn btn-sm btn-outline-danger remove-field w-100">
                                                    <i class="bi bi-trash"></i>
                                                </button>
                                            </div>
                                        </div>
                                    </div>
                                    <div class="field-item border rounded p-3 mb-2">
                                        <div class="row align-items-end">
                                            <div class="col-md-4">
                                                <label class="form-label small">Field Name</label>
                                                <input type="text" class="form-control form-control-sm field-name" 
                                                       placeholder="e.g., user_id" value="user_id">
                                            </div>
                                            <div class="col-md-3">
                                                <label class="form-label small">Data Type</label>
                                                <select class="form-select form-select-sm field-type">
                                                    <option value="string">String</option>
                                                    <option value="integer" selected>Integer</option>
                                                    <option value="float">Float</option>
                                                    <option value="boolean">Boolean</option>
                                                    <option value="email">Email</option>
                                                    <option value="url">URL</option>
                                                    <option value="json">JSON Object</option>
                                                    <option value="array">Array</option>
                                                </select>
                                            </div>
                                            <div class="col-md-4">
                                                <label class="form-label small">Sample Value</label>
                                                <input type="text" class="form-control form-control-sm field-value" 
                                                       placeholder="e.g., 12345" value="12345">
                                            </div>
                                            <div class="col-md-1">
                                                <button type="button" class="btn btn-sm btn-outline-danger remove-field w-100">
                                                    <i class="bi bi-trash"></i>
                                                </button>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                                <button type="button" class="btn btn-sm btn-outline-primary mt-2" id="add_field">
                                    <i class="bi bi-plus-circle"></i> Add Field
                                </button>
                                <div class="form-text mt-2">
                                    <strong>Auto-generated tests per field:</strong><br>
                                    • <strong>String</strong>: SQL injection, XSS, command injection, path traversal, LDAP injection<br>
                                    • <strong>Integer</strong>: Negative values, overflow, type confusion, SQL injection<br>
                                    • <strong>Email/URL</strong>: Format validation, SSRF, injection<br>
                                    • All fields tested with null, empty, special characters, and boundary values
                                </div>
                            </div>
                        </div>
                        
                        <!-- Advanced Options -->
                        <div class="mb-3">
                            <button class="btn btn-link" type="button" data-bs-toggle="collapse" 
                                    data-bs-target="#advancedOptions">
                                <i class="bi bi-gear"></i> Advanced Options
                            </button>
                        </div>
                        
                        <div class="collapse advanced-options" id="advancedOptions">
                            <div class="row">
                                <div class="col-md-6 mb-3">
                                    <label for="signature_header" class="form-label">Signature Header Name</label>
                                    <input type="text" class="form-control" id="signature_header" 
                                           value="X-Webhook-Signature">
                                </div>
                                
                                <div class="col-md-6 mb-3">
                                    <label for="signature_prefix" class="form-label">Signature Prefix</label>
                                    <input type="text" class="form-control" id="signature_prefix" 
                                           value="sha256=">
                                </div>
                            </div>
                            
                            <div class="row">
                                <div class="col-md-6 mb-3">
                                    <label for="timestamp_header" class="form-label">Timestamp Header Name</label>
                                    <input type="text" class="form-control" id="timestamp_header" 
                                           value="X-Webhook-Timestamp">
                                </div>
                            </div>
                            
                            <div class="mb-3">
                                <label for="custom_headers" class="form-label">
                                    <i class="bi bi-plus-circle"></i> Custom Headers (JSON)
                                </label>
                                <textarea class="form-control font-monospace" id="custom_headers" rows="3" 
                                          placeholder='{"X-API-Key": "your-key", "User-Agent": "MyApp/1.0"}'></textarea>
                                <div class="form-text">
                                    Add extra headers as JSON object. Useful for API keys, tracking headers, etc.
                                </div>
                            </div>
                            
                            <div class="mb-3">
                                <label class="form-label">
                                    <i class="bi bi-shield-check"></i> Security Standards to Test
                                </label>
                                <div>
                                    <div class="form-check form-check-inline test-category-checkbox">
                                        <input class="form-check-input" type="checkbox" id="std_stride" value="STRIDE" checked>
                                        <label class="form-check-label" for="std_stride">
                                            <strong>STRIDE</strong> <small class="text-muted">(12 tests)</small>
                                        </label>
                                    </div>
                                    <div class="form-check form-check-inline test-category-checkbox">
                                        <input class="form-check-input" type="checkbox" id="std_pci" value="PCI-DSS">
                                        <label class="form-check-label" for="std_pci">
                                            <strong>PCI DSS</strong> <small class="text-muted">(7 tests)</small>
                                        </label>
                                    </div>
                                    <div class="form-check form-check-inline test-category-checkbox">
                                        <input class="form-check-input" type="checkbox" id="std_owasp" value="OWASP">
                                        <label class="form-check-label" for="std_owasp">
                                            <strong>OWASP Top 10</strong> <small class="text-muted">(9 tests)</small>
                                        </label>
                                    </div>
                                </div>
                                <div class="form-text mt-2">
                                    <strong>STRIDE:</strong> Spoofing, Tampering, Repudiation, Info Disclosure, DoS, Privilege<br>
                                    <strong>PCI DSS:</strong> Payment Card Industry compliance tests<br>
                                    <strong>OWASP:</strong> OWASP Top 10 web security risks
                                </div>
                            </div>
                        </div>
                        
                        <button type="submit" class="btn btn-primary btn-scan w-100" id="scanBtn">
                            <i class="bi bi-play-circle"></i> Start Security Scan
                        </button>
                    </form>
                    
                    <!-- Loading Indicator -->
                    <div class="text-center py-5 d-none" id="loading">
                        <div class="spinner-border spinner-border-custom text-primary" role="status">
                            <span class="visually-hidden">Loading...</span>
                        </div>
                        <div class="mt-3">
                            <h5>Running security tests...</h5>
                            <p class="text-muted">This may take 30-60 seconds</p>
                            <div class="progress mx-auto" style="max-width: 400px;">
                                <div class="progress-bar progress-bar-striped progress-bar-animated" 
                                     role="progressbar" style="width: 100%"></div>
                            </div>
                        </div>
                    </div>
                    
                    <!-- Results Section -->
                    <div class="d-none mt-5" id="results">
                        <hr class="my-4">
                        
                        <!-- Summary -->
                        <div class="mb-4">
                            <h2><i class="bi bi-graph-up"></i> Scan Results</h2>
                            <div class="row g-3 mt-2">
                                <div class="col-md-4">
                                    <div class="stat-card">
                                        <div class="stat-number text-success" id="passedCount">0</div>
                                        <div class="stat-label">Passed</div>
                                    </div>
                                </div>
                                <div class="col-md-4">
                                    <div class="stat-card">
                                        <div class="stat-number text-danger" id="failedCount">0</div>
                                        <div class="stat-label">Failed</div>
                                    </div>
                                </div>
                                <div class="col-md-4">
                                    <div class="stat-card">
                                        <div class="stat-number text-warning" id="warnCount">0</div>
                                        <div class="stat-label">Warnings</div>
                                    </div>
                                </div>
                            </div>
                            
                            <div class="alert alert-custom mt-4" id="scanSummary" role="alert"></div>
                        </div>
                        
                        <!-- Test Results -->
                        <div id="resultsList"></div>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Bootstrap JS -->
        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
        
        <script>
            // Add/Remove Field functionality
            let fieldCounter = 2;
            
            document.getElementById('add_field').addEventListener('click', function() {
                fieldCounter++;
                const container = document.getElementById('fields_container');
                const newField = document.createElement('div');
                newField.className = 'field-item border rounded p-3 mb-2';
                newField.innerHTML = `
                    <div class="row align-items-end">
                        <div class="col-md-4">
                            <label class="form-label small">Field Name</label>
                            <input type="text" class="form-control form-control-sm field-name" 
                                   placeholder="e.g., email">
                        </div>
                        <div class="col-md-3">
                            <label class="form-label small">Data Type</label>
                            <select class="form-select form-select-sm field-type">
                                <option value="string" selected>String</option>
                                <option value="integer">Integer</option>
                                <option value="float">Float</option>
                                <option value="boolean">Boolean</option>
                                <option value="email">Email</option>
                                <option value="url">URL</option>
                                <option value="json">JSON Object</option>
                                <option value="array">Array</option>
                            </select>
                        </div>
                        <div class="col-md-4">
                            <label class="form-label small">Sample Value</label>
                            <input type="text" class="form-control form-control-sm field-value" 
                                   placeholder="Sample value">
                        </div>
                        <div class="col-md-1">
                            <button type="button" class="btn btn-sm btn-outline-danger remove-field w-100">
                                <i class="bi bi-trash"></i>
                            </button>
                        </div>
                    </div>
                `;
                container.appendChild(newField);
            });
            
            // Remove field (event delegation)
            document.getElementById('fields_container').addEventListener('click', function(e) {
                if (e.target.closest('.remove-field')) {
                    const fieldItems = document.querySelectorAll('.field-item');
                    if (fieldItems.length > 1) {
                        e.target.closest('.field-item').remove();
                    } else {
                        alert('You must have at least one field!');
                    }
                }
            });
            
            // Toggle password visibility
            document.getElementById('toggleSecret').addEventListener('click', function() {
                const secretInput = document.getElementById('shared_secret');
                const icon = this.querySelector('i');
                if (secretInput.type === 'password') {
                    secretInput.type = 'text';
                    icon.classList.remove('bi-eye');
                    icon.classList.add('bi-eye-slash');
                } else {
                    secretInput.type = 'password';
                    icon.classList.remove('bi-eye-slash');
                    icon.classList.add('bi-eye');
                }
            });
            
            // Form submission
            document.getElementById('scanForm').addEventListener('submit', async (e) => {
                e.preventDefault();
                
                // Get selected test standards
                const standards = [];
                document.querySelectorAll('input[type="checkbox"][id^="std_"]:checked').forEach(cb => {
                    standards.push(cb.value);
                });
                
                // Collect all field definitions
                const fields = [];
                document.querySelectorAll('.field-item').forEach(item => {
                    const name = item.querySelector('.field-name').value.trim();
                    const type = item.querySelector('.field-type').value;
                    const value = item.querySelector('.field-value').value.trim();
                    
                    if (name) {
                        fields.push({
                            name: name,
                            type: type,
                            sample_value: value || null
                        });
                    }
                });
                
                if (fields.length === 0) {
                    alert('Please define at least one field!');
                    return;
                }
                
                // Build a sample payload from fields
                const samplePayload = {};
                fields.forEach(field => {
                    if (field.sample_value) {
                        // Try to convert to appropriate type
                        if (field.type === 'integer') {
                            samplePayload[field.name] = parseInt(field.sample_value) || 0;
                        } else if (field.type === 'float') {
                            samplePayload[field.name] = parseFloat(field.sample_value) || 0.0;
                        } else if (field.type === 'boolean') {
                            samplePayload[field.name] = field.sample_value.toLowerCase() === 'true';
                        } else if (field.type === 'json') {
                            try {
                                samplePayload[field.name] = JSON.parse(field.sample_value);
                            } catch {
                                samplePayload[field.name] = {};
                            }
                        } else if (field.type === 'array') {
                            try {
                                samplePayload[field.name] = JSON.parse(field.sample_value);
                            } catch {
                                samplePayload[field.name] = [];
                            }
                        } else {
                            samplePayload[field.name] = field.sample_value;
                        }
                    } else {
                        samplePayload[field.name] = null;
                    }
                });
                
                // Prepare request data
                const formData = {
                    target_url: document.getElementById('target_url').value,
                    http_method: document.getElementById('http_method').value,
                    sample_valid_payload: JSON.stringify(samplePayload),
                    payload_schema: fields,  // Send field schema
                    signature_header_name: document.getElementById('signature_header').value,
                    signature_prefix: document.getElementById('signature_prefix').value,
                    timestamp_header_name: document.getElementById('timestamp_header').value,
                };
                
                // Add shared secret if provided
                const sharedSecret = document.getElementById('shared_secret').value.trim();
                if (sharedSecret) {
                    formData.shared_secret = sharedSecret;
                }
                
                // Add custom headers if provided
                const customHeadersText = document.getElementById('custom_headers').value.trim();
                if (customHeadersText) {
                    try {
                        formData.custom_headers = JSON.parse(customHeadersText);
                    } catch (e) {
                        alert('Invalid JSON format for Custom Headers. Please check and try again.');
                        return;
                    }
                }
                
                // Add test standards if selected
                if (standards.length > 0) {
                    formData.test_standards = standards;
                }
                
                // Show loading, hide results
                document.getElementById('loading').classList.remove('d-none');
                document.getElementById('results').classList.add('d-none');
                document.getElementById('scanBtn').disabled = true;
                
                try {
                    const response = await fetch('/api/scan', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(formData)
                    });
                    
                    const data = await response.json();
                    
                    // Hide loading
                    document.getElementById('loading').classList.add('d-none');
                    document.getElementById('scanBtn').disabled = false;
                    
                    if (response.ok) {
                        displayResults(data);
                    } else {
                        alert('Error: ' + data.detail);
                    }
                } catch (error) {
                    document.getElementById('loading').classList.add('d-none');
                    document.getElementById('scanBtn').disabled = false;
                    alert('Error: ' + error.message);
                }
            });
            
            function displayResults(data) {
                // Show results section
                document.getElementById('results').classList.remove('d-none');
                
                // Update statistics
                document.getElementById('passedCount').textContent = data.passed;
                document.getElementById('failedCount').textContent = data.failed;
                document.getElementById('warnCount').textContent = data.warnings;
                
                // Update summary
                const summaryEl = document.getElementById('scanSummary');
                summaryEl.textContent = data.summary;
                
                if (data.failed === 0) {
                    summaryEl.className = 'alert alert-custom alert-success';
                    summaryEl.style.borderLeftColor = '#28a745';
                    summaryEl.innerHTML = '<i class="bi bi-check-circle-fill"></i> ' + data.summary;
                } else if (data.failed <= 2) {
                    summaryEl.className = 'alert alert-custom alert-warning';
                    summaryEl.style.borderLeftColor = '#ffc107';
                    summaryEl.innerHTML = '<i class="bi bi-exclamation-triangle-fill"></i> ' + data.summary;
                } else {
                    summaryEl.className = 'alert alert-custom alert-danger';
                    summaryEl.style.borderLeftColor = '#dc3545';
                    summaryEl.innerHTML = '<i class="bi bi-x-circle-fill"></i> ' + data.summary;
                }
                
                // Display test results
                const resultsList = document.getElementById('resultsList');
                resultsList.innerHTML = '';
                
                data.results.forEach(result => {
                    const card = document.createElement('div');
                    card.className = `card result-card ${result.status.toLowerCase()} mb-3`;
                    
                    let badgeClass = 'bg-secondary';
                    let icon = 'info-circle';
                    
                    if (result.status === 'PASS') {
                        badgeClass = 'bg-success';
                        icon = 'check-circle-fill';
                    } else if (result.status === 'FAIL') {
                        badgeClass = 'bg-danger';
                        icon = 'x-circle-fill';
                    } else if (result.status === 'WARN') {
                        badgeClass = 'bg-warning text-dark';
                        icon = 'exclamation-triangle-fill';
                    }
                    
                    let cardBody = `
                        <div class="card-body">
                            <div class="d-flex justify-content-between align-items-start mb-2">
                                <span class="badge badge-category bg-primary">${result.category}</span>
                                <span class="badge ${badgeClass}">
                                    <i class="bi bi-${icon}"></i> ${result.status}
                                </span>
                            </div>
                            ${result.payload_name ? `<div class="badge bg-secondary mb-2"><i class="bi bi-file-code"></i> ${result.payload_name}</div>` : ''}
                            <h5 class="card-title">${result.name}</h5>
                            <p class="card-text"><strong>Details:</strong> ${result.details}</p>
                    `;
                    
                    if (result.risk) {
                        cardBody += `
                            <div class="alert alert-danger mt-3" role="alert">
                                <strong><i class="bi bi-exclamation-triangle"></i> Risk:</strong> ${result.risk}
                            </div>
                        `;
                    }
                    
                    if (result.mitigation) {
                        cardBody += `
                            <div class="alert alert-info mt-3" role="alert">
                                <strong><i class="bi bi-lightbulb"></i> Mitigation:</strong> ${result.mitigation}
                            </div>
                        `;
                    }
                    
                    cardBody += '</div>';
                    card.innerHTML = cardBody;
                    resultsList.appendChild(card);
                });
                
                // Scroll to results
                document.getElementById('results').scrollIntoView({ behavior: 'smooth', block: 'start' });
            }
        </script>
    </body>
    </html>
    """


def generate_schema_based_tests(schema: List[FieldSchema], standards: List[str]) -> dict:
    """
    Generate security tests based on field schema and selected standards.
    Properly aligned with STRIDE threat model, OWASP Top 10, and PCI-DSS requirements.
    
    Returns dict with:
    - payloads: List of test payloads to send
    - test_types: Type of tests (STRIDE, OWASP, PCI-DSS)
    - base_payload: The base payload structure
    """
    result = {
        "payloads": [],
        "test_types": [],
        "base_payload": {}
    }
    
    # Build base payload from schema
    base_payload = {}
    for field in schema:
        if field.type == 'integer':
            try:
                base_payload[field.name] = int(field.sample_value) if field.sample_value else 0
            except:
                base_payload[field.name] = 0
        elif field.type == 'float':
            try:
                base_payload[field.name] = float(field.sample_value) if field.sample_value else 0.0
            except:
                base_payload[field.name] = 0.0
        elif field.type == 'boolean':
            base_payload[field.name] = str(field.sample_value).lower() in ['true', '1', 'yes'] if field.sample_value else False
        else:
            base_payload[field.name] = field.sample_value if field.sample_value else ""
    
    result["base_payload"] = base_payload
    
    # Generate tests based on selected standards
    if not standards or len(standards) == 0:
        standards = ["STRIDE"]  # Default
    
    from webhook_auditor.scanner.injection_tests import INJECTION_PAYLOADS
    
    for standard in standards:
        if standard == "STRIDE":
            result["test_types"].append("STRIDE")
            
            # ===== STRIDE THREAT MODEL TESTS =====
            
            # 1. SPOOFING (Authentication)
            result["payloads"].append(TestPayload(
                name="[STRIDE-Spoofing] Request without authentication",
                data=json.dumps({"__skip_signature__": True, **base_payload})
            ))
            
            result["payloads"].append(TestPayload(
                name="[STRIDE-Spoofing] Request with invalid signature",
                data=json.dumps({"__invalid_signature__": True, **base_payload})
            ))
            
            result["payloads"].append(TestPayload(
                name="[STRIDE-Spoofing] Request with empty signature",
                data=json.dumps({"__empty_signature__": True, **base_payload})
            ))
            
            # 2. TAMPERING (Integrity)
            tampered_payload = base_payload.copy()
            for field in schema:
                if field.type == 'string':
                    tampered_payload[field.name] = str(tampered_payload.get(field.name, "")) + "_MODIFIED"
                    break
            result["payloads"].append(TestPayload(
                name="[STRIDE-Tampering] Modified payload integrity check",
                data=json.dumps(tampered_payload)
            ))
            
            result["payloads"].append(TestPayload(
                name="[STRIDE-Tampering] HTTPS/TLS 1.2+ enforcement check",
                data=json.dumps({"__check_https__": True, **base_payload})
            ))
            
            # 3. REPUDIATION (Logging & Audit Trail)
            result["payloads"].append(TestPayload(
                name="[STRIDE-Repudiation] Logging mechanism check",
                data=json.dumps({"__check_logging__": True, **base_payload})
            ))
            
            old_timestamp_payload = base_payload.copy()
            old_timestamp_payload["timestamp"] = "2020-01-01T00:00:00Z"
            result["payloads"].append(TestPayload(
                name="[STRIDE-Repudiation] Replay attack with old timestamp",
                data=json.dumps(old_timestamp_payload)
            ))
            
            result["payloads"].append(TestPayload(
                name="[STRIDE-Repudiation] Duplicate request detection",
                data=json.dumps({"__duplicate_request__": True, **base_payload})
            ))
            
            # 4. INFORMATION DISCLOSURE
            sensitive_payload = base_payload.copy()
            sensitive_payload.update({
                "api_key": "sk_test_51234567890",
                "password": "Password123!",
                "secret_token": "ghp_1234567890abcdef"
            })
            result["payloads"].append(TestPayload(
                name="[STRIDE-InfoDisclosure] Sensitive data in payload",
                data=json.dumps(sensitive_payload)
            ))
            
            result["payloads"].append(TestPayload(
                name="[STRIDE-InfoDisclosure] Error message information leakage",
                data=json.dumps({"invalid": "data", "__trigger_error__": True})
            ))
            
            result["payloads"].append(TestPayload(
                name="[STRIDE-InfoDisclosure] Verbose headers check",
                data=json.dumps({"__check_headers__": True, **base_payload})
            ))
            
            # 5. DENIAL OF SERVICE
            result["payloads"].append(TestPayload(
                name="[STRIDE-DoS] Rate limiting check",
                data=json.dumps({"__rate_limit_test__": True, **base_payload})
            ))
            
            large_payload = base_payload.copy()
            large_payload["large_field"] = "A" * (15 * 1024 * 1024)  # 15MB
            result["payloads"].append(TestPayload(
                name="[STRIDE-DoS] Large payload rejection (>10MB)",
                data=json.dumps(large_payload)
            ))
            
            result["payloads"].append(TestPayload(
                name="[STRIDE-DoS] Async processing timeout",
                data=json.dumps({"__check_timeout__": True, **base_payload})
            ))
            
            # 6. ELEVATION OF PRIVILEGE
            # SQL Injection on all string fields
            for field in schema:
                if field.type in ['string', 'email', 'url']:
                    for i, sql_payload in enumerate(INJECTION_PAYLOADS.get("sql", [])[:2]):
                        test_data = base_payload.copy()
                        test_data[field.name] = sql_payload
                        result["payloads"].append(TestPayload(
                            name=f"[STRIDE-Privilege] SQL Injection on '{field.name}' #{i+1}",
                            data=json.dumps(test_data)
                        ))
            
            # Command Injection
            for field in schema:
                if field.type == 'string':
                    for i, cmd_payload in enumerate(INJECTION_PAYLOADS.get("command", [])[:2]):
                        test_data = base_payload.copy()
                        test_data[field.name] = cmd_payload
                        result["payloads"].append(TestPayload(
                            name=f"[STRIDE-Privilege] Command Injection on '{field.name}' #{i+1}",
                            data=json.dumps(test_data)
                        ))
            
            # Privilege escalation via role field
            for field in schema:
                if any(keyword in field.name.lower() for keyword in ['role', 'permission', 'admin', 'privilege']):
                    for value in ['admin', 'superuser', 'root']:
                        test_data = base_payload.copy()
                        test_data[field.name] = value
                        result["payloads"].append(TestPayload(
                            name=f"[STRIDE-Privilege] Privilege escalation via '{field.name}' = {value}",
                            data=json.dumps(test_data)
                        ))
        
        elif standard in ["PCI-DSS", "PCI DSS"]:
            result["test_types"].append("PCI-DSS")
            
            # ===== PCI-DSS COMPLIANCE TESTS =====
            
            # CARDHOLDER DATA PROTECTION (CHD)
            card_numbers = ["4111111111111111", "5500000000000004", "378282246310005"]
            for field in schema:
                if field.type in ['string', 'integer']:
                    for i, card_number in enumerate(card_numbers):
                        test_data = base_payload.copy()
                        test_data[field.name] = card_number
                        result["payloads"].append(TestPayload(
                            name=f"[PCI-DSS-CHD] Credit card in '{field.name}' #{i+1}",
                            data=json.dumps(test_data)
                        ))
            
            # CVV in payload
            test_data = base_payload.copy()
            test_data.update({"cvv": "123", "cvc": "456", "security_code": "789"})
            result["payloads"].append(TestPayload(
                name="[PCI-DSS-CHD] CVV/CVC in payload",
                data=json.dumps(test_data)
            ))
            
            # Tokenization check
            result["payloads"].append(TestPayload(
                name="[PCI-DSS-CHD] Tokenization check",
                data=json.dumps({"card_token": "tok_visa_4111", **base_payload})
            ))
            
            # Requirement 6.5.1: Injection Flaws
            for field in schema:
                if field.type in ['string', 'email', 'url']:
                    for i, sql_payload in enumerate(INJECTION_PAYLOADS.get("sql", [])[:2]):
                        test_data = base_payload.copy()
                        test_data[field.name] = sql_payload
                        result["payloads"].append(TestPayload(
                            name=f"[PCI-DSS-6.5.1] SQL Injection on '{field.name}' #{i+1}",
                            data=json.dumps(test_data)
                        ))
            
            # Requirement 6.5.7: XSS
            for field in schema:
                if field.type in ['string', 'email']:
                    for i, xss_payload in enumerate(INJECTION_PAYLOADS.get("xss", [])[:2]):
                        test_data = base_payload.copy()
                        test_data[field.name] = xss_payload
                        result["payloads"].append(TestPayload(
                            name=f"[PCI-DSS-6.5.7] XSS on '{field.name}' #{i+1}",
                            data=json.dumps(test_data)
                        ))
            
            # Requirement 6.5.8: Buffer overflow
            large_payload = base_payload.copy()
            large_payload["buffer_overflow_test"] = "A" * (100 * 1024 * 1024)  # 100MB
            result["payloads"].append(TestPayload(
                name="[PCI-DSS-6.5.8] Buffer overflow protection",
                data=json.dumps(large_payload)
            ))
            
            # Requirement 6.5.10: Authentication
            result["payloads"].append(TestPayload(
                name="[PCI-DSS-6.5.10] Empty authentication rejection",
                data=json.dumps({"__empty_auth__": True, **base_payload})
            ))
        
        elif standard == "OWASP":
            result["test_types"].append("OWASP")
            
            # ===== OWASP TOP 10 TESTS =====
            
            # A01: Broken Access Control
            result["payloads"].append(TestPayload(
                name="[OWASP-A01] Cross-account data access",
                data=json.dumps({"user_id": "OTHER_USER_12345", "account_id": "VICTIM_789", **base_payload})
            ))
            
            for field in schema:
                if any(keyword in field.name.lower() for keyword in ['role', 'permission', 'admin']):
                    test_data = base_payload.copy()
                    test_data[field.name] = "admin"
                    result["payloads"].append(TestPayload(
                        name=f"[OWASP-A01] Privilege escalation via '{field.name}'",
                        data=json.dumps(test_data)
                    ))
            
            # A03: Injection
            for field in schema:
                if field.type in ['string', 'email', 'url']:
                    # SQL Injection
                    for i, sql_payload in enumerate(INJECTION_PAYLOADS.get("sql", [])[:2]):
                        test_data = base_payload.copy()
                        test_data[field.name] = sql_payload
                        result["payloads"].append(TestPayload(
                            name=f"[OWASP-A03] SQL Injection on '{field.name}' #{i+1}",
                            data=json.dumps(test_data)
                        ))
                    
                    # NoSQL Injection
                    nosql_payloads = ['{"$ne": null}', '{"$gt": ""}']
                    for i, nosql_payload in enumerate(nosql_payloads):
                        test_data = base_payload.copy()
                        test_data[field.name] = nosql_payload
                        result["payloads"].append(TestPayload(
                            name=f"[OWASP-A03] NoSQL Injection on '{field.name}' #{i+1}",
                            data=json.dumps(test_data)
                        ))
            
            # Command Injection
            for field in schema:
                if field.type == 'string':
                    for i, cmd_payload in enumerate(INJECTION_PAYLOADS.get("command", [])[:1]):
                        test_data = base_payload.copy()
                        test_data[field.name] = cmd_payload
                        result["payloads"].append(TestPayload(
                            name=f"[OWASP-A03] Command Injection on '{field.name}' #{i+1}",
                            data=json.dumps(test_data)
                        ))
            
            # A05: Security Misconfiguration - Path Traversal
            for field in schema:
                if any(keyword in field.name.lower() for keyword in ['file', 'path', 'filename', 'dir']):
                    path_payloads = ['../../../etc/passwd', '..\\..\\..\\windows\\system32\\config\\sam']
                    for i, path_payload in enumerate(path_payloads):
                        test_data = base_payload.copy()
                        test_data[field.name] = path_payload
                        result["payloads"].append(TestPayload(
                            name=f"[OWASP-A05] Path Traversal on '{field.name}' #{i+1}",
                            data=json.dumps(test_data)
                        ))
            
            # A07: XSS
            for field in schema:
                if field.type in ['string', 'email']:
                    for i, xss_payload in enumerate(INJECTION_PAYLOADS.get("xss", [])[:2]):
                        test_data = base_payload.copy()
                        test_data[field.name] = xss_payload
                        result["payloads"].append(TestPayload(
                            name=f"[OWASP-A07] XSS on '{field.name}' #{i+1}",
                            data=json.dumps(test_data)
                        ))
            
            # A10: SSRF (Server-Side Request Forgery)
            internal_ips = [
                "http://localhost/admin",
                "http://127.0.0.1/admin",
                "http://10.0.0.1/internal",
                "http://192.168.1.1/admin",
                "http://169.254.169.254/latest/meta-data/"
            ]
            
            for field in schema:
                if field.type in ['url', 'string'] and any(keyword in field.name.lower() for keyword in ['url', 'webhook', 'callback', 'link']):
                    for i, internal_ip in enumerate(internal_ips):
                        test_data = base_payload.copy()
                        test_data[field.name] = internal_ip
                        result["payloads"].append(TestPayload(
                            name=f"[OWASP-A10] SSRF on '{field.name}' - Internal IP #{i+1}",
                            data=json.dumps(test_data)
                        ))
    
    return result


def generate_injection_payloads(schema: List[FieldSchema]) -> List[TestPayload]:
    """
    Generate injection test payloads based on field schema.
    
    For each field, generates targeted injection payloads based on its data type.
    """
    from webhook_auditor.scanner.injection_tests import INJECTION_PAYLOADS
    
    test_payloads = []
    
    # Build base payload from schema
    base_payload = {}
    for field in schema:
        if field.sample_value:
            if field.type == 'integer':
                try:
                    base_payload[field.name] = int(field.sample_value)
                except:
                    base_payload[field.name] = 0
            elif field.type == 'float':
                try:
                    base_payload[field.name] = float(field.sample_value)
                except:
                    base_payload[field.name] = 0.0
            elif field.type == 'boolean':
                base_payload[field.name] = field.sample_value.lower() in ['true', '1', 'yes']
            else:
                base_payload[field.name] = field.sample_value
        else:
            base_payload[field.name] = None
    
    # Generate injection tests for each field
    for field in schema:
        field_name = field.name
        field_type = field.type
        
        # SQL Injection tests for string/integer fields
        if field_type in ['string', 'integer', 'email', 'url']:
            for i, sql_payload in enumerate(INJECTION_PAYLOADS.get("sql", [])[:3]):  # Top 3 SQL injections
                test_data = base_payload.copy()
                test_data[field_name] = sql_payload
                test_payloads.append(TestPayload(
                    name=f"SQL Injection on '{field_name}' #{i+1}",
                    data=json.dumps(test_data)
                ))
        
        # XSS tests for string fields
        if field_type in ['string', 'email', 'url']:
            for i, xss_payload in enumerate(INJECTION_PAYLOADS.get("xss", [])[:3]):
                test_data = base_payload.copy()
                test_data[field_name] = xss_payload
                test_payloads.append(TestPayload(
                    name=f"XSS Injection on '{field_name}' #{i+1}",
                    data=json.dumps(test_data)
                ))
        
        # Command Injection for string fields
        if field_type == 'string':
            for i, cmd_payload in enumerate(INJECTION_PAYLOADS.get("command", [])[:2]):
                test_data = base_payload.copy()
                test_data[field_name] = cmd_payload
                test_payloads.append(TestPayload(
                    name=f"Command Injection on '{field_name}' #{i+1}",
                    data=json.dumps(test_data)
                ))
        
        # Path Traversal for string fields
        if field_type == 'string':
            for i, path_payload in enumerate(INJECTION_PAYLOADS.get("path_traversal", [])[:2]):
                test_data = base_payload.copy()
                test_data[field_name] = path_payload
                test_payloads.append(TestPayload(
                    name=f"Path Traversal on '{field_name}' #{i+1}",
                    data=json.dumps(test_data)
                ))
        
        # NoSQL Injection for string fields
        if field_type == 'string':
            for i, nosql_payload in enumerate(INJECTION_PAYLOADS.get("nosql", [])[:2]):
                test_data = base_payload.copy()
                test_data[field_name] = nosql_payload
                test_payloads.append(TestPayload(
                    name=f"NoSQL Injection on '{field_name}' #{i+1}",
                    data=json.dumps(test_data)
                ))
        
        # Integer overflow/underflow tests
        if field_type in ['integer', 'float']:
            overflow_values = [
                -2147483648,  # INT_MIN
                2147483647,   # INT_MAX
                -1,
                0,
                999999999999,
                "' OR '1'='1",  # SQL injection in int field
            ]
            for i, val in enumerate(overflow_values[:4]):
                test_data = base_payload.copy()
                test_data[field_name] = val
                test_payloads.append(TestPayload(
                    name=f"Integer Boundary Test on '{field_name}' #{i+1}",
                    data=json.dumps(test_data)
                ))
        
        # Type confusion tests
        type_confusion_values = [
            None,
            "",
            "null",
            "undefined",
            [],
            {},
        ]
        for i, val in enumerate(type_confusion_values[:3]):
            test_data = base_payload.copy()
            test_data[field_name] = val
            test_payloads.append(TestPayload(
                name=f"Type Confusion on '{field_name}' #{i+1}",
                data=json.dumps(test_data)
            ))
    
    return test_payloads


@app.post("/api/scan", response_model=ScanResponse)
async def scan_webhook(request: ScanRequest):
    """
    Run a comprehensive security scan against a webhook endpoint.
    
    Performs security tests based on selected standards (STRIDE, PCI-DSS, OWASP).
    Automatically generates tests based on payload schema.
    """
    try:
        all_results = []
        
        # Mode 1: Schema-based testing with standards
        if request.payload_schema and len(request.payload_schema) > 0:
            standards = request.test_standards if request.test_standards else ["STRIDE"]
            print(f"🎯 Schema-based mode: {len(request.payload_schema)} fields, Standards: {', '.join(standards)}")
            
            # Generate tests based on schema and selected standards
            test_data = generate_schema_based_tests(request.payload_schema, standards)
            test_payloads = test_data["payloads"]
            
            print(f"✨ Generated {len(test_payloads)} test payloads for {', '.join(test_data['test_types'])}")
            
            # Test each payload
            async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
                for idx, payload in enumerate(test_payloads, 1):
                    try:
                        # Parse the payload
                        payload_dict = json.loads(payload.data)
                        payload_bytes = payload.data.encode('utf-8')
                        
                        # Prepare headers
                        headers = {"Content-Type": "application/json"}
                        if request.custom_headers:
                            headers.update(request.custom_headers)
                        
                        # Add signature if secret provided
                        if request.shared_secret:
                            from webhook_auditor.utils.crypto import calculate_hmac_signature
                            secret_bytes = request.shared_secret.encode('utf-8')
                            signature = calculate_hmac_signature(secret_bytes, payload_bytes, request.signature_prefix)
                            headers[request.signature_header_name] = signature
                        
                        # Send request
                        response = await client.request(
                            request.http_method,
                            request.target_url,
                            content=payload_bytes,
                            headers=headers,
                            timeout=10.0
                        )
                        
                        # Analyze response
                        status = response.status_code
                        response_text = response.text[:500]  # First 500 chars
                        
                        # Determine category from payload name
                        category = "Security Testing"
                        if "STRIDE" in payload.name:
                            category = "STRIDE Security"
                        elif "PCI-DSS" in payload.name:
                            category = "PCI DSS Compliance"
                        elif "OWASP" in payload.name:
                            category = "OWASP Top 10"
                        
                        # Determine result
                        if 400 <= status < 500:
                            # Server rejected - PASS
                            all_results.append({
                                "category": category,
                                "name": payload.name,
                                "status": "PASS",
                                "details": f"Server properly rejected malicious payload (HTTP {status})",
                                "payload_name": f"[{idx}/{len(test_payloads)}] {payload.name}"
                            })
                        elif status == 200:
                            # Server accepted - check for danger signs
                            danger_signs = [
                                "error", "exception", "syntax", "mysql", "postgresql", 
                                "sqlite", "oracle", "warning", "undefined", "null",
                                "stack trace", "line ", "file:", "/usr/", "/etc/",
                                "root:", "admin", "password"
                            ]
                            
                            found_danger = any(sign in response_text.lower() for sign in danger_signs)
                            
                            if found_danger:
                                all_results.append({
                                    "category": category,
                                    "name": payload.name,
                                    "status": "FAIL",
                                    "details": f"Server accepted payload and response contains suspicious content (HTTP {status})",
                                    "risk": "Potential vulnerability - server may be processing malicious input without proper validation",
                                    "mitigation": "Implement input validation, sanitization, and use parameterized queries. Escape special characters.",
                                    "payload_name": f"[{idx}/{len(test_payloads)}] {payload.name}"
                                })
                            else:
                                all_results.append({
                                    "category": category,
                                    "name": payload.name,
                                    "status": "PASS",
                                    "details": f"Server handled payload safely without exposing sensitive information (HTTP {status})",
                                    "payload_name": f"[{idx}/{len(test_payloads)}] {payload.name}"
                                })
                        else:
                            # Other status codes
                            all_results.append({
                                "category": category,
                                "name": payload.name,
                                "status": "WARN",
                                "details": f"Unexpected response: HTTP {status}",
                                "payload_name": f"[{idx}/{len(test_payloads)}] {payload.name}"
                            })
                    
                    except Exception as e:
                        all_results.append({
                            "category": "Security Testing",
                            "name": payload.name,
                            "status": "WARN",
                            "details": f"Test error: {str(e)}",
                            "payload_name": f"[{idx}/{len(test_payloads)}] {payload.name}"
                        })
        
        # Mode 2: Full STRIDE/PCI-DSS/OWASP testing with traditional payloads
        else:
            print(f"🔍 Full security testing mode")
            
            # Determine which payloads to use
            payloads_to_test = []
            if request.test_payloads and len(request.test_payloads) > 0:
                payloads_to_test = request.test_payloads
            else:
                payloads_to_test = [TestPayload(name="Default", data=request.sample_valid_payload)]
            
            # Run tests for each payload
            for idx, payload in enumerate(payloads_to_test, 1):
                config = ScannerSettings(
                    target_url=request.target_url,
                    http_method=request.http_method,
                    shared_secret=request.shared_secret,
                    signature_header_name=request.signature_header_name,
                    timestamp_header_name=request.timestamp_header_name,
                    sample_valid_payload=payload.data,
                    signature_prefix=request.signature_prefix,
                    custom_headers=request.custom_headers,
                    test_standards=request.test_standards if request.test_standards else ["STRIDE"]
                )
                
                payload_results = await run_stride_tests(config)
                
                for result in payload_results:
                    if len(payloads_to_test) > 1:
                        result["payload_name"] = f"[{idx}/{len(payloads_to_test)}] {payload.name}"
                    all_results.append(result)
        
        # Calculate statistics
        total_tests = len(all_results)
        passed = sum(1 for r in all_results if r.get("status") == "PASS")
        failed = sum(1 for r in all_results if r.get("status") == "FAIL")
        warnings = sum(1 for r in all_results if r.get("status") == "WARN")
        
        # Generate summary
        if failed == 0:
            summary = "✅ All security tests passed! Your webhook endpoint is secure."
        elif failed <= 2:
            summary = f"⚠️ {failed} security issue(s) detected. Review and fix them."
        else:
            summary = f"❌ {failed} security vulnerabilities detected! Immediate action required."
        
        # Generate scan ID
        scan_id = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        response = ScanResponse(
            scan_id=scan_id,
            target_url=request.target_url,
            timestamp=datetime.now().isoformat(),
            total_tests=total_tests,
            passed=passed,
            failed=failed,
            warnings=warnings,
            results=all_results,
            summary=summary
        )
        
        # Cache results
        scan_results_cache[scan_id] = response
        
        return response
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")


@app.get("/api/scan/{scan_id}")
async def get_scan_results(scan_id: str):
    """Retrieve results from a previous scan."""
    if scan_id not in scan_results_cache:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan_results_cache[scan_id]


@app.get("/api/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "service": "Webhook Security Scanner API"}


if __name__ == "__main__":
    import uvicorn
    print("\n🚀 Starting Webhook Security Scanner Web Interface...")
    print("📍 Open your browser at: http://localhost:8080")
    print("📚 API docs at: http://localhost:8080/docs")
    print("\n")
    uvicorn.run(app, host="0.0.0.0", port=8080, log_level="info")
