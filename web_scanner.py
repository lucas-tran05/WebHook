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


class ScanRequest(BaseModel):
    """Request model for security scan."""
    target_url: str = Field(..., description="Webhook endpoint URL to scan")
    shared_secret: Optional[str] = Field(default=None, description="Shared secret for HMAC signatures (optional)")
    http_method: str = Field(default="POST", description="HTTP method")
    signature_header_name: str = Field(default="X-Webhook-Signature", description="Signature header name")
    timestamp_header_name: Optional[str] = Field(default="X-Webhook-Timestamp", description="Timestamp header name")
    sample_valid_payload: str = Field(default='{"event": "test", "data": "sample"}', description="Sample payload")
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
                                <label for="sample_payload" class="form-label">
                                    <i class="bi bi-file-code"></i> Sample Payload (JSON)
                                </label>
                                <textarea class="form-control font-monospace" id="sample_payload" rows="4" 
                                          placeholder='{"event": "test", "data": "sample"}'>{"event": "test", "data": "sample"}</textarea>
                                <div class="form-text">Valid JSON format required</div>
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
                
                // Prepare request data
                const formData = {
                    target_url: document.getElementById('target_url').value,
                    http_method: document.getElementById('http_method').value,
                    sample_valid_payload: document.getElementById('sample_payload').value,
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


@app.post("/api/scan", response_model=ScanResponse)
async def scan_webhook(request: ScanRequest):
    """
    Run a comprehensive security scan against a webhook endpoint.
    
    Performs security tests based on selected standards (STRIDE, PCI-DSS, OWASP).
    """
    try:
        # Create scanner configuration
        config = ScannerSettings(
            target_url=request.target_url,
            http_method=request.http_method,
            shared_secret=request.shared_secret,
            signature_header_name=request.signature_header_name,
            timestamp_header_name=request.timestamp_header_name,
            sample_valid_payload=request.sample_valid_payload,
            signature_prefix=request.signature_prefix,
            custom_headers=request.custom_headers,
            test_standards=request.test_standards if request.test_standards else ["STRIDE"]
        )
        
        # Run all tests using orchestrator
        all_results = await run_stride_tests(config)
        
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
