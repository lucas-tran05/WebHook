"""
HTML Template for Webhook Security Scanner Web Interface
"""


def get_html_template() -> str:
    """Return the complete HTML template with Bootstrap UI."""
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
                                    <!-- Default fields -->
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
        <script src="/static/app.js"></script>
    </body>
    </html>
    """
