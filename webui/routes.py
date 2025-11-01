from datetime import datetime
import json
from typing import List

import httpx
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse

from webhook_auditor.scanner.config import ScannerSettings

from .cache import scan_results_cache
from .models import FieldSchema, TestPayload, ScanRequest, ScanResponse
from .scoring import calculate_security_score
from .generators import generate_schema_based_tests


def register_routes(app: FastAPI) -> None:
    @app.get("/", response_class=HTMLResponse)
    async def root():
        return """
        <!DOCTYPE html>
        <html lang=\"en\">
        <head>
            <meta charset=\"UTF-8\">
            <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">
            <title>Webhook Security Scanner</title>
            <link href=\"https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css\" rel=\"stylesheet\">
            <link href=\"https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.0/font/bootstrap-icons.css\" rel=\"stylesheet\">
            <link href=\"https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap\" rel=\"stylesheet\">
            <style>
            * { font-family: 'Inter', sans-serif; }
            body { min-height: 100vh; padding: 20px 0; }
            .main-card { background: white; border-radius: 20px; box-shadow: 0 20px 60px rgba(0,0,0,0.3); overflow: hidden; margin-bottom: 30px; }
            .header-section { background: #BC2626; color: white; padding: 40px; text-align: center; }
            .header-section h1 { font-size: 2.5rem; font-weight: 700; margin-bottom: 10px; }
            .header-section p { font-size: 1.1rem; opacity: 0.9; margin-bottom: 0; }
            .content-section { padding: 40px; }
            .form-label { font-weight: 600; color: #333; margin-bottom: 8px; }
            .form-control:focus, .form-select:focus { border-color: #667eea; box-shadow: 0 0 0 0.25rem rgba(102, 126, 234, 0.25); }
            .btn-scan { background: #BC2626; border: none; padding: 15px; font-weight: 600; font-size: 1.1rem; transition: transform 0.2s; }
            .btn-scan:hover { transform: translateY(-2px); box-shadow: 0 10px 20px #BC2626; background: #BC2626; opacity: 0.9; }
            .stat-card { text-align: center; padding: 25px; border-radius: 15px; background: white; border: 2px solid #e9ecef; transition: all 0.3s; }
            .stat-card:hover { transform: translateY(-5px); box-shadow: 0 10px 25px rgba(0,0,0,0.1); }
            .stat-number { font-size: 3rem; font-weight: 700; margin-bottom: 5px; }
            .stat-label { color: #6c757d; font-size: 0.95rem; font-weight: 500; text-transform: uppercase; }
            .result-card { border-left: 5px solid #dee2e6; margin-bottom: 20px; transition: all 0.3s; }
            .result-card:hover { transform: translateX(5px); box-shadow: 0 5px 15px rgba(0,0,0,0.1); }
            .result-card.pass { border-left-color: #28a745; }
            .result-card.fail { border-left-color: #dc3545; }
            .result-card.warn { border-left-color: #ffc107; }
            .badge-category { font-size: 0.75rem; padding: 5px 12px; border-radius: 20px; font-weight: 600; }
            .spinner-border-custom { width: 3rem; height: 3rem; border-width: 0.3rem; }
            .advanced-options { background: #f8f9fa; padding: 20px; border-radius: 10px; margin-top: 20px; }
            .test-category-checkbox { margin-right: 15px; }
            #results { animation: fadeIn 0.5s; }
            @keyframes fadeIn { from { opacity: 0; transform: translateY(20px); } to { opacity: 1; transform: translateY(0); } }
            .progress-bar-animated { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); }
            .alert-custom { border-left: 5px solid; border-radius: 10px; }
            .field-item { background: #f8f9fa; transition: all 0.3s ease; }
            .field-item:hover { background: #e9ecef; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
            .field-name, .field-type, .field-value { font-weight: 500; }
            .remove-field { transition: all 0.2s; }
            .remove-field:hover { transform: scale(1.1); }
            .small { font-size: 0.85rem; font-weight: 600; color: #495057; }
            </style>
        </head>
        <body>
        <div class=\"container\">
            <div class=\"main-card\"> 
                <div class=\"header-section\">
                    <h1><i class=\"bi bi-shield-lock\"></i> Webhook Security Scanner</h1>
                    <p>STRIDE, PCI DSS & OWASP Top 10 security testing</p>
                </div>
                <div class=\"content-section\">
                    <form id=\"scanForm\"> 
                        <div class=\"row\">
                            <div class=\"col-md-12 mb-3\">
                                <label for=\"target_url\" class=\"form-label\"><i class=\"bi bi-bullseye\"></i> Target Webhook URL *</label>
                                <input type=\"url\" class=\"form-control form-control-lg\" id=\"target_url\" placeholder=\"https://api.example.com/webhook\" required>
                                <div class=\"form-text\">Enter the webhook endpoint you want to test</div>
                            </div>
                        </div>
                        <div class=\"row\">
                            <div class=\"col-md-6 mb-3\">
                                <label for=\"shared_secret\" class=\"form-label\"><i class=\"bi bi-key\"></i> Shared Secret <small class=\"text-muted\">(optional)</small></label>
                                <div class=\"input-group\">
                                    <input type=\"password\" class=\"form-control\" id=\"shared_secret\" placeholder=\"your-webhook-secret\">
                                    <button class=\"btn btn-outline-secondary\" type=\"button\" id=\"toggleSecret\"><i class=\"bi bi-eye\"></i></button>
                                </div>
                                <div class=\"form-text\">Leave empty if webhook doesn't require authentication</div>
                            </div>
                            <div class=\"col-md-6 mb-3\">
                                <label for=\"http_method\" class=\"form-label\"><i class=\"bi bi-arrow-left-right\"></i> HTTP Method</label>
                                <select class=\"form-select\" id=\"http_method\">
                                    <option value=\"POST\" selected>POST</option>
                                    <option value=\"PUT\">PUT</option>
                                    <option value=\"PATCH\">PATCH</option>
                                </select>
                            </div>
                        </div>
                        <div class=\"row\">
                            <div class=\"col-md-12 mb-3\">
                                <label class=\"form-label\"><i class=\"bi bi-file-code\"></i> Payload Schema (Field Definitions)</label>
                                <div class=\"alert alert-info\"><i class=\"bi bi-info-circle\"></i> Define your webhook payload structure. The scanner will automatically generate injection test cases for each field based on its data type.</div>
                                <div id=\"fields_container\">
                                    <div class=\"field-item border rounded p-3 mb-2\">
                                        <div class=\"row align-items-end\">
                                            <div class=\"col-md-4\"><label class=\"form-label small\">Field Name</label><input type=\"text\" class=\"form-control form-control-sm field-name\" placeholder=\"e.g., event\" value=\"event\"></div>
                                            <div class=\"col-md-3\"><label class=\"form-label small\">Data Type</label><select class=\"form-select form-select-sm field-type\"><option value=\"string\" selected>String</option><option value=\"integer\">Integer</option><option value=\"float\">Float</option><option value=\"boolean\">Boolean</option><option value=\"email\">Email</option><option value=\"url\">URL</option><option value=\"json\">JSON Object</option><option value=\"array\">Array</option></select></div>
                                            <div class=\"col-md-4\"><label class=\"form-label small\">Sample Value</label><input type=\"text\" class=\"form-control form-control-sm field-value\" placeholder=\"e.g., user.created\" value=\"user.created\"></div>
                                            <div class=\"col-md-1\"><button type=\"button\" class=\"btn btn-sm btn-outline-danger remove-field w-100\"><i class=\"bi bi-trash\"></i></button></div>
                                        </div>
                                    </div>
                                    <div class=\"field-item border rounded p-3 mb-2\">
                                        <div class=\"row align-items-end\">
                                            <div class=\"col-md-4\"><label class=\"form-label small\">Field Name</label><input type=\"text\" class=\"form-control form-control-sm field-name\" placeholder=\"e.g., user_id\" value=\"user_id\"></div>
                                            <div class=\"col-md-3\"><label class=\"form-label small\">Data Type</label><select class=\"form-select form-select-sm field-type\"><option value=\"string\">String</option><option value=\"integer\" selected>Integer</option><option value=\"float\">Float</option><option value=\"boolean\">Boolean</option><option value=\"email\">Email</option><option value=\"url\">URL</option><option value=\"json\">JSON Object</option><option value=\"array\">Array</option></select></div>
                                            <div class=\"col-md-4\"><label class=\"form-label small\">Sample Value</label><input type=\"text\" class=\"form-control form-control-sm field-value\" placeholder=\"e.g., 12345\" value=\"12345\"></div>
                                            <div class=\"col-md-1\"><button type=\"button\" class=\"btn btn-sm btn-outline-danger remove-field w-100\"><i class=\"bi bi-trash\"></i></button></div>
                                        </div>
                                    </div>
                                </div>
                                <button type=\"button\" class=\"btn btn-sm btn-outline-primary mt-2\" id=\"add_field\"><i class=\"bi bi-plus-circle\"></i> Add Field</button>
                                <div class=\"form-text mt-2\"><strong>Auto-generated tests per field:</strong><br>• <strong>String</strong>: SQL injection, XSS, command injection, path traversal, LDAP injection<br>• <strong>Integer</strong>: Negative values, overflow, type confusion, SQL injection<br>• <strong>Email/URL</strong>: Format validation, SSRF, injection<br>• All fields tested with null, empty, special characters, and boundary values</div>
                            </div>
                        </div>
                        <div class=\"mb-3\"><button class=\"btn btn-link\" type=\"button\" data-bs-toggle=\"collapse\" data-bs-target=\"#advancedOptions\"><i class=\"bi bi-gear\"></i> Advanced Options</button></div>
                        <div class=\"collapse advanced-options\" id=\"advancedOptions\">
                            <div class=\"row\">
                                <div class=\"col-md-6 mb-3\"><label for=\"signature_header\" class=\"form-label\">Signature Header Name</label><input type=\"text\" class=\"form-control\" id=\"signature_header\" value=\"X-Webhook-Signature\"></div>
                                <div class=\"col-md-6 mb-3\"><label for=\"signature_prefix\" class=\"form-label\">Signature Prefix</label><input type=\"text\" class=\"form-control\" id=\"signature_prefix\" value=\"sha256=\"></div>
                            </div>
                            <div class=\"row\">
                                <div class=\"col-md-6 mb-3\"><label for=\"timestamp_header\" class=\"form-label\">Timestamp Header Name</label><input type=\"text\" class=\"form-control\" id=\"timestamp_header\" value=\"X-Webhook-Timestamp\"></div>
                            </div>
                            <div class=\"mb-3\"><label for=\"custom_headers\" class=\"form-label\"><i class=\"bi bi-plus-circle\"></i> Custom Headers (JSON)</label><textarea class=\"form-control font-monospace\" id=\"custom_headers\" rows=\"3\" placeholder='{" + "\"X-API-Key\": \"your-key\", \"User-Agent\": \"MyApp/1.0\"' + "}"></textarea><div class=\"form-text\">Add extra headers as JSON object. Useful for API keys, tracking headers, etc.</div></div>
                            <div class=\"mb-3\"><label class=\"form-label\"><i class=\"bi bi-shield-check\"></i> Security Standards to Test</label>
                                <div>
                                    <div class=\"form-check form-check-inline test-category-checkbox\"><input class=\"form-check-input\" type=\"checkbox\" id=\"std_stride\" value=\"STRIDE\" checked><label class=\"form-check-label\" for=\"std_stride\"><strong>STRIDE</strong> <small class=\"text-muted\">(12 tests)</small></label></div>
                                    <div class=\"form-check form-check-inline test-category-checkbox\"><input class=\"form-check-input\" type=\"checkbox\" id=\"std_pci\" value=\"PCI-DSS\"><label class=\"form-check-label\" for=\"std_pci\"><strong>PCI DSS</strong> <small class=\"text-muted\">(7 tests)</small></label></div>
                                    <div class=\"form-check form-check-inline test-category-checkbox\"><input class=\"form-check-input\" type=\"checkbox\" id=\"std_owasp\" value=\"OWASP\"><label class=\"form-check-label\" for=\"std_owasp\"><strong>OWASP Top 10</strong> <small class=\"text-muted\">(9 tests)</small></label></div>
                                </div>
                                <div class=\"form-text mt-2\"><strong>STRIDE:</strong> Spoofing, Tampering, Repudiation, Info Disclosure, DoS, Privilege<br><strong>PCI DSS:</strong> Payment Card Industry compliance tests<br><strong>OWASP:</strong> OWASP Top 10 web security risks</div>
                            </div>
                        </div>
                        <button type=\"submit\" class=\"btn btn-primary btn-scan w-100\" id=\"scanBtn\"><i class=\"bi bi-play-circle\"></i> Start Security Scan</button>
                    </form>
                    <div class=\"text-center py-5 d-none\" id=\"loading\">
                        <div class=\"spinner-border spinner-border-custom text-primary\" role=\"status\"><span class=\"visually-hidden\">Loading...</span></div>
                        <div class=\"mt-3\"><h5>Running security tests...</h5><p class=\"text-muted\">This may take 30-60 seconds</p><div class=\"progress mx-auto\" style=\"max-width: 400px;\"><div class=\"progress-bar progress-bar-striped progress-bar-animated\" role=\"progressbar\" style=\"width: 100%\"></div></div></div>
                    </div>
                    <div class=\"d-none mt-5\" id=\"results\">
                        <hr class=\"my-4\">
                        <div class=\"mb-4\">
                            <h2><i class=\"bi bi-graph-up\"></i> Scan Results</h2>
                            <div class=\"row g-3 mt-2\">
                                <div class=\"col-md-4\"><div class=\"stat-card\"><div class=\"stat-number text-success\" id=\"passedCount\">0</div><div class=\"stat-label\">Passed</div></div></div>
                                <div class=\"col-md-4\"><div class=\"stat-card\"><div class=\"stat-number text-danger\" id=\"failedCount\">0</div><div class=\"stat-label\">Failed</div></div></div>
                                <div class=\"col-md-4\"><div class=\"stat-card\"><div class=\"stat-number text-warning\" id=\"warnCount\">0</div><div class=\"stat-label\">Warnings</div></div></div>
                            </div>
                            <div class=\"alert alert-custom mt-4\" id=\"scanSummary\" role=\"alert\"></div>
                        </div>
                        <div id=\"resultsList\"></div>
                    </div>
                </div>
            </div>
        </div>
        <script src=\"https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js\"></script>
        <script>
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
                        <input type="text" class="form-control form-control-sm field-name" placeholder="e.g., email">
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
                        <input type="text" class="form-control form-control-sm field-value" placeholder="Sample value">
                    </div>
                    <div class="col-md-1">
                        <button type="button" class="btn btn-sm btn-outline-danger remove-field w-100">
                            <i class="bi bi-trash"></i>
                        </button>
                    </div>
                </div>`;
            container.appendChild(newField);
        });
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
        document.getElementById('toggleSecret').addEventListener('click', function() {
            const secretInput = document.getElementById('shared_secret');
            const icon = this.querySelector('i');
            if (secretInput.type === 'password') { secretInput.type = 'text'; icon.classList.remove('bi-eye'); icon.classList.add('bi-eye-slash'); }
            else { secretInput.type = 'password'; icon.classList.remove('bi-eye-slash'); icon.classList.add('bi-eye'); }
        });
        document.getElementById('scanForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const standards = [];
            document.querySelectorAll('input[type="checkbox"][id^="std_"]:checked').forEach(cb => standards.push(cb.value));
            const fields = [];
            document.querySelectorAll('.field-item').forEach(item => {
                const name = item.querySelector('.field-name').value.trim();
                const type = item.querySelector('.field-type').value;
                const value = item.querySelector('.field-value').value.trim();
                if (name) { fields.push({ name: name, type: type, sample_value: value || null }); }
            });
            if (fields.length === 0) { alert('Please define at least one field!'); return; }
            const samplePayload = {};
            fields.forEach(field => {
                if (field.sample_value) {
                    if (field.type === 'integer') samplePayload[field.name] = parseInt(field.sample_value) || 0;
                    else if (field.type === 'float') samplePayload[field.name] = parseFloat(field.sample_value) || 0.0;
                    else if (field.type === 'boolean') samplePayload[field.name] = field.sample_value.toLowerCase() === 'true';
                    else if (field.type === 'json') { try { samplePayload[field.name] = JSON.parse(field.sample_value); } catch { samplePayload[field.name] = {}; } }
                    else if (field.type === 'array') { try { samplePayload[field.name] = JSON.parse(field.sample_value); } catch { samplePayload[field.name] = []; } }
                    else samplePayload[field.name] = field.sample_value;
                } else samplePayload[field.name] = null;
            });
            const formData = {
                target_url: document.getElementById('target_url').value,
                http_method: document.getElementById('http_method').value,
                sample_valid_payload: JSON.stringify(samplePayload),
                payload_schema: fields,
                signature_header_name: document.getElementById('signature_header').value,
                signature_prefix: document.getElementById('signature_prefix').value,
                timestamp_header_name: document.getElementById('timestamp_header').value,
            };
            const sharedSecret = document.getElementById('shared_secret').value.trim();
            if (sharedSecret) { formData.shared_secret = sharedSecret; }
            const customHeadersText = document.getElementById('custom_headers').value.trim();
            if (customHeadersText) { try { formData.custom_headers = JSON.parse(customHeadersText); } catch (e) { alert('Invalid JSON format for Custom Headers. Please check and try again.'); return; } }
            if (standards.length > 0) { formData.test_standards = standards; }
            document.getElementById('loading').classList.remove('d-none');
            document.getElementById('results').classList.add('d-none');
            document.getElementById('scanBtn').disabled = true;
            try {
                const response = await fetch('/api/scan', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(formData) });
                const data = await response.json();
                document.getElementById('loading').classList.add('d-none');
                document.getElementById('scanBtn').disabled = false;
                if (response.ok) { displayResults(data); } else { alert('Error: ' + data.detail); }
            } catch (error) {
                document.getElementById('loading').classList.add('d-none');
                document.getElementById('scanBtn').disabled = false;
                alert('Error: ' + error.message);
            }
        });
        function displayResults(data) {
            document.getElementById('results').classList.remove('d-none');
            document.getElementById('passedCount').textContent = data.passed;
            document.getElementById('failedCount').textContent = data.failed;
            document.getElementById('warnCount').textContent = data.warnings;
            const summaryEl = document.getElementById('scanSummary');
            summaryEl.textContent = data.summary;
            if (data.failed === 0) { summaryEl.className = 'alert alert-custom alert-success'; summaryEl.style.borderLeftColor = '#28a745'; summaryEl.innerHTML = '<i class="bi bi-check-circle-fill"></i> ' + data.summary; }
            else if (data.failed <= 2) { summaryEl.className = 'alert alert-custom alert-warning'; summaryEl.style.borderLeftColor = '#ffc107'; summaryEl.innerHTML = '<i class="bi bi-exclamation-triangle-fill"></i> ' + data.summary; }
            else { summaryEl.className = 'alert alert-custom alert-danger'; summaryEl.style.borderLeftColor = '#dc3545'; summaryEl.innerHTML = '<i class="bi bi-x-circle-fill"></i> ' + data.summary; }
            const resultsList = document.getElementById('resultsList');
            resultsList.innerHTML = '';
            data.results.forEach(result => {
                const card = document.createElement('div');
                card.className = `card result-card ${result.status.toLowerCase()} mb-3`;
                let badgeClass = 'bg-secondary'; let icon = 'info-circle';
                if (result.status === 'PASS') { badgeClass = 'bg-success'; icon = 'check-circle-fill'; }
                else if (result.status === 'FAIL') { badgeClass = 'bg-danger'; icon = 'x-circle-fill'; }
                else if (result.status === 'WARN') { badgeClass = 'bg-warning text-dark'; icon = 'exclamation-triangle-fill'; }
                let cardBody = `
                    <div class="card-body">
                        <div class="d-flex justify-content-between align-items-start mb-2">
                            <span class="badge badge-category bg-primary">${result.category}</span>
                            <span class="badge ${badgeClass}"><i class="bi bi-${icon}"></i> ${result.status}</span>
                        </div>
                        ${result.payload_name ? `<div class="badge bg-secondary mb-2"><i class="bi bi-file-code"></i> ${result.payload_name}</div>` : ''}
                        <h5 class="card-title">${result.name}</h5>
                        <p class="card-text"><strong>Details:</strong> ${result.details}</p>`;
                if (result.risk) { cardBody += `<div class="alert alert-danger mt-3" role="alert"><strong><i class="bi bi-exclamation-triangle"></i> Risk:</strong> ${result.risk}</div>`; }
                if (result.mitigation) { cardBody += `<div class="alert alert-info mt-3" role="alert"><strong><i class="bi bi-lightbulb"></i> Mitigation:</strong> ${result.mitigation}</div>`; }
                cardBody += '</div>';
                card.innerHTML = cardBody;
                resultsList.appendChild(card);
            });
            document.getElementById('results').scrollIntoView({ behavior: 'smooth', block: 'start' });
        }
        </script>
        </body>
        </html>
        """

    @app.post("/api/scan", response_model=ScanResponse)
    async def scan_webhook(request: ScanRequest):
        try:
            all_results = []

            if request.payload_schema and len(request.payload_schema) > 0:
                standards = request.test_standards if request.test_standards else ["STRIDE"]
                test_data = generate_schema_based_tests(request.payload_schema, standards)
                test_payloads = test_data["payloads"]

                async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
                    for idx, payload in enumerate(test_payloads, 1):
                        try:
                            payload_dict = json.loads(payload.data)
                            test_type = payload_dict.pop("__test_type__", None)
                            clean_payload = json.dumps(payload_dict)
                            payload_bytes = clean_payload.encode("utf-8")

                            headers = {"Content-Type": "application/json"}
                            if request.custom_headers:
                                headers.update(request.custom_headers)

                            should_add_signature = True
                            signature_to_use = None

                            if test_type == "no_signature":
                                should_add_signature = False
                            elif test_type == "invalid_signature":
                                signature_to_use = request.signature_prefix + "invalid_signature_12345"
                                should_add_signature = True
                            elif test_type == "empty_signature":
                                signature_to_use = request.signature_prefix
                                should_add_signature = True
                            elif test_type == "no_timestamp":
                                if request.shared_secret:
                                    from webhook_auditor.utils.crypto import calculate_hmac_signature
                                    secret_bytes = request.shared_secret.encode("utf-8")
                                    signature_to_use = calculate_hmac_signature(
                                        secret_bytes, payload_bytes, request.signature_prefix
                                    )
                                    should_add_signature = True
                            else:
                                if request.shared_secret:
                                    from webhook_auditor.utils.crypto import calculate_hmac_signature
                                    secret_bytes = request.shared_secret.encode("utf-8")
                                    signature_to_use = calculate_hmac_signature(
                                        secret_bytes, payload_bytes, request.signature_prefix
                                    )
                                    should_add_signature = True

                            if should_add_signature and signature_to_use:
                                headers[request.signature_header_name] = signature_to_use

                            if test_type != "no_timestamp" and request.timestamp_header_name:
                                import time
                                headers[request.timestamp_header_name] = str(int(time.time()))

                            response = await client.request(
                                request.http_method,
                                request.target_url,
                                content=payload_bytes,
                                headers=headers,
                                timeout=10.0,
                            )

                            status = response.status_code
                            response_text = response.text[:500]

                            category = "Security Testing"
                            if "STRIDE" in payload.name:
                                category = "STRIDE Security"
                            elif "PCI-DSS" in payload.name:
                                category = "PCI DSS Compliance"
                            elif "OWASP" in payload.name:
                                category = "OWASP Top 10"

                            is_auth_test = test_type in ["no_signature", "invalid_signature", "empty_signature"]
                            is_replay_test = test_type == "no_timestamp"
                            is_tampering_test = "Tampering" in payload.name

                            if is_auth_test or is_replay_test or is_tampering_test:
                                if 200 <= status < 300:
                                    all_results.append(
                                        {
                                            "category": category,
                                            "name": payload.name,
                                            "status": "FAIL",
                                            "details": f"Server accepted request without proper validation (HTTP {status}). Expected rejection (4xx).",
                                            "risk": "Critical security vulnerability - server accepts unauthenticated or tampered requests",
                                            "mitigation": "Implement proper signature validation, timestamp checking, and reject invalid requests with 401/403",
                                            "payload_name": f"[{idx}/{len(test_payloads)}] {payload.name}",
                                            "response_status": status,
                                        }
                                    )
                                elif 400 <= status < 500:
                                    all_results.append(
                                        {
                                            "category": category,
                                            "name": payload.name,
                                            "status": "PASS",
                                            "details": f"Server properly rejected invalid request (HTTP {status})",
                                            "payload_name": f"[{idx}/{len(test_payloads)}] {payload.name}",
                                            "response_status": status,
                                        }
                                    )
                                else:
                                    all_results.append(
                                        {
                                            "category": category,
                                            "name": payload.name,
                                            "status": "WARN",
                                            "details": f"Unexpected response: HTTP {status}",
                                            "payload_name": f"[{idx}/{len(test_payloads)}] {payload.name}",
                                            "response_status": status,
                                        }
                                    )
                            else:
                                if 400 <= status < 500:
                                    all_results.append(
                                        {
                                            "category": category,
                                            "name": payload.name,
                                            "status": "PASS",
                                            "details": f"Server properly rejected malicious payload (HTTP {status})",
                                            "payload_name": f"[{idx}/{len(test_payloads)}] {payload.name}",
                                            "response_status": status,
                                        }
                                    )
                                elif 200 <= status < 300:
                                    danger_signs = [
                                        "error",
                                        "exception",
                                        "syntax",
                                        "mysql",
                                        "postgresql",
                                        "sqlite",
                                        "oracle",
                                        "warning",
                                        "undefined",
                                        "null",
                                        "stack trace",
                                        "line ",
                                        "file:",
                                        "/usr/",
                                        "/etc/",
                                        "root:",
                                        "admin",
                                        "password",
                                        "database",
                                        "query",
                                    ]
                                    found_danger = any(sign in response_text.lower() for sign in danger_signs)
                                    if found_danger:
                                        all_results.append(
                                            {
                                                "category": category,
                                                "name": payload.name,
                                                "status": "FAIL",
                                                "details": f"Server accepted payload and response contains suspicious content (HTTP {status})",
                                                "risk": "Potential vulnerability - server may be processing malicious input without proper validation",
                                                "mitigation": "Implement input validation, sanitization, and use parameterized queries. Escape special characters.",
                                                "payload_name": f"[{idx}/{len(test_payloads)}] {payload.name}",
                                                "response_status": status,
                                            }
                                        )
                                    else:
                                        all_results.append(
                                            {
                                                "category": category,
                                                "name": payload.name,
                                                "status": "PASS",
                                                "details": f"Server handled payload safely without exposing sensitive information (HTTP {status})",
                                                "payload_name": f"[{idx}/{len(test_payloads)}] {payload.name}",
                                                "response_status": status,
                                            }
                                        )
                                else:
                                    all_results.append(
                                        {
                                            "category": category,
                                            "name": payload.name,
                                            "status": "WARN",
                                            "details": f"Unexpected response: HTTP {status}",
                                            "payload_name": f"[{idx}/{len(test_payloads)}] {payload.name}",
                                            "response_status": status,
                                        }
                                    )
                        except Exception as e:
                            all_results.append(
                                {
                                    "category": "Security Testing",
                                    "name": payload.name,
                                    "status": "WARN",
                                    "details": f"Test error: {str(e)}",
                                    "payload_name": f"[{idx}/{len(test_payloads)}] {payload.name}",
                                }
                            )

            else:
                payloads_to_test = []
                if request.test_payloads and len(request.test_payloads) > 0:
                    payloads_to_test = request.test_payloads
                else:
                    payloads_to_test = [TestPayload(name="Default", data=request.sample_valid_payload)]

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
                        test_standards=request.test_standards if request.test_standards else ["STRIDE"],
                    )
                    from webhook_auditor.scanner.orchestrator import run_all_tests as run_stride_tests
                    payload_results = await run_stride_tests(config)
                    for result in payload_results:
                        if len(payloads_to_test) > 1:
                            result["payload_name"] = f"[{idx}/{len(payloads_to_test)}] {payload.name}"
                        all_results.append(result)

            total_tests = len(all_results)
            passed = sum(1 for r in all_results if r.get("status") == "PASS")
            failed = sum(1 for r in all_results if r.get("status") == "FAIL")
            warnings = sum(1 for r in all_results if r.get("status") == "WARN")

            scoring_result = calculate_security_score(all_results)
            security_score = scoring_result["score"]
            score_rating = scoring_result["rating"]

            if failed == 0:
                summary = f"All security tests passed! Security Score: {security_score}/10 ({score_rating})"
            elif failed <= 2:
                summary = f"{failed} security issue(s) detected. Security Score: {security_score}/10 ({score_rating})"
            else:
                summary = f"❌ {failed} security vulnerabilities detected! Security Score: {security_score}/10 ({score_rating})"

            scan_id = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

            response = ScanResponse(
                scan_id=scan_id,
                target_url=request.target_url,
                timestamp=datetime.now().isoformat(),
                total_tests=total_tests,
                passed=passed,
                failed=failed,
                warnings=warnings,
                security_score=security_score,
                score_rating=score_rating,
                results=all_results,
                summary=summary,
            )

            scan_results_cache[scan_id] = response

            return response
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")

    @app.get("/api/scan/{scan_id}")
    async def get_scan_results(scan_id: str):
        if scan_id not in scan_results_cache:
            raise HTTPException(status_code=404, detail="Scan not found")
        return scan_results_cache[scan_id]

    @app.get("/api/health")
    async def health_check():
        return {"status": "healthy", "service": "Webhook Security Scanner API"}
