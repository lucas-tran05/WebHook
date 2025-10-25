# 📁 TÀI LIỆU CẤU TRÚC DỰ ÁN - WEBHOOK SECURITY SCANNER

## 🎯 Tổng Quan Dự Án
Hệ thống quét và kiểm tra bảo mật webhook endpoints sử dụng các tiêu chuẩn STRIDE, OWASP Top 10, và PCI-DSS. Cung cấp cả giao diện Web (FastAPI) và CLI (Command Line Interface) để thực hiện các bài test bảo mật và cho điểm bảo mật từ 0-10.

---

## 📂 CẤU TRÚC THƯ MỤC VÀ MỤC ĐÍCH CÁC FILE

### 🔹 **ROOT LEVEL - File Chính**

#### 1. `main.py` (149 dòng)
**Mục đích:** Entry point cho chế độ CLI (Command Line Interface)

**Chức năng:**
- CLI tool sử dụng Click framework để chạy security tests từ terminal
- Nhận các tham số: target URL, secret key, HTTP method, headers, payload
- Gọi orchestrator để chạy các test STRIDE/OWASP/PCI-DSS
- In kết quả scan ra console với Rich formatting

**Khi nào dùng:** 
- Chạy security scan từ command line
- Tích hợp vào CI/CD pipelines
- Automation scripts

**Ví dụ sử dụng:**
```bash
python main.py scan --target-url https://webhook.example.com/endpoint --secret my_secret_key
```

---

#### 2. `web_scanner.py` (1675 dòng)
**Mục đích:** Main server - FastAPI web application với UI và API endpoint

**Chức năng chính:**
- **Web Server:** FastAPI server chạy trên port 8080
- **UI Route:** `GET /` - Giao diện web Bootstrap 5 để nhập thông tin scan
- **API Endpoint:** `POST /api/scan` - Nhận request scan và trả về kết quả
- **Security Scoring:** Hệ thống chấm điểm bảo mật 0-10 dựa trên lỗ hổng
- **Test Orchestration:** Điều phối chạy tất cả các test STRIDE/OWASP/PCI-DSS

**Components quan trọng:**
- Lines 72-87: `ScanResponse` model - Định nghĩa cấu trúc response với security_score
- Lines 92-150: `calculate_security_score()` - Logic tính điểm bảo mật theo severity
- Lines 1620-1640: `scan_webhook()` endpoint - Xử lý request scan và trả về kết quả

**Khi nào dùng:**
- Chạy web server để sử dụng giao diện UI
- Cung cấp API endpoint cho frontend/mobile apps
- Demo cho khách hàng/stakeholders

**Chạy server:**
```bash
python web_scanner.py
# Server sẽ chạy tại: http://localhost:8080
```

---

### 🔹 **WEBHOOK_AUDITOR/ - Core Security Testing Modules**

#### **webhook_auditor/__init__.py**
**Mục đích:** Package initializer cho webhook_auditor module
**Chức năng:** Định nghĩa package và export các components chính

---

#### **SCANNER/ - Các Module Test Bảo Mật**

##### 1. `webhook_auditor/scanner/config.py` (66 dòng)
**Mục đích:** Configuration model cho security scanner

**Chức năng:**
- `ScannerSettings` class - Pydantic model chứa tất cả config cho scan
- Định nghĩa: target URL, HTTP method, secret key, header names, payload mẫu
- Validation cho các tham số input

**Dùng ở đâu:** Được dùng bởi orchestrator và tất cả test modules

---

##### 2. `webhook_auditor/scanner/orchestrator.py` (104 dòng)
**Mục đích:** Điều phối và chạy tất cả các security tests

**Chức năng:**
- `run_all_tests()` - Main function chạy tất cả tests theo standards được chọn
- Xử lý logic chạy tests song song với httpx AsyncClient
- Hiển thị progress bar với Rich library
- Thu thập kết quả từ tất cả test modules
- Generate final report

**Flow:**
1. Nhận config (target URL, standards: STRIDE/OWASP/PCI-DSS)
2. Chạy các test modules tương ứng (spoofing, injection, dos, etc.)
3. Aggregate results
4. Generate và return report

**Quan trọng:** Đây là "bộ não" điều khiển toàn bộ quá trình scan

---

##### 3. `webhook_auditor/scanner/spoofing_tests.py`
**Mục đích:** Tests cho STRIDE threats - Spoofing & Tampering

**Các test thực hiện:**
- **Spoofing Tests:**
  - No signature header (test authentication bypass)
  - Invalid signature (test signature validation)
  - Empty signature (test empty value handling)
  - Manipulated timestamp (test replay protection)
  
- **Tampering Tests:**
  - Modified payload với valid signature (detect payload tampering)
  - Signature mismatch detection

**Mục tiêu:** Đảm bảo webhook endpoint validate đúng identity và detect payload modifications

---

##### 4. `webhook_auditor/scanner/repudiation_tests.py`
**Mục đích:** Tests cho STRIDE threat - Repudiation (phủ nhận hành động)

**Các test thực hiện:**
- Test endpoint có log requests không
- Kiểm tra timestamp tracking
- Verify audit trail mechanisms
- Test signature validation được log đúng không

**Mục tiêu:** Đảm bảo có audit trail để prevent repudiation attacks

---

##### 5. `webhook_auditor/scanner/info_disclosure_tests.py`
**Mục đích:** Tests cho STRIDE threat - Information Disclosure

**Các test thực hiện:**
- Error message exposure (server có leak sensitive info trong errors không)
- Stack trace leakage detection
- Debug information disclosure
- Internal path/structure exposure
- Verbose error messages

**Mục tiêu:** Đảm bảo server không leak sensitive information qua error responses

---

##### 6. `webhook_auditor/scanner/dos_tests.py`
**Mục đích:** Tests cho STRIDE threat - Denial of Service

**Các test thực hiện:**
- Large payload handling (10MB+)
- Malformed JSON/XML
- Null bytes injection
- Infinite loop payloads
- Resource exhaustion attacks
- Compression bombs

**Mục tiêu:** Kiểm tra server có handle được malicious payloads gây overload không

---

##### 7. `webhook_auditor/scanner/privilege_escalation_tests.py`
**Mục đích:** Tests cho STRIDE threat - Elevation of Privilege

**Các test thực hiện:**
- Role manipulation trong payload
- Permission bypass attempts
- Admin access injection
- Authorization header manipulation
- Privilege escalation via payload fields

**Mục tiêu:** Đảm bảo server validate quyền truy cập đúng cách

---

##### 8. `webhook_auditor/scanner/injection_tests.py`
**Mục đích:** Tests cho OWASP - Injection attacks (SQL, NoSQL, Command, LDAP)

**Các test thực hiện:**
- **SQL Injection:** Classic SQL injection payloads
- **NoSQL Injection:** MongoDB injection attacks
- **Command Injection:** OS command execution attempts
- **LDAP Injection:** Directory service injection
- **XML Injection:** XXE (XML External Entity) attacks
- **Template Injection:** Server-Side Template Injection (SSTI)

**Mục tiêu:** Kiểm tra input sanitization và parameterized queries

---

##### 9. `webhook_auditor/scanner/owasp_tests.py`
**Mục đích:** Tests cho OWASP Top 10 vulnerabilities

**Các test thực hiện:**
- **A01: Broken Access Control**
- **A02: Cryptographic Failures**
- **A03: Injection** (gọi injection_tests module)
- **A04: Insecure Design**
- **A05: Security Misconfiguration**
- **A06: Vulnerable Components**
- **A07: Authentication Failures**
- **A08: Data Integrity Failures**
- **A09: Insufficient Logging**
- **A10: SSRF (Server-Side Request Forgery)**

**Mục tiêu:** Comprehensive coverage của OWASP Top 10 security risks

---

##### 10. `webhook_auditor/scanner/pci_dss_tests.py`
**Mục đích:** Tests cho PCI-DSS compliance (credit card data protection)

**Các test thực hiện:**
- **CHD Detection:** Cardholder Data (credit card numbers) in payload
- **CVV Detection:** CVV/CVC codes in requests
- **Sensitive Data Encryption:** Check HTTPS requirement
- **Logging Controls:** Ensure CHD not logged
- **Access Control:** Validate proper authorization for payment data
- **Secure Transmission:** SSL/TLS verification

**Mục tiêu:** Đảm bảo compliance với PCI-DSS standards cho payment data

---

#### **UTILS/ - Utility Functions**

##### 1. `webhook_auditor/utils/crypto.py` (41 dòng)
**Mục đích:** Cryptographic utilities cho signature generation/validation

**Functions:**
- `calculate_hmac_signature()` - Generate HMAC-SHA256 signatures
- `verify_signature()` - Verify provided signatures
- Support cho multiple signature formats (sha256=, sha1=, etc.)

**Dùng ở đâu:** Spoofing tests, tampering tests, authentication validation

---

##### 2. `webhook_auditor/utils/reporter.py` (124 dòng)
**Mục đích:** Generate formatted reports cho scan results

**Functions:**
- `generate_report()` - Tạo Rich formatted console reports
- Group results by categories (Spoofing, Injection, DoS, etc.)
- Color-coded output (PASS = green, FAIL = red)
- Summary statistics (total tests, vulnerabilities found)

**Dùng ở đâu:** CLI mode (main.py) để hiển thị kết quả ra terminal

---

### 🔹 **WEB_APP/ - Web Interface Components**

#### 1. `web_app/models.py` (52 dòng)
**Mục đích:** Pydantic models cho Web API request/response

**Models định nghĩa:**
- `FieldSchema` - Định nghĩa field trong payload schema
- `TestPayload` - Model cho individual test payloads
- `ScanRequest` - Request model cho /api/scan endpoint
  - Fields: target_url, shared_secret, http_method, payload_schema, etc.

**Dùng ở đâu:** web_scanner.py API endpoints để validate input/output

---

#### 2. `web_app/scoring.py` (111 dòng)
**Mục đích:** Security scoring system (deprecated version)

**Chức năng:**
- Tính điểm bảo mật 0-10 dựa trên test results
- Logic cũ: mỗi test PASS = 1 điểm, FAIL = 0 điểm
- Rating levels: EXCELLENT/GOOD/FAIR/POOR/CRITICAL

**Note:** Version cũ - web_scanner.py có version mới hơn với severity-based scoring

---

#### 3. `web_app/templates.py` (480 dòng)
**Mục đích:** HTML template cho web interface

**Chức năng:**
- `get_html_template()` - Return complete HTML page
- Bootstrap 5 UI với form input cho scan parameters
- JavaScript code để gọi /api/scan và hiển thị results
- Responsive design với gradient background
- Results display với color-coded vulnerabilities

**Dùng ở đâu:** web_scanner.py route `GET /` để render web UI

---

#### 4. `web_app/test_generator.py` (474 dòng)
**Mục đích:** Generate security test payloads based on field schema

**Chức năng:**
- `generate_schema_based_tests()` - Generate tests từ field definitions
- Tự động tạo payloads cho:
  - SQL injection tests trên string fields
  - XSS payloads trên text fields
  - Type confusion tests (string → integer)
  - Buffer overflow tests trên length limits
  - Sensitive data tests (CHD, CVV)
  
**Logic:**
- Nhận field schema (name, type, sample_value)
- Generate malicious payloads phù hợp với từng field type
- Return list of test payloads ready to send

**Dùng ở đâu:** web_scanner.py để auto-generate tests khi user provide schema

---

#### 5. `web_app/__init__.py`
**Mục đích:** Package initializer cho web_app module

---

## 🎯 LUỒNG HOẠT ĐỘNG CHÍNH

### **Luồng 1: Web UI Scan**
```
1. User truy cập http://localhost:8080
2. web_scanner.py GET / route → Trả về HTML từ templates.py
3. User nhập target URL, secret, payload schema
4. JavaScript call POST /api/scan
5. web_scanner.py scan_webhook() endpoint:
   - Parse ScanRequest (models.py)
   - Generate tests từ schema (test_generator.py nếu cần)
   - Create ScannerSettings (config.py)
   - Gọi orchestrator.run_all_tests()
   - Orchestrator chạy các test modules (spoofing, injection, dos, etc.)
   - Collect results
   - Calculate security score (calculate_security_score())
   - Return ScanResponse với score + vulnerabilities
6. JavaScript hiển thị results trên UI
```

### **Luồng 2: CLI Scan**
```
1. User chạy: python main.py scan --target-url <url> --secret <key>
2. main.py CLI command:
   - Parse arguments
   - Create ScannerSettings
   - Gọi orchestrator.run_all_tests()
   - Orchestrator chạy tests
   - Collect results
   - reporter.generate_report() → In ra terminal
3. User xem kết quả trong console
```

---

## 📊 HỆ THỐNG CHẤM ĐIỂM (SECURITY SCORING)

### **Location:** `web_scanner.py` - `calculate_security_score()` function

### **Scoring Logic:**
Điểm ban đầu: **10.0**

**Trừ điểm theo severity của vulnerability:**

| Vulnerability Type | Severity | Điểm Trừ | Location |
|-------------------|----------|----------|----------|
| **CHD Detection** (Credit Card Numbers) | CRITICAL | -10.0 | Payload |
| **CVV Detection** (CVV/CVC Codes) | CRITICAL | -10.0 | Payload |
| **SSRF** (Server-Side Request Forgery) | CRITICAL | -8.0 | Payload |
| **SQL Injection** | CRITICAL | -7.0 | Payload |
| **Command Injection** | CRITICAL | -7.0 | Payload |
| **XXE** (XML External Entity) | CRITICAL | -7.0 | Payload |
| **Access Control Bypass** | HIGH | -6.0 | Header/Payload |
| **Authentication Failures** | HIGH | -6.0 | Header |
| **Spoofing** (No Signature) | HIGH | -5.0 | Header |
| **Tampering** (Invalid Signature) | HIGH | -5.0 | Header |
| **Template Injection** (SSTI) | HIGH | -5.0 | Payload |
| **XSS** (Cross-Site Scripting) | MEDIUM | -4.0 | Payload |
| **NoSQL Injection** | MEDIUM | -4.0 | Payload |
| **LDAP Injection** | MEDIUM | -4.0 | Payload |
| **Information Disclosure** | MEDIUM | -3.0 | Response |
| **Insecure Design** | MEDIUM | -3.0 | Config |
| **Security Misconfiguration** | MEDIUM | -3.0 | Config |
| **DoS** (Denial of Service) | LOW | -2.0 | Payload |
| **Insufficient Logging** | LOW | -2.0 | System |
| **Repudiation** (No Audit Trail) | LOW | -2.0 | System |

### **Rating Scale:**
- **9-10:** 🟢 XUẤT SẮC - Excellent security
- **7-8:** 🟡 KHÁ TỐT - Good security  
- **5-6:** 🟠 TRUNG BÌNH - Fair security (needs improvement)
- **3-4:** 🔴 YẾU - Poor security (major vulnerabilities)
- **0-2:** 🚨 NGUY HIỂM - Critical security issues

---

## 🔧 DEPENDENCIES CHÍNH

```
FastAPI - Web framework
httpx - Async HTTP client cho testing
Pydantic - Data validation
Rich - Terminal formatting
Click - CLI framework
Uvicorn - ASGI server
```

---

## 🚀 CÁCH CHẠY DỰ ÁN

### **Chạy Web Server:**
```bash
python web_scanner.py
# Truy cập: http://localhost:8080
```

### **Chạy CLI Scanner:**
```bash
python main.py scan --target-url https://webhook.example.com/endpoint --secret my_key
```

---

## 📝 NOTES QUAN TRỌNG

1. **web_scanner.py** là file chính được dùng nhiều nhất (Web UI + API)
2. **main.py** dùng cho CLI mode (ít dùng hơn)
3. **orchestrator.py** là "brain" điều phối tất cả tests
4. **Test modules** chia theo standards: STRIDE threats, OWASP Top 10, PCI-DSS
5. **Scoring system mới** trong web_scanner.py (severity-based) thay thế scoring.py cũ
6. **Test generator** tự động generate payloads từ schema (tiết kiệm thời gian test)

---

## ✅ TÓM TẮT

**Dự án này cung cấp:**
- ✅ Web interface để scan webhook endpoints
- ✅ CLI tool cho automation
- ✅ Comprehensive security testing (STRIDE + OWASP + PCI-DSS)
- ✅ Security scoring system (0-10 scale)
- ✅ Automatic test payload generation
- ✅ Detailed vulnerability reporting

**Use Cases:**
- Security auditing cho webhook endpoints
- Pre-production security validation
- Compliance testing (PCI-DSS)
- CI/CD integration
- Security training/demos

---

📅 **Document Created:** 2025
🔐 **Security Standards:** STRIDE, OWASP Top 10, PCI-DSS v3.2+
