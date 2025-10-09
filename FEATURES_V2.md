# 🔄 Cập nhật mới - Webhook Security Scanner v2.0

## ✨ Các tính năng mới

### 1. **Secret Key Optional**
- Secret key giờ đây không bắt buộc
- Hữu ích khi test webhooks không có authentication
- Vẫn recommend dùng secret key cho bảo mật

### 2. **Custom Headers Dynamic**
- Thêm headers tùy chỉnh ngoài signature và timestamp
- Hỗ trợ API keys, custom authentication, tracking headers
- Format CLI: `--custom-header "Header-Name: value"`
- Format Web: JSON object trong advanced options

### 3. **Multiple Security Standards**
Ngoài STRIDE, giờ hỗ trợ thêm:

#### 📋 **PCI DSS** (Payment Card Industry Data Security Standard)
- 7 tests cho compliance với thanh toán thẻ
- **Requirement 4**: TLS encryption, strong ciphers
- **Requirement 6**: SQL injection, XSS protection  
- **Requirement 8**: Authentication strength
- **Requirement 10**: Audit trail logging
- **Requirement 11**: Vulnerability disclosure

#### 🌐 **OWASP Top 10**
- 9 tests theo chuẩn OWASP 2021
- **A01**: Broken Access Control
- **A02**: Cryptographic Failures
- **A03**: Injection
- **A05**: Security Misconfiguration
- **A07**: Authentication Failures
- **A08**: Software/Data Integrity
- **A09**: Logging Failures
- **A10**: SSRF Protection

## 📊 Tổng số tests hiện tại

| Standard | Số lượng tests |
|----------|----------------|
| STRIDE   | 12 tests       |
| Injection| 6 tests        |
| PCI DSS  | 7 tests        |
| OWASP    | 9 tests        |
| **TOTAL**| **34 tests**   |

## 🚀 Cách sử dụng

### CLI Examples

#### 1. Scan với secret key (basic)
```bash
python main.py scan \
  --target-url https://api.example.com/webhook \
  --secret "my-secret-key"
```

#### 2. Scan không cần secret key
```bash
python main.py scan \
  --target-url https://api.example.com/webhook
```

#### 3. Scan với custom headers
```bash
python main.py scan \
  --target-url https://api.example.com/webhook \
  --custom-header "X-API-Key: abc123" \
  --custom-header "User-Agent: MyApp/1.0" \
  --custom-header "X-Request-ID: unique-id"
```

#### 4. Scan với multiple standards
```bash
# Chỉ STRIDE
python main.py scan --target-url <URL> --standards STRIDE

# STRIDE + PCI DSS
python main.py scan --target-url <URL> --standards STRIDE,PCI-DSS

# All standards
python main.py scan --target-url <URL> --standards STRIDE,PCI-DSS,OWASP
```

#### 5. Full advanced scan
```bash
python main.py scan \
  --target-url https://api.example.com/webhook \
  --secret "my-secret-key-256-bits-long" \
  --method POST \
  --payload '{"event": "payment.success", "amount": 100}' \
  --custom-header "X-API-Key: production-key" \
  --custom-header "X-Client-Version: 2.0" \
  --standards STRIDE,PCI-DSS,OWASP
```

### Web Interface

#### Khởi động:
```bash
python main.py web
```

Mở: **http://localhost:8080**

#### Các trường form mới:

1. **Target URL** (*bắt buộc*)
2. **Shared Secret** (optional - để trống nếu không có)
3. **HTTP Method**: POST/PUT/PATCH
4. **Sample Payload**: JSON data

**Advanced Options:**
- Signature Header Name
- Signature Prefix
- Timestamp Header Name
- **Custom Headers** (JSON format):
  ```json
  {
    "X-API-Key": "your-api-key",
    "User-Agent": "MyApp/1.0",
    "X-Custom-Header": "custom-value"
  }
  ```
- **Test Standards** (checkboxes):
  - ☑ STRIDE
  - ☑ PCI DSS
  - ☑ OWASP

## 📁 Files mới

```
webhook_auditor/scanner/
├── pci_dss_tests.py     # 7 PCI DSS compliance tests (MỚI)
├── owasp_tests.py       # 9 OWASP Top 10 tests (MỚI)
├── orchestrator.py      # Updated: hỗ trợ multiple standards
└── config.py            # Updated: custom_headers, test_standards
```

## 🔧 Config Changes

### ScannerSettings (config.py)

```python
class ScannerSettings(BaseModel):
    target_url: str                              # Required
    shared_secret: Optional[str] = None          # ⚡ Now optional
    http_method: str = "POST"
    signature_header_name: str = "X-Webhook-Signature"
    timestamp_header_name: Optional[str] = "X-Webhook-Timestamp"
    sample_valid_payload: str = '{"event": "test"}'
    signature_prefix: str = "sha256="
    
    # ⚡ NEW FIELDS
    custom_headers: Optional[Dict[str, str]] = None
    test_standards: List[str] = ["STRIDE"]
```

## 💡 Use Cases

### Use Case 1: Testing payment webhooks (PCI DSS)
```bash
python main.py scan \
  --target-url https://payments.example.com/webhook \
  --secret "secure-payment-secret" \
  --standards PCI-DSS \
  --custom-header "X-Payment-Provider: Stripe"
```

### Use Case 2: General web security (OWASP)
```bash
python main.py scan \
  --target-url https://api.example.com/webhook \
  --standards OWASP
```

### Use Case 3: Comprehensive audit (All standards)
```bash
python main.py scan \
  --target-url https://api.example.com/webhook \
  --secret "my-secret" \
  --standards STRIDE,PCI-DSS,OWASP \
  --custom-header "X-API-Key: prod-key"
```

### Use Case 4: Public webhook (no secret)
```bash
python main.py scan \
  --target-url https://public-api.example.com/webhook \
  --standards OWASP
```

## 🎯 Benefits

1. **Flexibility**: Secret key optional, custom headers support
2. **Compliance**: PCI DSS for payment systems
3. **Best Practices**: OWASP Top 10 coverage
4. **Comprehensive**: 34 total security tests
5. **Easy to use**: Both CLI and Web interface

## ⚠️ Important Notes

### Secret Key Optional
- Nếu không có secret key, một số STRIDE tests sẽ WARN hoặc SKIP
- Vẫn chạy được tests khác như HTTPS, headers, injection, etc.
- Recommend: Luôn dùng secret key trong production

### Custom Headers
- Hữu ích cho: API keys, tracking IDs, custom auth
- Format: `{"Header-Name": "value"}`
- Được gửi trong mọi request test

### Test Standards
- Mặc định: STRIDE only
- PCI DSS: Dành cho payment webhooks
- OWASP: General web security
- Có thể combine: `STRIDE,PCI-DSS,OWASP`

## 📊 Sample Output

```
🔍 Starting Webhook Security Scan
Target: https://api.example.com/webhook
Standards: STRIDE, PCI-DSS, OWASP

Testing Spoofing & Tampering...
Testing Repudiation...
Testing Information Disclosure...
Testing Denial of Service...
Testing Elevation of Privilege...
Testing Injection Attacks...
Testing PCI DSS Compliance...
Testing OWASP Top 10...

✓ Scan Complete

═════════════════════════════════════════
📊 Security Scan Results
═════════════════════════════════════════

Total Tests: 34
✅ Passed: 28
❌ Failed: 3
⚠️  Warnings: 3

Summary: 28 out of 34 tests passed (82.4% success rate)

[Detailed results for each test...]
```

## 🔜 Future Enhancements

- [ ] ISO 27001 compliance tests
- [ ] NIST Cybersecurity Framework
- [ ] GDPR compliance checks
- [ ] Custom test definitions via YAML
- [ ] Report export (PDF, HTML, JSON)
- [ ] Scheduled scanning
- [ ] Webhook replay testing
- [ ] Performance benchmarking

---

**Version**: 2.0.0  
**Last Updated**: October 9, 2025  
**Status**: ✅ Production Ready
