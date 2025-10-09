# 🌐 Web Interface Guide - Webhook Security Scanner

## 🚀 Khởi động Web Interface

```bash
python main.py web

# Hoặc chỉ định port khác
python main.py web --port 8080
```

Sau đó mở trình duyệt: **http://localhost:8080**

## 📝 Form Fields

### **Basic Configuration**

#### 1. Target Webhook URL (*bắt buộc*)
```
https://api.example.com/webhook
```
- URL endpoint của webhook cần test
- Phải là URL hợp lệ (http hoặc https)

#### 2. Shared Secret (optional)
```
your-secret-key-256-bits
```
- Khóa bí mật để tạo HMAC signature
- **Có thể để trống** nếu webhook không cần authentication
- Một số tests sẽ bị SKIP nếu không có secret

#### 3. HTTP Method
- **POST** (mặc định)
- **PUT**
- **PATCH**

#### 4. Sample Payload (JSON)
```json
{
  "event": "user.created",
  "user_id": 12345,
  "email": "user@example.com",
  "timestamp": "2025-10-09T10:00:00Z"
}
```
- Payload mẫu hợp lệ để test
- Phải là JSON format
- Được dùng làm baseline cho các tests

### **Advanced Options** (Click để mở)

#### 5. Signature Header Name
```
X-Webhook-Signature
```
- Tên header chứa HMAC signature
- Ví dụ khác: `X-Hub-Signature-256`, `Stripe-Signature`

#### 6. Signature Prefix
```
sha256=
```
- Prefix trước signature value
- Ví dụ: `sha256=abc123...`, `v1,t=timestamp,v1=signature`

#### 7. Timestamp Header Name
```
X-Webhook-Timestamp
```
- Tên header chứa timestamp
- Dùng để phát hiện replay attacks

#### 8. Custom Headers (JSON) **⚡ MỚI**
```json
{
  "X-API-Key": "production-api-key-12345",
  "User-Agent": "MyWebhookClient/2.0",
  "X-Request-ID": "unique-request-id",
  "X-Client-Version": "2.0.1"
}
```
- Thêm headers tùy chỉnh vào mọi request
- Format: JSON object
- **Use Cases:**
  - API authentication keys
  - Custom user agents
  - Tracking/correlation IDs
  - Client version info
  - Any custom headers your webhook needs

#### 9. Security Standards to Test **⚡ MỚI**

##### ☑ **STRIDE** (mặc định - 12 tests)
- **S**poofing: Identity verification
- **T**ampering: Data integrity
- **R**epudiation: Logging and audit trails
- **I**nformation Disclosure: Data leakage
- **D**enial of Service: Resource exhaustion
- **E**levation of Privilege: Authorization bypass

##### ☐ **PCI DSS** (7 tests)
- Payment Card Industry Data Security Standard
- **Requirements covered:**
  - **4.1**: Strong TLS/SSL encryption
  - **4.2**: Secure cipher suites
  - **6.2**: SQL Injection prevention
  - **6.3**: XSS protection
  - **8.1**: Strong authentication
  - **10.1**: Audit logging
  - **11.2**: Vulnerability disclosure
- **Khi nào dùng:** Payment webhooks, credit card processing

##### ☐ **OWASP Top 10** (9 tests)
- OWASP Top 10 Web Application Security Risks 2021
- **Tests include:**
  - **A01**: Broken Access Control
  - **A02**: Cryptographic Failures
  - **A03**: Injection (SQL, NoSQL, Command, XSS)
  - **A05**: Security Misconfiguration
  - **A07**: Authentication Failures
  - **A08**: Software/Data Integrity
  - **A09**: Security Logging Failures
  - **A10**: Server-Side Request Forgery (SSRF)
- **Khi nào dùng:** General web security audit

**💡 Tip:** Có thể chọn nhiều standards cùng lúc!

## 📊 Results Dashboard

### Statistics Cards
```
┌─────────┐  ┌─────────┐  ┌─────────┐
│   28    │  │    3    │  │    3    │
│ Passed  │  │ Failed  │  │Warnings │
└─────────┘  └─────────┘  └─────────┘
```

### Summary Alert
- 🟢 **Green**: All tests passed or minor issues
- 🟡 **Yellow**: Some tests failed (1-3 failures)
- 🔴 **Red**: Critical issues (4+ failures)

### Individual Test Results
Mỗi test hiển thị:
- **Category badge**: STRIDE, Injection, PCI DSS, OWASP
- **Status badge**: PASS (green), FAIL (red), WARN (yellow)
- **Test name**: Tên test cụ thể
- **Details**: Mô tả kết quả
- **Risk**: Rủi ro nếu test fail
- **Mitigation**: Cách khắc phục

## 🎯 Example Use Cases

### Use Case 1: Basic Webhook Test
**Scenario:** Test webhook không cần authentication

**Input:**
```
Target URL: https://webhook.site/your-unique-id
Shared Secret: (để trống)
Standards: ☑ OWASP
```

### Use Case 2: Payment Webhook (PCI DSS)
**Scenario:** Test webhook xử lý thanh toán

**Input:**
```
Target URL: https://payments.example.com/webhook
Shared Secret: stripe-webhook-secret-key
Payload: {"event": "payment.succeeded", "amount": 100.00}
Standards: ☑ STRIDE ☑ PCI-DSS
Custom Headers: {"X-Stripe-Signature": "..."}
```

### Use Case 3: API with Custom Auth
**Scenario:** Webhook cần API key trong header

**Input:**
```
Target URL: https://api.example.com/webhook
Shared Secret: (để trống hoặc có)
Standards: ☑ STRIDE ☑ OWASP
Custom Headers: 
{
  "X-API-Key": "prod-api-key-12345",
  "Authorization": "Bearer your-token"
}
```

### Use Case 4: Comprehensive Security Audit
**Scenario:** Full security testing với tất cả standards

**Input:**
```
Target URL: https://production-api.example.com/webhook
Shared Secret: super-secure-secret-key-256-bits
Payload: {"event": "user.action", "user_id": 123}
Standards: ☑ STRIDE ☑ PCI-DSS ☑ OWASP
Custom Headers:
{
  "X-API-Key": "production-key",
  "X-Client-ID": "web-app",
  "X-Request-ID": "req-12345"
}
```
**Result:** 28 total tests (12 STRIDE + 7 PCI DSS + 9 OWASP)

### Use Case 5: GitHub Webhook
**Scenario:** Test GitHub webhook integration

**Input:**
```
Target URL: https://api.example.com/github-webhook
Shared Secret: github-webhook-secret
Signature Header: X-Hub-Signature-256
Signature Prefix: sha256=
Payload: {"action": "opened", "repository": {"name": "repo"}}
Standards: ☑ STRIDE
```

### Use Case 6: Slack Webhook
**Scenario:** Test Slack incoming webhook

**Input:**
```
Target URL: https://hooks.slack.com/services/T00/B00/XXX
Shared Secret: (để trống - Slack không dùng HMAC)
Payload: {"text": "Test message"}
Standards: ☑ OWASP
```

## 🔍 Understanding Test Results

### PASS ✅
- Test đã vượt qua
- Webhook có bảo mật tốt cho test này
- Không cần action

### FAIL ❌
- Test thất bại
- Phát hiện lỗ hổng bảo mật
- **Action required:** Đọc Risk và Mitigation để fix

### WARN ⚠️
- Test không thể thực hiện hoặc kết quả không chắc chắn
- Có thể do thiếu configuration (vd: không có secret)
- Review để xác định có cần fix không

## 🛡️ Security Best Practices

### Khi test:
1. ✅ **Dùng test environment** - Không test production
2. ✅ **Rotate secrets** - Dùng test secrets, không dùng production secrets
3. ✅ **Monitor logs** - Kiểm tra logs của webhook server
4. ✅ **Review all failures** - Mỗi FAIL là một lỗ hổng bảo mật

### Sau khi test:
1. 📝 **Document results** - Lưu lại kết quả scan
2. 🔧 **Fix failures** - Ưu tiên fix các FAIL
3. 🔒 **Re-test** - Scan lại sau khi fix
4. ✅ **Regular scans** - Scan định kỳ (weekly/monthly)

## 💡 Tips & Tricks

### Tip 1: Test từng standard riêng
Chạy từng standard riêng để dễ phân tích:
- First: ☑ STRIDE only
- Then: ☑ PCI-DSS only
- Finally: ☑ OWASP only

### Tip 2: Copy-paste custom headers từ production
Lấy headers từ production requests để test realistic hơn:
```bash
# Check production headers
curl -I https://api.example.com/webhook
```

### Tip 3: Test với và không có secret
- Run 1: Với secret → Test signature validation
- Run 2: Không secret → Test general security

### Tip 4: Save good payloads
Lưu payload examples cho các loại events:
- `user.created`
- `payment.succeeded`
- `order.completed`
- etc.

## 🐛 Troubleshooting

### Issue: "Connection refused"
**Solution:**
- Verify target URL is accessible
- Check firewall settings
- Try with webhook.site first

### Issue: "Invalid JSON format"
**Solution:**
- Validate JSON syntax (use jsonlint.com)
- Remove comments from JSON
- Check quotes and commas

### Issue: "All signature tests WARN"
**Solution:**
- Ensure shared secret is provided
- Check signature header name matches server
- Verify signature prefix is correct

### Issue: "Timeout errors"
**Solution:**
- Webhook server might be slow
- Increase timeout (future feature)
- Test with simpler payload

## 📱 Mobile Support

Web interface is **fully responsive**:
- ✅ Works on tablets (iPad, Android tablets)
- ✅ Works on phones (iPhone, Android phones)
- ✅ Touch-friendly UI
- ✅ Scrollable results

## 🎨 UI Features

- **Bootstrap 5**: Modern, clean design
- **Icons**: Bootstrap Icons for visual clarity
- **Colors**: Intuitive color coding (green/yellow/red)
- **Animations**: Smooth transitions
- **Dark text on light background**: Easy to read
- **Loading spinner**: Clear progress indication
- **Collapsible sections**: Hide/show advanced options

## 🔗 API Documentation

Access Swagger UI at: **http://localhost:8080/docs**
- Interactive API documentation
- Try out API endpoints
- See request/response schemas

## 📞 Need Help?

- Check `FEATURES_V2.md` for CLI usage
- Check `README.md` for overview
- Check `HUONG_DAN_TIENG_VIET.md` for Vietnamese guide

---

**Version:** 2.0.0  
**Last Updated:** October 9, 2025  
**Interface:** Bootstrap 5 + Python FastAPI
