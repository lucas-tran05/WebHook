# Hướng Dẫn Cài Đặt và Chạy Test

## 📋 Yêu Cầu Hệ Thống

- Python 3.8 trở lên
- pip (Python package manager)
- Git (optional)

## 🚀 Cài Đặt

### 1. Clone hoặc Download Project

```bash
# Nếu dùng Git
git clone https://github.com/lucas-tran05/WebHook.git
cd WebHook

# Hoặc download ZIP và giải nén
```

### 2. Tạo Virtual Environment (Khuyến nghị)

**Windows:**
```powershell
python -m venv .venv
.venv\Scripts\activate
```

**Linux/Mac:**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Cài Đặt Dependencies

```bash
pip install -r requirements.txt
```

**Packages chính:**
- FastAPI: Web framework
- Uvicorn: ASGI server
- HTTPX: HTTP client
- Pydantic: Data validation
- Rich: Terminal output formatting

## 🎯 Chạy Application

### Option 1: Web Interface (Khuyến nghị)

```bash
python web_scanner.py
```

Server sẽ chạy tại: **http://localhost:8080**

### Option 2: CLI Mode

```bash
python main.py --url https://webhook.site/your-unique-id
```

## 🧪 Chạy Test Ví Dụ

### Test 1: Schema-Based Scan với STRIDE

Tạo file `test_stride_example.py`:

```python
import httpx

# Định nghĩa schema cho webhook
schema = [
    {"name": "event", "type": "string", "sample_value": "user.created"},
    {"name": "user_id", "type": "integer", "sample_value": "123"},
    {"name": "email", "type": "email", "sample_value": "test@example.com"}
]

# Gửi request để scan
response = httpx.post("http://localhost:8080/api/scan", json={
    "target_url": "https://webhook.site/your-unique-id",
    "shared_secret": "my_secret_key",
    "payload_schema": schema,
    "test_standards": ["STRIDE"]
}, timeout=60.0)

result = response.json()
print(f"✅ Đã chạy {len(result['results'])} tests")
print(f"📊 Scan ID: {result['scan_id']}")

# In kết quả
for test in result['results'][:5]:
    print(f"\n🔍 {test['name']}")
    print(f"   Status: {test['status']}")
    print(f"   Details: {test['details']}")
```

**Chạy test:**
```bash
# Đảm bảo web_scanner.py đang chạy trước
python test_stride_example.py
```

### Test 2: OWASP Top 10 với SSRF Check

Tạo file `test_owasp_ssrf.py`:

```python
import httpx

schema = [
    {"name": "event", "type": "string", "sample_value": "webhook.triggered"},
    {"name": "callback_url", "type": "url", "sample_value": "https://example.com/callback"},
    {"name": "user_id", "type": "integer", "sample_value": "456"}
]

response = httpx.post("http://localhost:8080/api/scan", json={
    "target_url": "https://webhook.site/your-unique-id",
    "shared_secret": "test_secret",
    "payload_schema": schema,
    "test_standards": ["OWASP"]
}, timeout=60.0)

result = response.json()

# Tìm SSRF tests
ssrf_tests = [t for t in result['results'] if 'SSRF' in t['name']]
print(f"🔍 Tìm thấy {len(ssrf_tests)} SSRF tests")

for test in ssrf_tests:
    print(f"\n⚠️  {test['name']}")
    print(f"   Status: {test['status']}")
```

**Chạy test:**
```bash
python test_owasp_ssrf.py
```

### Test 3: PCI-DSS Compliance (Cardholder Data)

Tạo file `test_pci_dss_example.py`:

```python
import httpx

schema = [
    {"name": "transaction_id", "type": "string", "sample_value": "txn_123456"},
    {"name": "amount", "type": "float", "sample_value": "99.99"},
    {"name": "card_token", "type": "string", "sample_value": "tok_visa_4111"}
]

response = httpx.post("http://localhost:8080/api/scan", json={
    "target_url": "https://webhook.site/your-unique-id",
    "shared_secret": "pci_test_key",
    "payload_schema": schema,
    "test_standards": ["PCI-DSS"]
}, timeout=60.0)

result = response.json()

# Tìm CHD (Cardholder Data) tests
chd_tests = [t for t in result['results'] if 'CHD' in t['name']]
print(f"💳 Tìm thấy {len(chd_tests)} Cardholder Data tests")

for test in chd_tests:
    print(f"\n🔒 {test['name']}")
    print(f"   Status: {test['status']}")
    if test['status'] == 'FAIL':
        print(f"   ⚠️  WARNING: {test['details']}")
```

**Chạy test:**
```bash
python test_pci_dss_example.py
```

### Test 4: Full Scan (Tất Cả Standards)

Tạo file `test_full_scan.py`:

```python
import httpx
import json

schema = [
    {"name": "event", "type": "string", "sample_value": "order.created"},
    {"name": "order_id", "type": "integer", "sample_value": "789"},
    {"name": "customer_email", "type": "email", "sample_value": "customer@example.com"},
    {"name": "webhook_url", "type": "url", "sample_value": "https://example.com/notify"},
    {"name": "user_role", "type": "string", "sample_value": "customer"}
]

print("🚀 Starting full security scan...")
print("=" * 80)

response = httpx.post("http://localhost:8080/api/scan", json={
    "target_url": "https://webhook.site/your-unique-id",
    "shared_secret": "full_scan_secret",
    "payload_schema": schema,
    "test_standards": ["STRIDE", "OWASP", "PCI-DSS"]
}, timeout=120.0)

result = response.json()

print(f"\n✅ Scan Complete!")
print(f"📊 Total Tests: {len(result['results'])}")
print(f"🆔 Scan ID: {result['scan_id']}")

# Phân loại theo standard
stride_tests = [t for t in result['results'] if 'STRIDE' in t['name']]
owasp_tests = [t for t in result['results'] if 'OWASP' in t['name']]
pci_tests = [t for t in result['results'] if 'PCI-DSS' in t['name']]

print(f"\n📋 Breakdown:")
print(f"   - STRIDE: {len(stride_tests)} tests")
print(f"   - OWASP: {len(owasp_tests)} tests")
print(f"   - PCI-DSS: {len(pci_tests)} tests")

# Đếm PASS/FAIL
passed = len([t for t in result['results'] if t['status'] == 'PASS'])
failed = len([t for t in result['results'] if t['status'] == 'FAIL'])
warnings = len([t for t in result['results'] if t['status'] == 'WARN'])

print(f"\n📊 Results:")
print(f"   ✅ PASS: {passed}")
print(f"   ❌ FAIL: {failed}")
print(f"   ⚠️  WARN: {warnings}")

# In top 5 failed tests
if failed > 0:
    print(f"\n❌ Failed Tests:")
    for test in [t for t in result['results'] if t['status'] == 'FAIL'][:5]:
        print(f"   - {test['name']}")
        print(f"     Reason: {test['details']}")

# Lưu kết quả ra file
with open("scan_results.json", "w") as f:
    json.dump(result, f, indent=2)
print(f"\n💾 Results saved to: scan_results.json")
```

**Chạy test:**
```bash
python test_full_scan.py
```

### Test 5: Test Với Custom Headers

Tạo file `test_custom_headers.py`:

```python
import httpx

schema = [
    {"name": "event", "type": "string", "sample_value": "payment.processed"}
]

response = httpx.post("http://localhost:8080/api/scan", json={
    "target_url": "https://webhook.site/your-unique-id",
    "shared_secret": "test_secret",
    "payload_schema": schema,
    "test_standards": ["STRIDE"],
    "custom_headers": {
        "X-Api-Version": "v2",
        "X-Client-Id": "test-client-123",
        "Authorization": "Bearer test-token"
    }
}, timeout=60.0)

result = response.json()
print(f"✅ Scan with custom headers: {len(result['results'])} tests")
```

**Chạy test:**
```bash
python test_custom_headers.py
```

## 🌐 Test Qua Web Interface

### 1. Mở Browser

Truy cập: http://localhost:8080

### 2. Điền Thông Tin

**Target Webhook URL:**
```
https://webhook.site/your-unique-id
```
*Lưu ý: Tạo URL test tại https://webhook.site*

**Shared Secret (Optional):**
```
my_secret_key_123
```

### 3. Định Nghĩa Schema

Click "Add Field" và nhập:

| Field Name | Type | Sample Value |
|------------|------|--------------|
| event | string | user.signup |
| user_id | integer | 12345 |
| email | email | user@example.com |
| callback_url | url | https://example.com/callback |

### 4. Chọn Security Standards

☑️ STRIDE  
☑️ OWASP  
☑️ PCI-DSS  

### 5. Click "Start Schema-Based Scan"

Kết quả sẽ hiển thị real-time với màu sắc:
- 🟢 **PASS**: Test thành công
- 🔴 **FAIL**: Phát hiện lỗ hổng
- 🟡 **WARN**: Cảnh báo

## 📊 Hiểu Kết Quả Test

### STRIDE Tests

| Test Name | Ý Nghĩa | PASS = Tốt | FAIL = Lỗ hổng |
|-----------|---------|------------|----------------|
| Spoofing - Request without authentication | Kiểm tra xác thực | Endpoint reject request không có signature | Endpoint chấp nhận request không xác thực |
| Tampering - HTTPS enforcement | Kiểm tra HTTPS | Chỉ chấp nhận HTTPS | Chấp nhận HTTP |
| Repudiation - Logging check | Kiểm tra logging | Response có request-id header | Không có logging |
| InfoDisclosure - Sensitive data | Kiểm tra rò rỉ dữ liệu | Dữ liệu nhạy cảm bị che | API key/password lộ ra |
| DoS - Rate limiting | Kiểm tra giới hạn request | HTTP 429 khi quá nhiều request | Chấp nhận unlimited requests |
| Privilege - SQL Injection | Kiểm tra injection | Input được sanitize | SQL injection thành công |

### OWASP Tests

| Test Name | Ý Nghĩa | PASS = Tốt | FAIL = Lỗ hổng |
|-----------|---------|------------|----------------|
| A01 - Cross-account access | Kiểm tra phân quyền | Không thể access dữ liệu user khác | IDOR vulnerability |
| A03 - SQL/NoSQL Injection | Kiểm tra injection | Input được escape | Injection thành công |
| A10 - SSRF Internal IP | Kiểm tra SSRF | Chặn localhost/10.x/192.168.x | Có thể gọi internal IPs |

### PCI-DSS Tests

| Test Name | Ý Nghĩa | PASS = Tốt | FAIL = Lỗ hổng |
|-----------|---------|------------|----------------|
| CHD - Credit card in payload | Kiểm tra lưu thẻ | Không có số thẻ trong logs | Số thẻ bị lưu trữ |
| CHD - CVV in payload | Kiểm tra CVV | CVV không được store | CVV bị lưu (vi phạm PCI) |
| 6.5.1 - SQL Injection | Kiểm tra injection | Input được sanitize | SQL injection |

## 🔧 Troubleshooting

### Lỗi: ModuleNotFoundError

```bash
# Cài đặt lại dependencies
pip install -r requirements.txt
```

### Lỗi: Port 8080 đã được sử dụng

**Windows:**
```powershell
# Tìm process đang dùng port 8080
netstat -ano | findstr :8080

# Kill process (thay PID bằng số từ lệnh trên)
taskkill /PID <PID> /F
```

**Linux/Mac:**
```bash
# Tìm và kill process
lsof -ti:8080 | xargs kill -9
```

### Lỗi: Connection timeout

- Kiểm tra internet connection
- Tăng timeout trong code:
```python
response = httpx.post(..., timeout=120.0)  # 120 seconds
```

### Lỗi: 422 Unprocessable Entity

- Kiểm tra request body có đúng format không
- Field `target_url` là required (không phải `url`)
- Field `payload_schema` phải là array of objects

## 📚 API Documentation

Khi server chạy, truy cập: http://localhost:8080/docs

Interactive API documentation với Swagger UI:
- Test API trực tiếp từ browser
- Xem request/response schema
- Download OpenAPI spec

## 🎓 Examples Repository

Tất cả các test examples trên có thể download tại:
https://github.com/lucas-tran05/WebHook/tree/main/examples

## 💡 Tips

1. **Dùng webhook.site để test:**
   - Tạo unique URL tại https://webhook.site
   - Xem real-time requests được gửi
   - Không cần setup backend thật

2. **Test từng standard riêng trước:**
   - Start với `["STRIDE"]` để hiểu flow
   - Sau đó test `["OWASP"]` và `["PCI-DSS"]`
   - Cuối cùng test all 3 cùng lúc

3. **Save kết quả:**
   ```python
   with open("results.json", "w") as f:
       json.dump(result, f, indent=2)
   ```

4. **Check logs:**
   - Server logs hiển thị chi tiết mỗi request
   - Dùng để debug khi test fail

## 🆘 Support

Issues: https://github.com/lucas-tran05/WebHook/issues  
Email: lucas.tran05@example.com

## 📝 License

MIT License - Free to use and modify
