# 🔐 Công cụ Quét Bảo mật Webhook# 🚀 Hướng Dẫn Sử Dụng - Webhook Security Auditor



Công cụ kiểm tra bảo mật toàn diện cho webhook endpoints dựa trên mô hình STRIDE với phát hiện tấn công injection.## ✨ Tính Năng Mới!



## ✨ Tính năng### 1. 💉 **Test Injection Attacks** 

- SQL Injection

- **18 Bài kiểm tra bảo mật** bao gồm:- NoSQL Injection  

  - ✅ **Mô hình STRIDE**: Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Privilege Escalation- Command Injection

  - ✅ **Tấn công Injection**: SQL, NoSQL, Command, XSS, Path Traversal, Template Injection- XSS (Cross-Site Scripting)

  - Path Traversal

- **Hai giao diện**:- Template Injection

  - 🖥️ **CLI**: Giao diện dòng lệnh cho tự động hóa

  - 🌐 **Web UI**: Giao diện Bootstrap đẹp mắt, dễ sử dụng### 2. 🌐 **Web Interface**

- Giao diện đẹp, dễ sử dụng

- **Xác thực HMAC Signature**: Kiểm tra bảo mật chữ ký webhook- Không cần dùng command line

- **Báo cáo chi tiết**: Kết quả chi tiết với đánh giá rủi ro và khuyến nghị khắc phục- Kết quả hiển thị trực quan



## 🚀 Bắt đầu nhanh---



### Cài đặt## 🎯 Cách Sử Dụng



```bash### Phương Pháp 1: Giao Diện Web (Dễ Nhất!)

# Clone repository

git clone <your-repo-url>```powershell

cd WebHook# Chạy web interface

python main.py web

# Tạo virtual environment```

python -m venv .venv

.venv\Scripts\Activate.ps1  # Windows PowerShellSau đó mở trình duyệt tại: **http://localhost:8080**



# Cài đặt dependencies**Các bước:**

pip install -r requirements.txt1. Nhập URL webhook cần test

```2. Nhập shared secret

3. Nhập payload mẫu (JSON)

### Sử dụng4. Click "Start Security Scan"

5. Xem kết quả chi tiết!

#### Giao diện Web (Khuyến nghị)

### Phương Pháp 2: Command Line

```bash

python main.py web```powershell

```# Terminal 1: Chạy mock server

python main.py mock

Sau đó mở **http://localhost:8080** trong trình duyệt và nhập:

- URL webhook cần kiểm tra# Terminal 2: Chạy scan

- Shared secret (khóa bí mật)python main.py scan --target-url http://localhost:8000 --secret "test" --payload '{"test": true}'

- Sample payload (dữ liệu mẫu JSON)```

- Tùy chọn: Cấu hình nâng cao

---

#### Giao diện CLI

## 📊 Các Test Được Thực Hiện

```bash

python main.py scan \### STRIDE Tests (12 tests)

  --target-url https://api.example.com/webhook \1. ✅ Kiểm tra chữ ký (signature) 

  --secret "your-secret-key" \2. ✅ Phát hiện tampering

  --payload '{"event": "test", "data": "sample"}'3. ✅ Replay attack

```4. ✅ Timestamp validation

5. ✅ HTTPS check

## 📊 Các bài kiểm tra bảo mật6. ✅ Server headers

7. ✅ Error messages

### Danh mục STRIDE (12 bài test)8. ✅ Large payload

1. **Spoofing** - Phát hiện chữ ký thiếu/không hợp lệ9. ✅ Rate limiting

2. **Tampering** - Xác thực chữ ký, phát hiện payload bị sửa đổi10. ✅ Privilege escalation

3. **Repudiation** - Xác thực timestamp, phát hiện replay attack11. ✅ Parameter pollution

4. **Information Disclosure** - Kiểm tra HTTPS, phân tích lỗi trả về

5. **Denial of Service** - Xử lý payload lớn, rate limiting### Injection Tests (6 tests) 🆕

6. **Privilege Escalation** - Phát hiện injection field không được phép12. ✅ SQL Injection

13. ✅ NoSQL Injection

### Kiểm tra Injection (6 bài test)14. ✅ Command Injection

1. **SQL Injection** - Kiểm tra lỗ hổng SQL injection15. ✅ XSS Protection

2. **NoSQL Injection** - MongoDB operator injection16. ✅ Path Traversal

3. **Command Injection** - Thử thực thi lệnh OS17. ✅ Template Injection

4. **XSS** - Cross-site scripting vectors

5. **Path Traversal** - Thử truy cập thư mục không được phép**Tổng cộng: 18 tests bảo mật!**

6. **Template Injection** - Server-side template injection

---

## 🎯 Tùy chọn CLI

## 🎨 Giao Diện Web

```bash

python main.py scan --help### Tính Năng

- ✨ Giao diện đẹp với gradient màu

Tùy chọn:- 📊 Dashboard hiển thị thống kê

  --target-url TEXT          URL webhook cần kiểm tra (bắt buộc)- 🎯 Form dễ sử dụng

  --secret TEXT              Shared secret cho HMAC (bắt buộc)- 📝 Kết quả chi tiết cho từng test

  --method TEXT              HTTP method (mặc định: POST)- 🔴 Màu đỏ = Lỗi bảo mật

  --signature-header TEXT    Tên header chứa chữ ký- 🟢 Màu xanh = An toàn

  --timestamp-header TEXT    Tên header chứa timestamp- 🟡 Màu vàng = Cảnh báo

  --payload TEXT             Sample JSON payload

  --signature-prefix TEXT    Prefix của chữ ký (mặc định: sha256=)### API Documentation

```- Swagger UI: http://localhost:8080/docs

- ReDoc: http://localhost:8080/redoc

## 🌐 Giao diện Web

---

Giao diện web cung cấp:

- 📝 Form động với validation## 💡 Ví Dụ Thực Tế

- 🎨 UI Bootstrap 5 hiện đại

- 📊 Kết quả real-time với thống kê### Test 1: Webhook Đơn Giản

- 🔍 Chi tiết từng bài test

- ⚙️ Tùy chọn cấu hình nâng cao**Web Interface:**

- 📱 Thiết kế responsive1. Mở http://localhost:8080

2. Target URL: `http://localhost:8000`

### Hướng dẫn sử dụng Web Interface3. Secret: `test-secret`

4. Payload: `{"event": "test"}`

1. **Khởi động web server**:5. Click scan!

```bash

python main.py web**Command Line:**

``````powershell

python main.py scan --target-url http://localhost:8000 --secret "test-secret" --payload '{"event": "test"}'

2. **Mở trình duyệt** tại http://localhost:8080```



3. **Nhập thông tin**:### Test 2: GitHub Webhook

   - **Target URL**: URL webhook cần test (ví dụ: https://api.example.com/webhook)

   - **Shared Secret**: Khóa bí mật dùng để tạo HMAC signature```powershell

   - **HTTP Method**: Chọn POST, PUT, hoặc PATCHpython main.py scan \

   - **Sample Payload**: Nhập JSON payload mẫu hợp lệ  --target-url http://localhost:8000 \

  --secret "github-secret" \

4. **Advanced Options** (tùy chọn):  --signature-header "X-Hub-Signature-256" \

   - Click "Advanced Options" để mở rộng  --signature-prefix "sha256=" \

   - Cấu hình tên header cho signature và timestamp  --payload '{"ref": "refs/heads/main"}'

   - Chọn các category test cụ thể (hoặc để trống để chạy tất cả)```



5. **Chạy scan**:### Test 3: Test Injection Vulnerabilities

   - Click nút "Start Security Scan"

   - Đợi 30-60 giây để hoàn thành```powershell

   - Xem kết quả với statistics và chi tiết từng testpython main.py scan \

  --target-url http://localhost:8000 \

### Ví dụ form input  --secret "test" \

  --payload '{"username": "admin", "comment": "<script>alert(1)</script>"}'

``````

Target URL: https://webhook.site/your-unique-id

Shared Secret: my-secret-key-123Scanner sẽ tự động test:

HTTP Method: POST- ✅ SQL injection attempts

Sample Payload:- ✅ XSS payloads

{- ✅ Command injection

  "event": "user.created",- ✅ Path traversal

  "user_id": 12345,- ✅ Và nhiều hơn nữa!

  "email": "user@example.com"

}---

```

## 🔐 Kết Quả Mong Đợi

## 📁 Cấu trúc dự án

### Hệ Thống An Toàn ✅

``````

WebHook/📊 Scan Results

├── main.py                          # CLI entry point━━━━━━━━━━━━━━━━━━

├── web_scanner.py                   # Web interface✓ Passed: 18

├── requirements.txt                 # Python dependencies✗ Failed: 0

├── webhook_auditor/⚠ Warnings: 0

│   ├── scanner/

│   │   ├── config.py               # Cấu hình✅ All security tests passed!

│   │   ├── orchestrator.py         # Điều phối tests```

│   │   ├── spoofing_tests.py       # Tests spoofing

│   │   ├── repudiation_tests.py    # Tests repudiation### Phát Hiện Lỗ Hổng ❌

│   │   ├── info_disclosure_tests.py # Tests info disclosure```

│   │   ├── dos_tests.py            # Tests DoS📊 Scan Results

│   │   ├── privilege_escalation_tests.py # Tests privilege━━━━━━━━━━━━━━━━━━

│   │   └── injection_tests.py      # Tests injection✓ Passed: 12

│   └── utils/✗ Failed: 4

│       ├── crypto.py               # HMAC utilities⚠ Warnings: 2

│       └── reporter.py             # Tạo báo cáo

└── README.md❌ Vulnerabilities detected:

```- SQL Injection possible

- No signature validation

## 🔧 Cấu hình- XSS vulnerability

- No rate limiting

Tất cả cài đặt có thể được cấu hình qua:```

- CLI arguments

- Form trên web interface---

- Advanced options (signature headers, prefixes, etc.)

## 🛠️ Các Lệnh Chính

## 💡 Best Practices

```powershell

### Cho người phát triển webhook# Xem help

python main.py --help

1. **Luôn xác thực chữ ký** - Verify HMAC signatures trên tất cả requests

2. **Chỉ dùng HTTPS** - Từ chối kết nối không mã hóa# Chạy mock server

3. **Xác thực timestamp** - Ngăn chặn replay attackspython main.py mock

4. **Rate limiting** - Bảo vệ khỏi DoS

5. **Sanitize inputs** - Ngăn chặn injection attacks# Chạy security scan

6. **Log đầy đủ** - Bật audit trailspython main.py scan --target-url <URL> --secret <SECRET>

7. **Kiểm tra authorization** - Check permissions cho các thao tác nhạy cảm

# Chạy web interface

### Cho người kiểm trapython main.py web



1. **Dùng test environments** - Không test trên production# Xem ví dụ

2. **Rotate secrets** - Dùng secret riêng cho testingpython main.py examples

3. **Monitor logs** - Kiểm tra hành vi bất thường

4. **Review kết quả cẩn thận** - Failed tests = lỗ hổng bảo mật# Test installation

python test_installation.py

## ❓ Troubleshooting

# Xem payloads mẫu

### Lỗi thường gặppython example_payloads.py

```

1. **Connection refused**

   - Đảm bảo URL có thể truy cập được---

   - Kiểm tra firewall settings

   - Xác nhận server đang chạy## 📚 Tài Liệu



2. **Signature validation fails**### Tiếng Anh

   - Verify shared secret đúng- `README.md` - Documentation đầy đủ

   - Kiểm tra tên signature header- `NEW_FEATURES.md` - Tính năng mới

   - Xác nhận format của signature prefix- `QUICKSTART.md` - Hướng dẫn nhanh

- `PAYLOAD_EXAMPLES.md` - Ví dụ payloads

3. **SSL certificate errors**

   - Dùng HTTPS cho production endpoints### File Quan Trọng

   - Kiểm tra certificate hợp lệ- `example_payloads.py` - 20+ payload mẫu

- `web_scanner.py` - Web interface code

## 📝 License- `injection_tests.py` - Injection tests



MIT License---



## 👤 Tác giả## 🎯 Use Cases



Your Name### 1. Development Testing

Dùng mock server để xem webhook requests:

---```powershell

python main.py mock

Được tạo với ❤️ cho bảo mật webhook# Gửi requests và xem details

```

### 2. Security Audit
Scan webhook trước khi deploy production:
```powershell
python main.py scan --target-url https://staging.api.com/webhook --secret "key"
```

### 3. Team Demo
Dùng web interface để demo cho team:
```powershell
python main.py web
# Mở browser và share screen
```

### 4. CI/CD Integration
Integrate vào pipeline:
```bash
# Script để test webhooks tự động
python main.py scan --target-url $WEBHOOK_URL --secret $SECRET
```

---

## 🚨 Các Lỗ Hổng Thường Gặp

### 1. SQL Injection
**Nguy hiểm:** ⭐⭐⭐⭐⭐
**Khắc phục:** Dùng parameterized queries

### 2. Không Validate Signature
**Nguy hiểm:** ⭐⭐⭐⭐⭐
**Khắc phục:** Implement HMAC signature check

### 3. XSS (Cross-Site Scripting)
**Nguy hiểm:** ⭐⭐⭐⭐
**Khắc phục:** Encode output, validate input

### 4. Command Injection
**Nguy hiểm:** ⭐⭐⭐⭐⭐
**Khắc phục:** Không dùng shell commands với user input

### 5. No Rate Limiting
**Nguy hiểm:** ⭐⭐⭐
**Khắc phục:** Implement rate limits (100 req/min)

### 6. Path Traversal
**Nguy hiểm:** ⭐⭐⭐⭐
**Khắc phục:** Validate file paths, dùng whitelist

---

## 💻 Demo Nhanh

### Bước 1: Start Mock Server
```powershell
python main.py mock
```
Output:
```
🚀 Starting Mock Webhook Server on http://0.0.0.0:8000
📌 Send POST requests to inspect webhook data
```

### Bước 2: Scan (Terminal khác)
```powershell
python main.py scan --target-url http://localhost:8000 --secret "test"
```

Hoặc dùng Web:
```powershell
python main.py web
# Mở http://localhost:8080
```

### Bước 3: Xem Kết Quả
- ✅ Tests passed = An toàn
- ❌ Tests failed = Cần fix
- ⚠️ Warnings = Nên cải thiện

---

## 🎓 Tips & Tricks

### Tip 1: Dùng webhook.site
Test mà không cần server:
1. Vào https://webhook.site/
2. Copy unique URL
3. Scan với URL đó

### Tip 2: Save Results
Web interface tự động save results - có thể xem lại sau

### Tip 3: Custom Payloads
Check `example_payloads.py` để có payloads thực tế:
```python
from example_payloads import USER_CREATED, PAYMENT_SUCCEEDED
```

### Tip 4: Test Từng Phần
```python
# Chỉ test injection
test_categories=["injection"]

# Test STRIDE + injection
test_categories=["spoofing", "injection", "dos"]
```

---

## 📞 Support

**Cần help?**
- Chạy `python main.py --help`
- Xem `NEW_FEATURES.md` cho tính năng mới
- Check `PAYLOAD_EXAMPLES.md` cho ví dụ
- Mở http://localhost:8080/docs cho API docs

---

## 🎉 Tóm Tắt

Bạn hiện có:
- ✅ 18 security tests (STRIDE + Injection)
- ✅ Web interface đẹp mắt
- ✅ RESTful API
- ✅ Mock webhook server
- ✅ 20+ payload examples
- ✅ Complete documentation

**Bắt đầu test webhooks của bạn ngay!** 🚀🔐

```powershell
# Quick start
python main.py web
# Mở http://localhost:8080 và enjoy! 🎊
```
