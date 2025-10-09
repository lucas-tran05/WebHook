# Quick Start Guide - Examples

## 🚀 Chạy Examples

### Bước 1: Start Server

```bash
python web_scanner.py
```

Server sẽ chạy tại: http://localhost:8080

### Bước 2: Chạy Examples

**Example 1: STRIDE Basic Test**
```bash
python example_1_stride.py
```
- Test cơ bản nhất với STRIDE threat model
- Khoảng 27 tests
- Thời gian: ~30-60 giây

**Example 2: OWASP with SSRF**
```bash
python example_2_owasp.py
```
- Test OWASP Top 10 vulnerabilities
- Đặc biệt test SSRF (Server-Side Request Forgery)
- Khoảng 30 tests

**Example 3: PCI-DSS Compliance**
```bash
python example_3_pci_dss.py
```
- Test PCI-DSS compliance
- Scan cho cardholder data (credit card numbers, CVV)
- Khoảng 30 tests

**Example 4: Full Security Scan**
```bash
python example_4_full_scan.py
```
- Comprehensive scan với cả 3 standards
- Khoảng 85+ tests
- Thời gian: ~1-2 phút
- Tự động save kết quả ra JSON file

## 📝 Lưu Ý

### Thay URL Test
Mở file example và thay:
```python
"target_url": "https://webhook.site/unique-id-here"
```

Bằng URL thật của bạn từ https://webhook.site

### Kết Quả

- ✅ **PASS**: Endpoint an toàn, đã chặn attack
- ❌ **FAIL**: Phát hiện lỗ hổng bảo mật
- ⚠️ **WARN**: Cảnh báo, cần kiểm tra

## 📚 Documentation Đầy Đủ

Xem file `INSTALLATION_GUIDE.md` để biết:
- Hướng dẫn cài đặt chi tiết
- Giải thích từng test
- Troubleshooting
- API documentation

## 💡 Tips

1. Chạy từng example riêng trước khi chạy full scan
2. Dùng webhook.site để test (không cần setup backend)
3. Check server logs để debug
4. Example 4 tự động save results ra JSON file

## ❓ Issues

Nếu gặp lỗi:
- Đảm bảo server đang chạy (python web_scanner.py)
- Check port 8080 không bị chiếm
- Cài đặt dependencies: `pip install -r requirements.txt`
