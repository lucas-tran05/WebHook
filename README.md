# Webhook Security Scanner (STRIDE / PCI DSS / OWASP)

Công cụ quét bảo mật cho webhook, giúp bạn kiểm thử tự động theo các tiêu chuẩn/phương pháp: STRIDE, PCI DSS và OWASP Top 10. Ứng dụng hỗ trợ chạy bằng CLI và Web UI, tạo chữ ký HMAC, kiểm tra xác thực, chống giả mạo/tampering, chống replay, rò rỉ thông tin, DoS, nâng quyền, và nhiều dạng Injection.

## Tính năng chính

- Quét bảo mật webhook theo STRIDE: Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege
- Bài test PCI DSS quan trọng (mã hóa truyền tải, header bảo mật, logging/audit, v.v.)
- Bài test OWASP Top 10 trọng yếu (Access Control, Injection, Security Headers, SSRF, v.v.)
- Web UI đẹp, dễ dùng: dựng payload theo schema trường, tự sinh nhiều test case injection
- CLI tiện dụng để chạy quét nhanh trong CI/CD
- Tính điểm an toàn 0–10 và tóm tắt PASS/FAIL/WARN

## Cài đặt và chạy

Yêu cầu: Python 3.10+ (khuyến nghị), Windows/Ubuntu/macOS đều được.

1) Tạo và kích hoạt môi trường ảo (Windows PowerShell)

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

2) Cài dependency

```powershell
pip install -r requirements.txt
```

3) Chạy Web UI (khuyến nghị để khám phá nhanh)

```powershell
python web_scanner.py
```

- Mở: http://localhost:8080 (UI) và http://localhost:8080/docs (OpenAPI)

4) Chạy bằng CLI

```powershell
# Ví dụ cơ bản (STRIDE):
python main.py scan --target-url https://api.example.com/webhook --secret your-secret

# Chạy nhiều chuẩn cùng lúc:
python main.py scan --target-url https://api.example.com/webhook --standards STRIDE,PCI-DSS,OWASP

# Thêm custom header:
python main.py scan --target-url https://api.example.com/webhook --custom-header "X-API-Key: abc123"
```

Gợi ý: Nếu webhook không yêu cầu xác thực, bạn có thể bỏ --secret. Một số bài test nâng cao sẽ được bỏ qua khi thiếu shared secret.

## Cấu trúc thư mục (quan trọng)

```
main.py                    # CLI: lệnh scan và web
web_scanner.py             # Entrypoint Web UI (FastAPI + Uvicorn)

webhook_auditor/
  scanner/
    config.py              # Model cấu hình ScannerSettings
    orchestrator.py        # Điều phối chạy test theo chuẩn đã chọn, gom kết quả
    spoofing_tests.py      # STRIDE: Spoofing & Tampering (chữ ký, integrity)
    repudiation_tests.py   # STRIDE: Repudiation (timestamp, chống replay)
    info_disclosure_tests.py # STRIDE: Information Disclosure (HTTPS, header, error)
    dos_tests.py           # STRIDE: Denial of Service (payload lớn, rate-limit)
    privilege_escalation_tests.py # STRIDE: Elevation of Privilege (trường đặc quyền)
    injection_tests.py     # STRIDE: Injection (SQL/NoSQL/Command/XSS/Path/Template)
    pci_dss_tests.py       # PCI DSS: TLS, header, logging, SQLi/XSS, v.v.
    owasp_tests.py         # OWASP Top 10: Access Control, Headers, Injection, SSRF...
  utils/
    crypto.py              # Tính/kiểm tra chữ ký HMAC
    reporter.py            # In báo cáo kết quả đẹp bằng rich

webui/
  app.py                   # Tạo FastAPI app (CORS, routes)
  routes.py                # Trang HTML UI + API /api/scan
  models.py                # Pydantic models cho request/response Web UI
  generators.py            # Sinh test payload theo schema trường (STRIDE/PCI/OWASP)
  scoring.py               # Tính điểm an toàn 0–10 theo kết quả
  cache.py                 # Bộ nhớ cache kết quả quét tạm thời
```

Lưu ý: Bỏ qua các tệp không quan trọng như .gitignore, …

## Chuẩn đầu ra (return) của các module scanner

Tất cả các module test đều trả về danh sách các đối tượng kết quả: `List[Dict]`. Mỗi phần tử là một dict có các trường tiêu chuẩn sau (tùy test có thể thêm/bớt `risk`, `mitigation`, `payload_name`, `response_status`):

- category: Nhóm/chuẩn bài test (ví dụ: "Spoofing & Tampering", "Repudiation", "Information Disclosure", "Denial of Service", "Elevation of Privilege", "Injection Attacks", hoặc "OWASP - ...", "PCI DSS - Requirement ...")
- name: Tên bài test (ví dụ: "Request with No Signature", "Old Timestamp Check")
- status: "PASS" | "FAIL" | "WARN"
- details: Mô tả ngắn gọn kết quả
- risk: Mô tả rủi ro (thường có khi FAIL)
- mitigation: Gợi ý khắc phục (thường có khi FAIL)
- payload_name: Nhãn payload (khi chạy nhiều payload khác nhau)
- response_status: HTTP status trả về từ endpoint (nếu có)

Ví dụ một phần tử kết quả:

```json
{
  "category": "Spoofing & Tampering",
  "name": "Request with No Signature",
  "status": "PASS",
  "details": "Server correctly rejected request without signature (HTTP 401)",
  "risk": "",
  "mitigation": ""
}
```

### Cụ thể theo từng file

- `spoofing_tests.py` → `run_spoofing_tampering_tests(config, client) -> List[Dict]`
  - Kiểm tra: không có chữ ký, chữ ký sai, payload bị sửa nhưng dùng chữ ký cũ
  - category: "Spoofing & Tampering"; status: PASS/FAIL/WARN; có thể có `risk`, `mitigation`

- `repudiation_tests.py` → `run_repudiation_tests(config, client) -> List[Dict]`
  - Kiểm tra: timestamp cũ (nếu cấu hình `timestamp_header_name`), phát hiện replay
  - category: "Repudiation"; status: PASS/FAIL/WARN; có thể có `risk`, `mitigation`

- `info_disclosure_tests.py` → `run_info_disclosure_tests(config, client) -> List[Dict]`
  - Kiểm tra: dùng HTTPS, header Server quá chi tiết, lỗi chi tiết lộ thông tin
  - category: "Information Disclosure"; status: PASS/FAIL/WARN

- `dos_tests.py` → `run_dos_tests(config, client) -> List[Dict]`
  - Kiểm tra: payload lớn (~10MB), rate limiting (burst ~15 request)
  - category: "Denial of Service"; status: PASS/FAIL/WARN; có thể có `risk`, `mitigation`

- `privilege_escalation_tests.py` → `run_privilege_escalation_tests(config, client) -> List[Dict]`
  - Kiểm tra: trường đặc quyền dư thừa (is_admin/role/permissions), ô nhiễm tham số (case khác nhau)
  - category: "Elevation of Privilege"; status: PASS/FAIL/WARN

- `injection_tests.py` → `run_injection_tests(config, client) -> List[Dict]`
  - Kiểm tra: SQLi, NoSQLi, Command Injection, XSS, Path Traversal, Template Injection
  - category: "Injection Attacks"; status: PASS/FAIL/WARN; có `risk`, `mitigation` khi FAIL

- `pci_dss_tests.py` → `run_pci_dss_tests(config) -> List[Dict]`
  - Tập hợp các kiểm tra: TLS 1.2+, cipher mạnh (mức gợi ý), chống SQLi/XSS cơ bản, logging/audit, tiết lộ thông tin, v.v.
  - Mỗi phần tử từ các test con có dạng Dict: `{"category": "PCI DSS - Requirement <n>", "name": ..., "status": ..., "details": ..., "risk": ..., "mitigation": ...}`

- `owasp_tests.py` → `run_owasp_tests(config) -> List[Dict]`
  - Tập hợp các kiểm tra: A01 (Access Control), A02 (Crypto in transit), A03 (Injection cơ bản), A05 (Headers/Error), A07 (Auth), A08 (Integrity), A09 (Logging), A10 (SSRF)
  - Mỗi phần tử là Dict: `{"category": "OWASP - Axx ...", "name": ..., "status": ..., "details": ...}` (có thể có `risk`/`mitigation`)

- `orchestrator.py` → `run_all_tests(config) -> List[Dict]`
  - Điều phối chạy theo chuẩn đã chọn (STRIDE, PCI-DSS, OWASP), trả về toàn bộ `List[Dict]` gộp từ tất cả test
  - Đồng thời in báo cáo tổng hợp ra console qua `utils.reporter.generate_report`

## Cấu hình đầu vào (ScannerSettings)

`webhook_auditor/scanner/config.py` định nghĩa `ScannerSettings` (Pydantic):

- target_url: URL webhook cần quét
- http_method: Mặc định POST
- shared_secret: (tùy chọn) bí mật để tạo chữ ký HMAC
- signature_header_name: tên header chữ ký (mặc định: X-Webhook-Signature)
- timestamp_header_name: tên header timestamp (tùy chọn)
- sample_valid_payload: payload mẫu JSON dạng chuỗi
- signature_prefix: tiền tố chữ ký, ví dụ `sha256=`
- custom_headers: header bổ sung, ví dụ `{ "X-API-Key": "..." }`
- test_standards: danh sách chuẩn cần chạy: STRIDE, PCI-DSS, OWASP

## Web UI: tạo test theo schema trường

Trong Web UI, bạn có thể khai báo schema trường (tên, kiểu dữ liệu, giá trị mẫu). Module `webui/generators.py` sẽ sinh nhiều payload kiểm thử tự động theo STRIDE/PCI/OWASP cho từng trường (SQLi/XSS/Command/Path/SSRF/biên số nguyên…). API `/api/scan` sẽ thực thi lần lượt và trả kết quả dạng `ScanResponse` (xem `webui/models.py`).

## Tính điểm an toàn (0–10)

`webui/scoring.py` tính điểm theo quy tắc:
- PASS = 1 điểm; FAIL = 0 điểm; WARN không tính vào mẫu số
- Score = (PASS / (PASS + FAIL)) * 10, làm tròn 1 chữ số
- Gán nhãn: EXCELLENT / GOOD / FAIR / POOR / CRITICAL

---

Nếu bạn muốn mở rộng bài test mới, hãy tham khảo các module trong `webhook_auditor/scanner/`, giữ nguyên định dạng kết quả `Dict` như trên để tương thích với báo cáo và tính điểm.