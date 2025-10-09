# 🔐 Webhook Security Scanner

A comprehensive security testing tool for webhook endpoints based on the STRIDE threat model with injection attack detection.

## ✨ Features

- **18 Security Tests** covering:
  - ✅ **STRIDE Model**: Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Privilege Escalation
  - ✅ **Injection Attacks**: SQL, NoSQL, Command, XSS, Path Traversal, Template Injection
  
- **Dual Interface**:
  - 🖥️ **CLI**: Command-line interface for automation
  - 🌐 **Web UI**: Beautiful Bootstrap-based interface for easy testing

- **HMAC Signature Validation**: Tests webhook signature security
- **Comprehensive Reporting**: Detailed results with risk assessment and mitigation advice

## 🚀 Quick Start

### Installation

```bash
# Clone repository
git clone <your-repo-url>
cd WebHook

# Create virtual environment
python -m venv .venv
.venv\Scripts\Activate.ps1  # Windows PowerShell

# Install dependencies
pip install -r requirements.txt
```

### Usage

#### Web Interface (Recommended)

```bash
python main.py web
```

Then open **http://localhost:8080** in your browser and enter:
- Target webhook URL
- Shared secret
- Sample payload (JSON)
- Optional: Advanced settings

#### CLI Interface

```bash
python main.py scan \
  --target-url https://api.example.com/webhook \
  --secret "your-secret-key" \
  --payload '{"event": "test", "data": "sample"}'
```

## 📊 Security Tests

### STRIDE Categories (12 tests)
1. **Spoofing** - Missing/Invalid signature detection
2. **Tampering** - Signature validation, payload modification
3. **Repudiation** - Timestamp validation, replay attack detection
4. **Information Disclosure** - HTTPS enforcement, error message analysis
5. **Denial of Service** - Large payload handling, rate limiting
6. **Privilege Escalation** - Unauthorized field injection

### Injection Tests (6 tests)
1. **SQL Injection** - Tests for SQL injection vulnerabilities
2. **NoSQL Injection** - MongoDB operator injection
3. **Command Injection** - OS command execution attempts
4. **XSS** - Cross-site scripting vectors
5. **Path Traversal** - Directory traversal attempts
6. **Template Injection** - Server-side template injection

## 🎯 CLI Options

```bash
python main.py scan --help

Options:
  --target-url TEXT          Target webhook endpoint (required)
  --secret TEXT              Shared secret for HMAC (required)
  --method TEXT              HTTP method (default: POST)
  --signature-header TEXT    Signature header name
  --timestamp-header TEXT    Timestamp header name
  --payload TEXT             Sample JSON payload
  --signature-prefix TEXT    Signature prefix (default: sha256=)
```

## 🌐 Web Interface

The web interface provides:
- 📝 Dynamic form with validation
- 🎨 Modern Bootstrap 5 UI
- 📊 Real-time results with statistics
- 🔍 Detailed test breakdown
- ⚙️ Advanced configuration options
- 📱 Responsive design

## 📁 Project Structure

```
WebHook/
├── main.py                          # CLI entry point
├── web_scanner.py                   # Web interface
├── requirements.txt                 # Python dependencies
├── webhook_auditor/
│   ├── scanner/
│   │   ├── config.py               # Configuration
│   │   ├── orchestrator.py         # Test coordinator
│   │   ├── spoofing_tests.py       # Spoofing tests
│   │   ├── repudiation_tests.py    # Repudiation tests
│   │   ├── info_disclosure_tests.py # Info disclosure tests
│   │   ├── dos_tests.py            # DoS tests
│   │   ├── privilege_escalation_tests.py # Privilege tests
│   │   └── injection_tests.py      # Injection tests
│   └── utils/
│       ├── crypto.py               # HMAC utilities
│       └── reporter.py             # Report generation
└── README.md
```

## 🔧 Configuration

All settings can be configured via:
- CLI arguments
- Web interface form
- Advanced options (signature headers, prefixes, etc.)

## 📝 License

MIT License

## 👤 Author

Your Name

---

Made with ❤️ for webhook security
