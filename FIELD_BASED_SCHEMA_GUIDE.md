# Field-Based Schema Testing - Complete Guide

## 🎯 Overview

Thay vì nhập payload JSON cố định, bạn giờ có thể **định nghĩa schema với từng field** và scanner sẽ **tự động sinh ra các test case injection** dựa trên kiểu dữ liệu của mỗi field.

## 📋 How It Works

### Trước đây (Old Method)
```json
{
  "event": "user.created",
  "user_id": 12345,
  "email": "test@example.com"
}
```
→ Test với 1 payload cố định

### Bây giờ (New Method - Field-Based Schema)
```
Field Name: event      | Type: string  | Sample: user.created
Field Name: user_id    | Type: integer | Sample: 12345
Field Name: email      | Type: email   | Sample: test@example.com
```
→ **Tự động sinh 50+ test payloads** với injection attacks trên từng field!

## 🔧 Field Types & Auto-Generated Tests

### 1. **String Fields**
Auto-generated tests:
- ✅ **SQL Injection** (3 variants): `' OR '1'='1`, `admin'--`, `' UNION SELECT...`
- ✅ **XSS (Cross-Site Scripting)** (3 variants): `<script>alert(1)</script>`, `<img src=x onerror=...>`
- ✅ **Command Injection** (2 variants): `; cat /etc/passwd`, `| whoami`
- ✅ **Path Traversal** (2 variants): `../../etc/passwd`, `..\..\windows\system32`
- ✅ **NoSQL Injection** (2 variants): `{"$gt": ""}`, `{"$ne": null}`
- ✅ **Type Confusion**: `null`, `""`, `"null"`, `[]`, `{}`

**Total per string field**: ~15 test cases

### 2. **Integer/Float Fields**
Auto-generated tests:
- ✅ **Boundary Values**: `-2147483648` (INT_MIN), `2147483647` (INT_MAX)
- ✅ **Negative Values**: `-1`, `-999`
- ✅ **Overflow**: `999999999999`
- ✅ **SQL Injection in int**: `' OR '1'='1`
- ✅ **Type Confusion**: `null`, `""`, `"null"`, `[]`, `{}`

**Total per integer field**: ~9 test cases

### 3. **Email Fields**
Auto-generated tests:
- ✅ **SQL Injection**: Same as string
- ✅ **XSS**: Same as string
- ✅ **Format Validation**: Invalid email formats
- ✅ **SSRF Attempts**: `test@[internal-ip]`, `test@localhost`

**Total per email field**: ~15 test cases

### 4. **URL Fields**
Auto-generated tests:
- ✅ **SQL Injection**: Same as string
- ✅ **SSRF**: `http://localhost`, `http://169.254.169.254` (AWS metadata)
- ✅ **Protocol Smuggling**: `file:///etc/passwd`, `javascript:alert(1)`

**Total per URL field**: ~12 test cases

### 5. **Boolean Fields**
Auto-generated tests:
- ✅ **Type Confusion**: `"true"`, `1`, `"yes"`, `null`

**Total per boolean field**: ~4 test cases

### 6. **JSON Object / Array Fields**
Auto-generated tests:
- ✅ **Nested Injection**: Injections inside nested objects
- ✅ **Type Confusion**: `null`, `""`, `[]`, `{}`

**Total per JSON field**: ~6 test cases

## 📊 Example Scenario

### Input Schema
```
Field 1: event     → String    → "user.login"
Field 2: user_id   → Integer   → 12345
Field 3: email     → Email     → "test@example.com"
```

### Auto-Generated Test Payloads (40+ total)

#### SQL Injection Tests on 'event' field:
```json
{"event": "' OR '1'='1", "user_id": 12345, "email": "test@example.com"}
{"event": "admin'--", "user_id": 12345, "email": "test@example.com"}
{"event": "' UNION SELECT...", "user_id": 12345, "email": "test@example.com"}
```

#### XSS Tests on 'event' field:
```json
{"event": "<script>alert(1)</script>", "user_id": 12345, "email": "test@example.com"}
{"event": "<img src=x onerror=alert(1)>", "user_id": 12345, "email": "test@example.com"}
```

#### Integer Overflow Tests on 'user_id':
```json
{"event": "user.login", "user_id": -2147483648, "email": "test@example.com"}
{"event": "user.login", "user_id": 2147483647, "email": "test@example.com"}
{"event": "user.login", "user_id": "' OR '1'='1", "email": "test@example.com"}
```

#### Email Injection Tests:
```json
{"event": "user.login", "user_id": 12345, "email": "' OR '1'='1"}
{"event": "user.login", "user_id": 12345, "email": "<script>alert(1)</script>"}
```

... and 30+ more combinations!

## 🎨 Web Interface Usage

### Step 1: Define Fields
```
┌────────────────────────────────────────────────────────────┐
│ Field Name      │ Type     │ Sample Value                  │
├────────────────────────────────────────────────────────────┤
│ event           │ String   │ user.created                  │
│ user_id         │ Integer  │ 12345                         │
│ email           │ Email    │ test@example.com              │
│ timestamp       │ Integer  │ 1696867200                    │
│ data            │ JSON     │ {"key": "value"}              │
└────────────────────────────────────────────────────────────┘
```

### Step 2: Click "Start Security Scan"

### Step 3: View Results
```
✅ SQL Injection on 'event' #1 - PASS
✅ SQL Injection on 'event' #2 - PASS
❌ XSS Injection on 'event' #1 - FAIL (vulnerability detected!)
✅ Integer Overflow on 'user_id' #1 - PASS
...
```

## 💡 Benefits

### 1. **Comprehensive Coverage**
- Mỗi field được test với **10-15 attack vectors**
- Tổng test cases: `số_fields × 10-15 payloads`
- Ví dụ: 5 fields → **50-75 test cases tự động**

### 2. **Type-Aware Testing**
- String fields → test injection attacks
- Integer fields → test overflow/underflow
- Email/URL → test SSRF + injection
- Smart targeting based on data type

### 3. **Easy to Use**
- Không cần biết injection payloads
- Chỉ cần định nghĩa schema
- Scanner tự động sinh test cases

### 4. **Realistic Scenarios**
- Tests giữ nguyên structure của payload
- Chỉ inject vào 1 field tại 1 thời điểm
- Dễ debug và identify vulnerable field

## 📈 Comparison

| Feature | Old Method (Fixed JSON) | New Method (Schema-Based) |
|---------|------------------------|---------------------------|
| Test Coverage | 1 payload | 50+ payloads |
| Field-Specific | ❌ No | ✅ Yes |
| Type-Aware | ❌ No | ✅ Yes |
| Auto-Generation | ❌ No | ✅ Yes |
| Easy to Configure | ⚠️ Manual | ✅ Visual UI |
| Identifies Vulnerable Field | ❌ Hard | ✅ Easy |

## 🔍 Under the Hood

### Backend Logic (Python)
```python
def generate_injection_payloads(schema: List[FieldSchema]) -> List[TestPayload]:
    """
    Generates injection test payloads based on field schema.
    """
    test_payloads = []
    
    # Build base payload
    base_payload = {field.name: field.sample_value for field in schema}
    
    # For each field
    for field in schema:
        if field.type == 'string':
            # Generate SQL injection tests
            for sql_payload in SQL_INJECTIONS:
                test_data = base_payload.copy()
                test_data[field.name] = sql_payload
                test_payloads.append(TestPayload(
                    name=f"SQL Injection on '{field.name}'",
                    data=json.dumps(test_data)
                ))
            
            # Generate XSS tests
            for xss_payload in XSS_PAYLOADS:
                test_data = base_payload.copy()
                test_data[field.name] = xss_payload
                test_payloads.append(...)
    
    return test_payloads
```

## 🎯 Use Cases

### Use Case 1: Payment Webhook
```
Fields:
- transaction_id → Integer
- amount → Float
- currency → String (3 chars)
- customer_email → Email
- status → String (enum)

Auto-generates: 60+ test cases
```

### Use Case 2: User Event Webhook
```
Fields:
- event_type → String
- user_id → Integer
- timestamp → Integer
- metadata → JSON

Auto-generates: 55+ test cases
```

### Use Case 3: Order Notification
```
Fields:
- order_id → String
- items → Array
- total → Float
- shipping_address → JSON
- callback_url → URL

Auto-generates: 70+ test cases
```

## 🚀 Advanced Features

### Feature 1: Mixed Injection
Tests multiple fields simultaneously (coming soon)

### Feature 2: Custom Injection Patterns
Upload your own attack vectors (coming soon)

### Feature 3: Field Relationships
Define dependencies between fields (coming soon)

## 📝 Summary

**Old way**: Manual JSON payload → 1 test
**New way**: Define schema → 50+ auto-generated injection tests

✨ **Smart, automated, comprehensive security testing!**
