"""
Security Scoring System for Webhook Scanner

Hệ thống chấm điểm bảo mật:
- Mỗi test: 1 điểm nếu PASS (server từ chối đúng), 0 điểm nếu FAIL (server chấp nhận sai)
- Điểm cuối cùng = (Số test PASS / Tổng số test) * 10
- Ví dụ: 8/10 test pass => điểm = 8.0/10
"""
from typing import List, Dict


def calculate_security_score(test_results: List[Dict]) -> dict:
    """
    Tính điểm bảo mật dựa trên kết quả test.
    
    Nguyên tắc:
    - Mỗi test được chấm điểm riêng: 1 điểm nếu PASS, 0 điểm nếu FAIL
    - Điểm cuối cùng = (Tổng điểm PASS / Tổng số test) * 10
    - Test FAIL do chấp nhận request không hợp lệ (200 OK) sẽ là 0 điểm
    
    Returns:
        dict với:
        - score: Điểm từ 0-10
        - rating: Đánh giá (EXCELLENT/GOOD/FAIR/POOR/CRITICAL)
        - test_scores: Điểm chi tiết từng test
        - vulnerabilities: Danh sách lỗ hổng
    """
    total_tests = 0
    passed_tests = 0
    test_scores = []
    vulnerabilities = []
    
    for result in test_results:
        status = result.get("status", "")
        test_name = result.get("name", "")
        test_category = result.get("category", "")
        response_status = result.get("response_status", 0)
        
        # Đếm tổng số test (không tính WARN)
        if status in ["PASS", "FAIL"]:
            total_tests += 1
            
            if status == "PASS":
                # Test PASS = 1 điểm
                passed_tests += 1
                test_scores.append({
                    "test": test_name,
                    "category": test_category,
                    "score": 1.0,
                    "status": "PASS",
                    "response_status": response_status
                })
            else:  # FAIL
                # Test FAIL = 0 điểm
                test_scores.append({
                    "test": test_name,
                    "category": test_category,
                    "score": 0.0,
                    "status": "FAIL",
                    "response_status": response_status
                })
                
                # Xác định mức độ nghiêm trọng dựa trên loại test
                severity = "MEDIUM"
                if "Spoofing" in test_name or "Authentication" in test_name:
                    severity = "CRITICAL"
                elif "Tampering" in test_name:
                    severity = "HIGH"
                elif "Injection" in test_name or "SSRF" in test_name:
                    severity = "HIGH"
                elif "CHD" in test_name or "PCI" in test_name:
                    severity = "CRITICAL"
                
                vulnerabilities.append({
                    "test": test_name,
                    "category": test_category,
                    "severity": severity,
                    "response_status": response_status,
                    "description": result.get("details", ""),
                    "risk": result.get("risk", "Security vulnerability detected"),
                    "mitigation": result.get("mitigation", "Review and implement proper security controls")
                })
    
    # Tính điểm cuối cùng
    if total_tests > 0:
        score = (passed_tests / total_tests) * 10.0
    else:
        score = 10.0  # Không có test nào => full điểm
    
    # Xác định rating
    if score >= 9.0:
        rating = "🟢 EXCELLENT"
    elif score >= 7.0:
        rating = "🟡 GOOD"
    elif score >= 5.0:
        rating = "🟠 FAIR"
    elif score >= 3.0:
        rating = "🔴 POOR"
    else:
        rating = "🚨 CRITICAL"
    
    return {
        "score": round(score, 1),
        "rating": rating,
        "total_tests": total_tests,
        "passed_tests": passed_tests,
        "failed_tests": total_tests - passed_tests,
        "test_scores": test_scores,
        "vulnerabilities": vulnerabilities
    }
