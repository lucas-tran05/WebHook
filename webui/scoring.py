from typing import List, Dict


def calculate_security_score(test_results: List[Dict]) -> dict:
    """
    Compute a 0-10 security score based on test results.

    Rules:
    - Each PASS test = 1 point, FAIL = 0 points, WARN is not counted in total.
    - Final score = (PASS / Total) * 10
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

        if status in ["PASS", "FAIL"]:
            total_tests += 1

            if status == "PASS":
                passed_tests += 1
                test_scores.append(
                    {
                        "test": test_name,
                        "category": test_category,
                        "score": 1.0,
                        "status": "PASS",
                        "response_status": response_status,
                    }
                )
            else:
                test_scores.append(
                    {
                        "test": test_name,
                        "category": test_category,
                        "score": 0.0,
                        "status": "FAIL",
                        "response_status": response_status,
                    }
                )

                severity = "MEDIUM"
                if "Spoofing" in test_name or "Authentication" in test_name:
                    severity = "CRITICAL"
                elif "Tampering" in test_name:
                    severity = "HIGH"
                elif "Injection" in test_name or "SSRF" in test_name:
                    severity = "CRITICAL"
                elif "CHD" in test_name or "PCI" in test_name:
                    severity = "CRITICAL"

                vulnerabilities.append(
                    {
                        "test": test_name,
                        "category": test_category,
                        "severity": severity,
                        "response_status": response_status,
                        "description": result.get("details", ""),
                        "risk": result.get("risk", "Security vulnerability detected"),
                        "mitigation": result.get(
                            "mitigation", "Review and implement proper security controls"
                        ),
                    }
                )

    score = (passed_tests / total_tests) * 10.0 if total_tests > 0 else 10.0

    if score >= 9.0:
        rating = "EXCELLENT"
    elif score >= 7.0:
        rating = "GOOD"
    elif score >= 5.0:
        rating = "FAIR"
    elif score >= 3.0:
        rating = "POOR"
    else:
        rating = "CRITICAL"

    return {
        "score": round(score, 1),
        "rating": rating,
        "total_tests": total_tests,
        "passed_tests": passed_tests,
        "failed_tests": total_tests - passed_tests,
        "test_scores": test_scores,
        "vulnerabilities": vulnerabilities,
    }
