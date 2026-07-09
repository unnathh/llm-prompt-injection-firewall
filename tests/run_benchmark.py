import json
import os
import sys
from typing import Any, Dict, List

# Add current directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.scoring.engine import scoring_engine

def run_benchmark() -> None:
    attacks_file = "sample_attacks/attacks.json"
    if not os.path.exists(attacks_file):
        print(f"Error: {attacks_file} not found.")
        sys.exit(1)
        
    with open(attacks_file, "r", encoding="utf-8") as f:
        test_cases: List[Dict[str, Any]] = json.load(f)

    total = len(test_cases)
    attacks_count = 0
    benign_count = 0
    
    true_positives = 0  # Attacks correctly flagged (score >= 25)
    false_positives = 0 # Benign correctly flagged as threat (score >= 25)
    true_negatives = 0  # Benign correctly allowed (score < 25)
    false_negatives = 0 # Attacks missed (score < 25)

    detailed_results = []

    for tc in test_cases:
        category = tc["category"]
        payload = tc["payload"]
        severity = tc["severity"]
        
        score, meta = scoring_engine.score_prompt(payload)
        
        # Threat flag boundary
        flagged = score >= 25.0
        
        is_attack = category != "benign"
        if is_attack:
            attacks_count += 1
            if flagged:
                true_positives += 1
                result = "TP (Attack Blocked/Flagged)"
            else:
                false_negatives += 1
                result = "FN (Attack Missed)"
        else:
            benign_count += 1
            if flagged:
                false_positives += 1
                result = "FP (False Alarm)"
            else:
                true_negatives += 1
                result = "TN (Clean Allowed)"

        detailed_results.append({
            "id": tc["id"],
            "category": category,
            "payload": payload[:60] + "..." if len(payload) > 60 else payload,
            "threat_score": score,
            "flagged": flagged,
            "result_status": result,
            "matched_rules": meta.get("matched_rules", [])
        })

    # Calculations
    accuracy = (true_positives + true_negatives) / total * 100
    recall = true_positives / attacks_count * 100 if attacks_count > 0 else 0
    fp_rate = false_positives / benign_count * 100 if benign_count > 0 else 0

    # Write Markdown Report
    report = f"""# LLM Firewall Benchmark Verification Report

This report summarizes the threat detection accuracy and false positive rates evaluated by the verification suite.

## Execution Summary

- **Total Test Cases**: {total}
- **Attack Inputs Evaluated**: {attacks_count}
- **Benign Inputs Evaluated**: {benign_count}

## Detection Accuracy Metrics

| Metric | Count | Rate | Description |
| :--- | :--- | :--- | :--- |
| **Accuracy** | {true_positives + true_negatives}/{total} | **{accuracy:.2f}%** | Overall correct decisions |
| **Recall (Detection Rate)** | {true_positives}/{attacks_count} | **{recall:.2f}%** | Attacks correctly flagged |
| **False Positive Rate** | {false_positives}/{benign_count} | **{fp_rate:.2f}%** | Benign inputs incorrectly flagged |

## Confusion Matrix

- **True Positives (TP)**: {true_positives}
- **False Negatives (FN - Misses)**: {false_negatives}
- **True Negatives (TN)**: {true_negatives}
- **False Positives (FP - False Alarms)**: {false_positives}

---

## Detailed Evaluation Log

| ID | Category | Payload Snippet | Score | Status | Rules Triggered |
| :--- | :--- | :--- | :--- | :--- | :--- |
"""
    for res in detailed_results:
        rules_str = ", ".join(res["matched_rules"]) if res["matched_rules"] else "None"
        report += f"| {res['id']} | {res['category']} | `{res['payload']}` | {res['threat_score']}% | {res['result_status']} | {rules_str} |\n"

    # Save to file
    os.makedirs("docs", exist_ok=True)
    with open("docs/accuracy_report.md", "w", encoding="utf-8") as rf:
        rf.write(report)
        
    print("Benchmark complete!")
    print(f"Accuracy: {accuracy:.2f}%")
    print(f"Recall (Detection Rate): {recall:.2f}%")
    print(f"False Positive Rate: {fp_rate:.2f}%")
    print("Full report written to docs/accuracy_report.md")

if __name__ == "__main__":
    run_benchmark()
