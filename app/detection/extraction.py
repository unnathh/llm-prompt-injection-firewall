import re
from typing import Any, Dict, Tuple
from app.detection.base import BaseDetector

class ExtractionDetector(BaseDetector):
    """
    Detects attempts to extract the system prompt, configuration parameters,
    underlying guidelines, training data snippets, or memory state logs.
    """
    @property
    def name(self) -> str:
        return "extraction_detector"

    @property
    def category(self) -> str:
        return "data_extraction"

    def __init__(self) -> None:
        self.patterns = [
            (re.compile(r"reveal\s+(?:your|the)\s+system\s+(?:prompt|instructions?)", re.IGNORECASE), "System Prompt Extraction"),
            (re.compile(r"print\s+(?:your|the)\s+(?:hidden|system)\s+(?:prompt|instructions?)", re.IGNORECASE), "System Prompt Extraction"),
            (re.compile(r"what\s+is\s+written\s+above", re.IGNORECASE), "Preceding Text Extraction"),
            (re.compile(r"output\s+(?:everything|the\s+text)\s+above", re.IGNORECASE), "Preceding Text Extraction"),
            (re.compile(r"training\s+data\s+extraction", re.IGNORECASE), "Training Data Leakage"),
            (re.compile(r"extract\s+training\s+data", re.IGNORECASE), "Training Data Leakage"),
            (re.compile(r"internal\s+instructions?", re.IGNORECASE), "Internal Instructions Extraction"),
            (re.compile(r"developer\s+messages?", re.IGNORECASE), "System Message Extraction"),
            (re.compile(r"system\s+messages?", re.IGNORECASE), "System Message Extraction"),
            (re.compile(r"memory\s+dump", re.IGNORECASE), "Memory Dump Attempt"),
            (re.compile(r"dump\s+your\s+memory", re.IGNORECASE), "Memory Dump Attempt")
        ]

    def evaluate(self, prompt: str) -> Tuple[float, Dict[str, Any]]:
        matches = []
        max_score = 0.0

        for pattern, rule_name in self.patterns:
            finds = pattern.findall(prompt)
            if finds:
                matches.append({
                    "rule": rule_name,
                    "matched_pattern": pattern.pattern,
                    "occurrences": len(finds)
                })
                # Score matching
                if rule_name in ["System Prompt Extraction", "System Message Extraction", "Internal Instructions Extraction"]:
                    max_score = max(max_score, 90.0)
                elif rule_name in ["Memory Dump Attempt", "Training Data Leakage"]:
                    max_score = max(max_score, 85.0)
                else:
                    max_score = max(max_score, 70.0)

        metadata = {
            "matched_rules": matches,
            "match_count": len(matches)
        }

        return max_score, metadata
