import re
from typing import Any, Dict, Tuple
from app.detection.base import BaseDetector

class IndirectDetector(BaseDetector):
    """
    Detects indirect injection mechanisms, including HTML comments, XML tag injections,
    markdown overrides, system-like prompt delimiters, and invisible Unicode characters.
    """
    @property
    def name(self) -> str:
        return "indirect_injection_detector"

    @property
    def category(self) -> str:
        return "indirect_injection"

    def __init__(self) -> None:
        self.patterns = [
            (re.compile(r"<!--[\s\S]*?-->"), "HTML Comment Injection"),
            (re.compile(r"\[comment\]\s*:\s*#\s*\(.*?\)", re.IGNORECASE), "Markdown Hidden Comment"),
            (re.compile(r"<(?P<tag>instruction|system|prompt|user|override|rules|context|payload|data|text)>[\s\S]*?</(?P=tag)>", re.IGNORECASE), "XML Instruction Injections"),
            (re.compile(r"[-=]{3,}\s*(?:SYSTEM|INSTRUCTION|CONTEXT|PROMPT|USER)\s*[-=]{3,}", re.IGNORECASE), "Prompt Delimiter Injection"),
            (re.compile(r"[\u200b\u200c\u200d\u200e\u200f\ufeff]"), "Invisible Unicode / Zero-Width Characters"),
            # Matches nested prompts in code blocks e.g. json structures containing user/system blocks
            (re.compile(r'(?:"role"\s*:\s*"(?:system|user|assistant)"|role\s*=\s*(?:system|user))', re.IGNORECASE), "Structured Prompt Hijacking")
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
                # Score mapping
                if rule_name in ["HTML Comment Injection", "Markdown Hidden Comment", "XML Instruction Injections"]:
                    max_score = max(max_score, 80.0)
                elif rule_name in ["Invisible Unicode / Zero-Width Characters"]:
                    max_score = max(max_score, 60.0)
                elif rule_name in ["Prompt Delimiter Injection", "Structured Prompt Hijacking"]:
                    max_score = max(max_score, 75.0)

        metadata = {
            "matched_rules": matches,
            "match_count": len(matches)
        }

        return max_score, metadata
