import re
from typing import Any, Dict, Tuple
from app.detection.base import BaseDetector

class JailbreakDetector(BaseDetector):
    """
    Detects known jailbreak framing patterns such as DAN, Developer Mode bypasses,
    and roleplay-based safety rule evasion.
    """
    @property
    def name(self) -> str:
        return "jailbreak_detector"

    @property
    def category(self) -> str:
        return "jailbreak"

    def __init__(self) -> None:
        self.patterns = [
            (re.compile(r"\bDAN\b", re.IGNORECASE), "DAN Jailbreak Core"),
            (re.compile(r"do\s+anything\s+now", re.IGNORECASE), "Do Anything Now Jailbreak"),
            (re.compile(r"developer\s+mode\s*(?:v\d+|enabled|active)?", re.IGNORECASE), "Developer Mode Jailbreak"),
            (re.compile(r"dev\s*mode", re.IGNORECASE), "Short Developer Mode Jailbreak"),
            (re.compile(r"unlimited\s+AI", re.IGNORECASE), "Restrictions Removal Check"),
            (re.compile(r"no\s+restrictions", re.IGNORECASE), "Restrictions Removal Check"),
            (re.compile(r"\bunrestricted\s+(?:AI|assistant|model|terminal|mode)\b", re.IGNORECASE), "Unrestricted Persona Jailbreak"),
            (re.compile(r"safety\s+(?:rules|filters|protocols)\s+(?:are\s+)?(?:suspended|disabled|ignored|inactive|removed)", re.IGNORECASE), "Rules Suspension Jailbreak"),
            (re.compile(r"\bplay(?:ing)?\s+a\s+game\b", re.IGNORECASE), "Game Roleplay Jailbreak"),
            (re.compile(r"\b(?:hacker\s+bot|no\s+moral\s+restrictions|character\s+simulation)\b", re.IGNORECASE), "Hacker Persona Jailbreak"),
            (re.compile(r"bypass\s+safety", re.IGNORECASE), "Safety Filter Bypass Command"),
            (re.compile(r"jailbreak\s+prompt", re.IGNORECASE), "Explicit Jailbreak Mention"),
            (re.compile(r"hypothetical\s+scenario\s+where\s+you\s+can", re.IGNORECASE), "Hypothetical Scenario Evasion"),
            # Matches roleplay jailbreaks like: "Imagine two computers playing roles. One has no filters. Computer A says..."
            (re.compile(r"(?:imagine|simulate|roleplay).*(?:no\s+filters|no\s+rules|unrestricted|bypass)", re.IGNORECASE), "Simulated Persona Jailbreak"),
            (re.compile(r"\brepeat\s+after\s+me\b|\becho\s+back\b", re.IGNORECASE), "Echoing Prompt Bypass"),
            (re.compile(r"\btranslate\s+to\s+[a-zA-Z]+.*\bignore\b", re.IGNORECASE), "Translation Hijacking"),
            (re.compile(r"\bwrite\s+code\s+that\s+ignores\b", re.IGNORECASE), "Code-gen Evasion")
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
                # Jailbreak matches have high threat significance
                if rule_name in ["DAN Jailbreak Core", "Do Anything Now Jailbreak", "Developer Mode Jailbreak", "Simulated Persona Jailbreak"]:
                    max_score = max(max_score, 98.0)
                else:
                    max_score = max(max_score, 85.0)

        metadata = {
            "matched_rules": matches,
            "match_count": len(matches)
        }

        return max_score, metadata
