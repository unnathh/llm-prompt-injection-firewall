import re
from typing import Any, Dict, Tuple
from app.detection.base import BaseDetector

class DirectDetector(BaseDetector):
    """
    Detects direct instruction overrides, role-playing, and model personification triggers.
    """
    @property
    def name(self) -> str:
        return "direct_injection_detector"

    @property
    def category(self) -> str:
        return "direct_injection"

    def __init__(self) -> None:
        # Compile direct pattern matchers
        self.patterns = [
            (re.compile(r"ignore\s+(?:(?:previous|all|prior|system|your)\s*){1,3}(?:instructions?|prompts?|rules?)", re.IGNORECASE), "Instruction Override"),
            (re.compile(r"forget\s+(?:(?:your|the|all|system)\s*){1,3}(?:prompts?|instructions?|rules?)", re.IGNORECASE), "System Prompt Erasure"),
            (re.compile(r"disregard\s+(?:(?:all|previous|prior|system|your)\s*){1,3}(?:prompts?|instructions?|directions?|rules?)", re.IGNORECASE), "Prompt Disregard"),
            (re.compile(r"\byou\s+are\s+now\b", re.IGNORECASE), "Identity Override"),
            (re.compile(r"\bact\s+as\b", re.IGNORECASE), "Persona Alteration"),
            (re.compile(r"pretend\s+you\s+are", re.IGNORECASE), "Persona Simulation"),
            (re.compile(r"roleplay\s+as", re.IGNORECASE), "Roleplay Simulation"),
            (re.compile(r"\bnew\s+rule\b", re.IGNORECASE), "Rule Modification"),
            (re.compile(r"override\s+system\s+(?:prompt|instructions)", re.IGNORECASE), "Direct Override Check"),
            (re.compile(r"(?:do\s+not|never)\s+(?:refuse|say\s+no|mention\s+safety|tell\s+me\s+you\s+cannot)", re.IGNORECASE), "Refusal Suppression"),
            (re.compile(r"\b(?:switch|change)\s+(?:personas|identities)\b", re.IGNORECASE), "Persona Alteration")
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
                # Escalate score. Each match contributes.
                # A single hard match (e.g. system override) triggers high threat score (90-100)
                # Some generic terms (act as, roleplay as) may trigger lower/warn score (30) depending on context
                if rule_name in ["Instruction Override", "System Prompt Erasure", "Prompt Disregard", "Direct Override Check"]:
                    max_score = max(max_score, 95.0)
                else:
                    # Roleplay, act as, etc.
                    max_score = max(max_score, 40.0)

        metadata = {
            "matched_rules": matches,
            "match_count": len(matches)
        }

        return max_score, metadata
