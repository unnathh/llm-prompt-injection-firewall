from typing import Any, Dict, Tuple
from app.detection.direct import DirectDetector
from app.detection.indirect import IndirectDetector
from app.detection.jailbreak import JailbreakDetector
from app.detection.extraction import ExtractionDetector
from app.detection.encoding import EncodingDetector
from app.heuristics.entropy import EntropyAnalyzer
from app.heuristics.statistics import StatisticsAnalyzer

class ThreatScoringEngine:
    """
    Aggregates findings from all detectors and heuristics into a unified 0-100 threat score.
    Also calculates the threat breakdown matrix for dashboard visualizations.
    """
    def __init__(self) -> None:
        self.direct_detector = DirectDetector()
        self.indirect_detector = IndirectDetector()
        self.jailbreak_detector = JailbreakDetector()
        self.extraction_detector = ExtractionDetector()
        self.encoding_detector = EncodingDetector()
        
        self.entropy_analyzer = EntropyAnalyzer()
        self.statistics_analyzer = StatisticsAnalyzer()

    def score_prompt(self, prompt: str) -> Tuple[float, Dict[str, Any]]:
        """
        Scan a prompt with all active tools and return aggregated score & metadata.
        """
        if not prompt or not prompt.strip():
            return 0.0, {
                "final_score": 0.0,
                "breakdown": {
                    "prompt_override": 0.0,
                    "role_switching": 0.0,
                    "encoded_payload": 0.0,
                    "entropy": 0.0,
                    "pattern_match": 0.0
                },
                "raw_scores": {}
            }

        # Run all analyzers
        direct_score, direct_meta = self.direct_detector.evaluate(prompt)
        indirect_score, indirect_meta = self.indirect_detector.evaluate(prompt)
        jailbreak_score, jailbreak_meta = self.jailbreak_detector.evaluate(prompt)
        extraction_score, extraction_meta = self.extraction_detector.evaluate(prompt)
        encoding_score, encoding_meta = self.encoding_detector.evaluate(prompt)
        
        entropy_score, entropy_meta = self.entropy_analyzer.evaluate(prompt)
        stats_score, stats_meta = self.statistics_analyzer.evaluate(prompt)

        # Aggregate raw match metadata
        all_rules_matched = []
        for r in direct_meta.get("matched_rules", []): all_rules_matched.append(f"Direct: {r['rule']}")
        for r in indirect_meta.get("matched_rules", []): all_rules_matched.append(f"Indirect: {r['rule']}")
        for r in jailbreak_meta.get("matched_rules", []): all_rules_matched.append(f"Jailbreak: {r['rule']}")
        for r in extraction_meta.get("matched_rules", []): all_rules_matched.append(f"Extraction: {r['rule']}")
        for r in encoding_meta.get("matched_rules", []): 
            all_rules_matched.append(f"Obfuscation: {r['obfuscation']}")
            # Also extract nested rules from decoded contents
            details = r.get("details", {})
            nested_meta = details.get("meta", {})
            for nr in nested_meta.get("matched_rules", []):
                all_rules_matched.append(f"Nested {details.get('detector')}: {nr['rule']}")
        for h in stats_meta.get("heuristic_matches", []): all_rules_matched.append(f"Heuristic: {h}")

        # Compute specific dashboard threat breakdown contributions (summing up to 100)
        # 1. Prompt Override (Max 25)
        # Triggered by instruction overrides or disregards
        has_override = any(
            "Instruction Override" in r or "System Prompt Erasure" in r or "Prompt Disregard" in r or "Direct Override Check" in r
            for r in all_rules_matched
        )
        prompt_override_contrib = 25.0 if has_override or direct_score > 80.0 or (encoding_score > 80.0 and has_override) else (direct_score * 0.25)
        prompt_override_contrib = min(prompt_override_contrib, 25.0)

        # 2. Role Switching / Persona (Max 10)
        # Triggered by "Act as", "Pretend you are", "Roleplay as", or roleplay jailbreaks
        has_role_switch = any(
            "Identity Override" in r or "Persona Alteration" in r or "Persona Simulation" in r or "Roleplay Simulation" in r or "Simulated Persona Jailbreak" in r
            for r in all_rules_matched
        )
        role_switching_contrib = 10.0 if has_role_switch else min(jailbreak_score * 0.1, 10.0)

        # 3. Encoded Payload (Max 20)
        # Triggered by Base64/Hex/ROT13/Homoglyph/Leetspeak obfuscations
        has_encoding = encoding_score > 0.0 or "Mixed Unicode Script (Homoglyphs)" in stats_meta.get("heuristic_matches", [])
        encoded_payload_contrib = 20.0 if has_encoding else 0.0

        # 4. Entropy (Max 15)
        # Driven by Shannon Entropy score
        entropy_contrib = (entropy_score / 80.0) * 15.0
        entropy_contrib = min(entropy_contrib, 15.0)

        # 5. Pattern Match (Max 30)
        # Driven by indirect markers (XML, HTML comments) and extraction attempts
        has_patterns = (indirect_score > 0.0 or extraction_score > 0.0)
        pattern_match_contrib = 30.0 if has_patterns else min((indirect_score + extraction_score) * 0.15, 30.0)

        # Total additive score based on breakdown matrix
        additive_score = prompt_override_contrib + role_switching_contrib + encoded_payload_contrib + entropy_contrib + pattern_match_contrib
        
        # Max-bias score: If a single detector is extremely confident of an attack (e.g. DAN jailbreak),
        # we must not dilute it. The overall score is the max of the additive total and the individual max.
        max_individual_score = max(
            direct_score, 
            indirect_score, 
            jailbreak_score, 
            extraction_score, 
            encoding_score, 
            stats_score
        )
        
        final_score = max(max_individual_score, additive_score)
        final_score = min(round(final_score, 2), 100.0)

        metadata = {
            "final_score": final_score,
            "matched_rules": all_rules_matched,
            "breakdown": {
                "prompt_override": round(prompt_override_contrib, 2),
                "role_switching": round(role_switching_contrib, 2),
                "encoded_payload": round(encoded_payload_contrib, 2),
                "entropy": round(entropy_contrib, 2),
                "pattern_match": round(pattern_match_contrib, 2)
            },
            "raw_scores": {
                "direct": direct_score,
                "indirect": indirect_score,
                "jailbreak": jailbreak_score,
                "extraction": extraction_score,
                "encoding": encoding_score,
                "entropy": entropy_score,
                "statistics": stats_score
            }
        }

        return final_score, metadata

# Export scoring engine singleton
scoring_engine = ThreatScoringEngine()
