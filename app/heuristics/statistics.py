import re
from typing import Any, Dict, Tuple

class StatisticsAnalyzer:
    """
    Computes statistical and structural metrics of the input text:
    - Instruction Density
    - Unicode Script Switching (homoglyph indicator)
    - Special Character Ratio
    - Token/Word Repetition
    - Nested Formatting (deeply nested JSON/brackets)
    - Input Length Anomaly
    """
    @property
    def name(self) -> str:
        return "statistics_analyzer"

    def __init__(self) -> None:
        # Keywords indicative of LLM orchestration or instruction commands
        self.instruction_keywords = {
            "ignore", "forget", "disregard", "override", "bypass", "system", "prompt", 
            "instructions", "rules", "developer", "dev", "mode", "roleplay", "persona", 
            "dan", "assistant", "user", "write", "print", "reveal", "output", "translate"
        }
        
        # Ranges for script switching checks
        self.cyrillic_pattern = re.compile(r"[\u0400-\u04FF]")
        self.greek_pattern = re.compile(r"[\u0370-\u03FF]")
        self.latin_pattern = re.compile(r"[a-zA-Z]")

    def evaluate(self, text: str) -> Tuple[float, Dict[str, Any]]:
        if not text:
            return 0.0, {}

        # 1. Input Length
        length = len(text)
        
        # 2. Instruction Word Density
        words = re.findall(r"\b\w+\b", text.lower())
        total_words = len(words)
        instruction_count = sum(1 for w in words if w in self.instruction_keywords)
        instruction_ratio = (instruction_count / total_words) if total_words > 0 else 0.0

        # 3. Unicode Script Switching (flagging homoglyph lookalikes within same word)
        script_switches = 0
        raw_words = text.split()
        for rw in raw_words:
            has_latin = bool(self.latin_pattern.search(rw))
            has_cyrillic = bool(self.cyrillic_pattern.search(rw))
            has_greek = bool(self.greek_pattern.search(rw))
            # If word is a mixture, it is a homoglyph switch
            if (has_latin and has_cyrillic) or (has_latin and has_greek):
                script_switches += 1

        # 4. Special Character Ratio
        special_chars = sum(1 for c in text if not c.isalnum() and not c.isspace())
        special_char_ratio = special_chars / length if length > 0 else 0.0

        # 5. Token Repetition (e.g. repeated override attempts to exhaust token buffers)
        word_freqs: Dict[str, int] = {}
        for w in words:
            word_freqs[w] = word_freqs.get(w, 0) + 1
        max_rep_count = max(word_freqs.values()) if word_freqs else 0
        repetition_ratio = (max_rep_count / total_words) if total_words > 0 else 0.0

        # 6. Nested Formatting (checking bracket nesting depth)
        nesting_depth = 0
        max_nesting_depth = 0
        for char in text:
            if char in "{[<(":
                nesting_depth += 1
                max_nesting_depth = max(max_nesting_depth, nesting_depth)
            elif char in "}])>":
                nesting_depth = max(0, nesting_depth - 1)

        # Calculate heuristic risk components
        heuristic_matches = []
        threat_score = 0.0

        if instruction_ratio > 0.20:
            heuristic_matches.append("High Instruction Density")
            threat_score += 25.0
        elif instruction_ratio > 0.10:
            heuristic_matches.append("Moderate Instruction Density")
            threat_score += 10.0

        if script_switches > 0:
            heuristic_matches.append("Mixed Unicode Script (Homoglyphs)")
            threat_score += 45.0

        if special_char_ratio > 0.20 and length > 50:
            heuristic_matches.append("High Special Character Ratio")
            threat_score += 15.0

        if repetition_ratio > 0.25 and total_words > 8:
            heuristic_matches.append("Excessive Token Repetition")
            threat_score += 20.0

        if max_nesting_depth > 4:
            heuristic_matches.append("Deeply Nested Formatting")
            threat_score += 15.0

        if length > 12000:
            heuristic_matches.append("Length Anomaly (Excessive Payload)")
            threat_score += 30.0

        # Cap score to 100
        threat_score = min(threat_score, 100.0)

        metadata = {
            "instruction_ratio": round(instruction_ratio, 4),
            "script_switches": script_switches,
            "special_char_ratio": round(special_char_ratio, 4),
            "repetition_ratio": round(repetition_ratio, 4),
            "max_nesting_depth": max_nesting_depth,
            "length": length,
            "heuristic_matches": heuristic_matches
        }

        return threat_score, metadata
