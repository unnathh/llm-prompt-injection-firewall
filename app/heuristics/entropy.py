import math
from typing import Any, Dict, Tuple

class EntropyAnalyzer:
    """
    Computes Shannon Entropy of the input text to identify random string obfuscation,
    dense Base64 sequences, or hex dumps.
    """
    @property
    def name(self) -> str:
        return "entropy_analyzer"

    def calculate_entropy(self, text: str) -> float:
        """
        Calculate Shannon Entropy of the text.
        """
        if not text:
            return 0.0
            
        # Count frequency of each character
        frequencies: Dict[str, int] = {}
        for char in text:
            frequencies[char] = frequencies.get(char, 0) + 1
            
        length = len(text)
        entropy = 0.0
        
        # Calculate Shannon entropy formula
        for count in frequencies.values():
            p = count / length
            entropy -= p * math.log2(p)
            
        return entropy

    def evaluate(self, text: str) -> Tuple[float, Dict[str, Any]]:
        """
        Evaluate entropy and map to a threat score between 0.0 and 100.0.
        Typical English text has an entropy of ~3.5 to 5.0.
        Base64-encoded strings and Hex strings have entropy closer to 5.5 - 6.0+.
        We also look at string length because short strings have naturally higher/lower variance.
        """
        if len(text) < 15:
            # Too short for reliable entropy metric
            return 0.0, {"entropy": 0.0, "reason": "Text too short"}
            
        entropy = self.calculate_entropy(text)
        score = 0.0
        
        # Score mapping based on entropy levels
        if entropy > 5.2:
            # Highly uniform distribution (very dense Base64 / random characters)
            score = 80.0
        elif entropy > 4.5:
            # Moderately high entropy (standard Base64 / dense character mixtures)
            score = 45.0
        elif entropy > 2.8:
            # Normal range for standard text / programming layouts
            score = 0.0
        else:
            # Very low entropy (repeating a character pattern, typical of buffer exhaustions)
            score = 30.0

        metadata = {
            "entropy": round(entropy, 4),
            "text_length": len(text)
        }
        
        return score, metadata
