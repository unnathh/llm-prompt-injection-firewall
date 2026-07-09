import base64
import codecs
import re
from typing import Any, Dict, List, Tuple
from app.detection.base import BaseDetector
from app.detection.direct import DirectDetector
from app.detection.jailbreak import JailbreakDetector
from app.detection.extraction import ExtractionDetector
from app.detection.indirect import IndirectDetector

class EncodingDetector(BaseDetector):
    """
    Detects obfuscated prompt injection attempts leveraging Base64, Hex, ROT13,
    Leetspeak, Unicode homoglyphs, and double-encoding. Decodes payloads and runs 
    recursive pattern-checks.
    """
    @property
    def name(self) -> str:
        return "encoding_detector"

    @property
    def category(self) -> str:
        return "encoding"

    def __init__(self) -> None:
        # Homoglyph translation map (Cyrillic/Greek lookalikes to ASCII Latin)
        self.homoglyph_map = {
            'а': 'a', 'е': 'e', 'і': 'i', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x', 'ѕ': 's', 'ј': 'j', 
            'ԁ': 'd', 'һ': 'h', 'ԝ': 'w', 'і': 'i', 'І': 'I', 'А': 'A', 'В': 'B', 'С': 'C', 'Е': 'E', 'Н': 'H', 
            'Ј': 'J', 'К': 'K', 'М': 'M', 'О': 'O', 'Р': 'P', 'Т': 'T', 'Х': 'X', 'Ү': 'Y', 'Ѕ': 'S', 'ꬿ': 'w'
        }
        
        # Leetspeak conversion map
        self.leetspeak_map = {
            '0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's', '7': 't', '8': 'b', '@': 'a', '$': 's', '!': 'i'
        }

        # Regexes to flag suspicious looking words
        self.base64_regex = re.compile(r"\b[A-Za-z0-9+/]{16,}={0,2}\b")
        self.hex_regex = re.compile(r"\b(?:[0-9a-fA-F]{2}\s*){8,}\b|\b(?:0x[0-9a-fA-F]{2},?\s*){4,}\b")

    def _is_text_like(self, s: str) -> bool:
        """
        Check if a string is text-like (consists mostly of printable characters and normal whitespace).
        Prevents evasion via inserting newlines/tabs.
        """
        if not s:
            return False
        # Allow normal controls: newline, carriage return, tab
        allowed_controls = {'\n', '\r', '\t'}
        non_printable = sum(1 for c in s if not c.isprintable() and c not in allowed_controls)
        # If less than 5% of characters are unprintable control/binary chars, treat as text
        return (non_printable / len(s)) < 0.05


    def evaluate(self, prompt: str) -> Tuple[float, Dict[str, Any]]:
        decoded_results: List[Dict[str, Any]] = []
        max_score = 0.0

        # Try base64 decoding
        b64_matches = self.base64_regex.findall(prompt)
        for match in b64_matches:
            try:
                # Add padding if needed
                padded = match + "=" * ((4 - len(match) % 4) % 4)
                decoded_bytes = base64.b64decode(padded, validate=True)
                decoded_str = decoded_bytes.decode("utf-8", errors="strict")
                if self._is_text_like(decoded_str) and len(decoded_str.strip()) > 5:

                    # Recursive layer check
                    final_str, pipeline = self._fully_decode(decoded_str)
                    score, details = self._evaluate_decoded_text(final_str)
                    if score > 20.0:
                        max_score = max(max_score, score)
                        label = "Base64" if not pipeline else f"Base64 + {' + '.join(pipeline)}"
                        decoded_results.append({
                            "obfuscation": label,
                            "original": match,
                            "decoded": final_str,
                            "score": score,
                            "details": details
                        })
            except Exception:
                pass

        # Try Hex decoding
        hex_matches = self.hex_regex.findall(prompt)
        for match in hex_matches:
            cleaned_hex = re.sub(r"[,\s]|0x", "", match)
            try:
                decoded_bytes = bytes.fromhex(cleaned_hex)
                decoded_str = decoded_bytes.decode("utf-8", errors="strict")
                if self._is_text_like(decoded_str) and len(decoded_str.strip()) > 5:

                    # Recursive layer check
                    final_str, pipeline = self._fully_decode(decoded_str)
                    score, details = self._evaluate_decoded_text(final_str)
                    if score > 20.0:
                        max_score = max(max_score, score)
                        label = "Hex" if not pipeline else f"Hex + {' + '.join(pipeline)}"
                        decoded_results.append({
                            "obfuscation": label,
                            "original": match,
                            "decoded": final_str,
                            "score": score,
                            "details": details
                        })
            except Exception:
                pass

        # Try ROT13 decoding on the prompt (or segments)
        try:
            rot13_str = codecs.decode(prompt, "rot-13")
            # ROT13 is symmetrical, so we compare if the rotated version matches rules better than original
            if rot13_str != prompt:
                score, details = self._evaluate_decoded_text(rot13_str)
                # Only record if the decoded text actually triggers threat flags
                if score > 40.0:
                    max_score = max(max_score, score)
                    decoded_results.append({
                        "obfuscation": "ROT13",
                        "decoded": rot13_str,
                        "score": score,
                        "details": details
                    })
        except Exception:
            pass

        # Try Homoglyph normalization
        normalized_homoglyphs = self._normalize_homoglyphs(prompt)
        if normalized_homoglyphs != prompt:
            score, details = self._evaluate_decoded_text(normalized_homoglyphs)
            if score > 30.0:
                max_score = max(max_score, score)
                decoded_results.append({
                    "obfuscation": "Unicode Homoglyph",
                    "decoded": normalized_homoglyphs,
                    "score": score,
                    "details": details
                })

        # Try Leetspeak decoding
        normalized_leet = self._normalize_leet(prompt)
        if normalized_leet != prompt:
            score, details = self._evaluate_decoded_text(normalized_leet)
            if score > 30.0:
                max_score = max(max_score, score)
                decoded_results.append({
                    "obfuscation": "Leetspeak",
                    "decoded": normalized_leet,
                    "score": score,
                    "details": details
                })

        # Base64/Hex/ROT13 detections get a baseline threat weight if they succeeded and nested evaluations trigger
        if decoded_results:
            # Escalated score if a payload was successfully obfuscated
            max_score = max(max_score, 80.0)

        metadata = {
            "matched_rules": decoded_results,
            "match_count": len(decoded_results)
        }

        return max_score, metadata

    def _normalize_homoglyphs(self, text: str) -> str:
        """
        Replaces homoglyphs (lookalike unicode letters) with their standard Latin equivalents.
        """
        return "".join(self.homoglyph_map.get(char, char) for char in text)

    def _normalize_leet(self, text: str) -> str:
        """
        Converts numbers and characters (leetspeak) back to Latin equivalents.
        """
        # Lowercase for map lookup but preserve letters
        normalized = []
        for char in text:
            # Map check
            if char in self.leetspeak_map:
                normalized.append(self.leetspeak_map[char])
            else:
                normalized.append(char)
        return "".join(normalized)

    def _fully_decode(self, text: str, depth: int = 0) -> Tuple[str, List[str]]:
        """
        Recursively decodes Base64 or Hex layers (up to depth 2).
        """
        if depth >= 2:
            return text, []

        # Check if the string matches Base64 pattern
        b64_matches = self.base64_regex.findall(text)
        if b64_matches:
            match = b64_matches[0]
            try:
                padded = match + "=" * ((4 - len(match) % 4) % 4)
                decoded_bytes = base64.b64decode(padded, validate=True)
                decoded_str = decoded_bytes.decode("utf-8", errors="strict")
                if self._is_text_like(decoded_str) and len(decoded_str.strip()) > 5:

                    final, pipeline = self._fully_decode(decoded_str, depth + 1)
                    return final, ["Base64"] + pipeline
            except Exception:
                pass

        # Check if the string matches Hex pattern
        hex_matches = self.hex_regex.findall(text)
        if hex_matches:
            match = hex_matches[0]
            cleaned_hex = re.sub(r"[,\s]|0x", "", match)
            try:
                decoded_bytes = bytes.fromhex(cleaned_hex)
                decoded_str = decoded_bytes.decode("utf-8", errors="strict")
                if self._is_text_like(decoded_str) and len(decoded_str.strip()) > 5:

                    final, pipeline = self._fully_decode(decoded_str, depth + 1)
                    return final, ["Hex"] + pipeline
            except Exception:
                pass

        return text, []

    def _evaluate_decoded_text(self, text: str) -> Tuple[float, Dict[str, Any]]:
        """
        Evaluate decoded content against other standard classifiers.
        """
        detectors = [
            DirectDetector(),
            JailbreakDetector(),
            ExtractionDetector(),
            IndirectDetector()
        ]
        
        highest_score = 0.0
        details = {}
        
        for d in detectors:
            score, meta = d.evaluate(text)
            if score > highest_score:
                highest_score = score
                details = {
                    "detector": d.name,
                    "category": d.category,
                    "threat_score": score,
                    "meta": meta
                }
                
        return highest_score, details
