import html
import re
import unicodedata

class SanitizationEngine:
    """
    Cleanses, normalizes, and escapes payloads to neutralize markup injection vectors,
    delimiter hijacks, instruction repeats, and buffer exploits.
    """
    def __init__(self, max_length: int = 4000) -> None:
        self.max_length = max_length
        # Matches repeating lines of delimiters (e.g. ===, ---, ###, ***)
        self.delimiter_regex = re.compile(r"^[=\-_#*`~]{3,}\s*$", re.MULTILINE)
        # Matches consecutive repeated words/tokens (e.g. "ignore ignore ignore")
        self.word_dedup_regex = re.compile(r"\b(\w+)(?:\s+\1\b)+", re.IGNORECASE)

    def normalize_unicode(self, text: str) -> str:
        """
        Applies NFKC normalization to flatten homoglyphs and hidden Unicode formatting.
        """
        return unicodedata.normalize("NFKC", text)

    def escape_xml_html(self, text: str) -> str:
        """
        Escapes XML and HTML control tags to neutralize tag breakout attempts.
        """
        return html.escape(text, quote=True)

    def escape_markdown(self, text: str) -> str:
        """
        Escapes markdown formatting tags to render them as inert literal text.
        """
        # Escape markdown control characters: \, `, *, _, {, }, [, ], (, ), #, +, -, ., !, |
        escape_chars = r"\`*_{}[]()#+-."
        escaped = text
        for char in escape_chars:
            escaped = escaped.replace(char, f"\\{char}")
        return escaped

    def strip_delimiters(self, text: str) -> str:
        """
        Removes conversation separators/boundaries (e.g., lines of === or ---).
        """
        return self.delimiter_regex.sub("", text)

    def collapse_repetitions(self, text: str) -> str:
        """
        Collapses consecutive repeating words to a single occurrence.
        """
        return self.word_dedup_regex.sub(r"\1", text)

    def truncate_payload(self, text: str) -> str:
        """
        Cuts payload down to max length parameters.
        """
        if len(text) > self.max_length:
            return text[:self.max_length] + "... [TRUNCATED BY FIREWALL]"
        return text

    def sanitize_prompt(
        self, 
        prompt: str,
        normalize: bool = True,
        escape_html: bool = True,
        escape_md: bool = False, # often off by default to preserve normal symbols, but testable
        strip_delims: bool = True,
        collapse_repeats: bool = True,
        truncate: bool = True
    ) -> str:
        """
        Run all configured sanitizations sequentially on input prompt.
        """
        if not prompt:
            return ""

        clean = prompt

        if normalize:
            clean = self.normalize_unicode(clean)

        if strip_delims:
            clean = self.strip_delimiters(clean)

        if collapse_repeats:
            clean = self.collapse_repetitions(clean)

        if escape_html:
            clean = self.escape_xml_html(clean)

        if escape_md:
            clean = self.escape_markdown(clean)

        if truncate:
            clean = self.truncate_payload(clean)

        return clean

# Export sanitization engine singleton
sanitization_engine = SanitizationEngine()
