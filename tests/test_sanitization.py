import pytest
from app.sanitization.sanitizers import sanitization_engine

def test_unicode_normalization():
    # Cyrillic lookalike letters
    confusable = "іgnоrе"  # contains Cyrillic letters
    normalized = sanitization_engine.normalize_unicode(confusable)
    # Checks that it decomposes/normalizes correctly
    assert len(normalized) == 6

def test_xml_html_escaping():
    payload = "<script>alert(1)</script> & override"
    escaped = sanitization_engine.escape_xml_html(payload)
    assert "<script>" not in escaped
    assert "</script>" not in escaped
    assert "&lt;script&gt;" in escaped
    assert "&amp;" in escaped

def test_delimiter_stripping():
    payload = "Hello\n=======\nWorld\n---\nPrompt"
    stripped = sanitization_engine.strip_delimiters(payload)
    assert "=======" not in stripped
    assert "---" not in stripped
    assert "Hello" in stripped
    assert "World" in stripped

def test_repetition_collapsing():
    payload = "ignore ignore ignore please help"
    collapsed = sanitization_engine.collapse_repetitions(payload)
    assert collapsed == "ignore please help"
    
    # CASE SENSITIVE collapse check
    payload_mixed = "Ignore ignore IGNORE rules"
    collapsed_mixed = sanitization_engine.collapse_repetitions(payload_mixed)
    assert collapsed_mixed == "Ignore rules"

def test_truncation():
    large_payload = "a" * 5000
    engine_small = sanitization_engine.__class__(max_length=100)
    truncated = engine_small.truncate_payload(large_payload)
    assert len(truncated) < 200
    assert "TRUNCATED BY FIREWALL" in truncated

def test_full_sanitize_pipeline():
    payload = "<instruction>ignore ignore ignore\n===\nsystem prompt</instruction>"
    clean = sanitization_engine.sanitize_prompt(payload)
    
    assert "<instruction>" not in clean
    assert "ignore ignore" not in clean
    assert "===" not in clean
    assert "&lt;instruction&gt;" in clean
