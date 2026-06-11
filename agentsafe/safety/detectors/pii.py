"""
PII Detection - regex-based with optional NER.
"""
from __future__ import annotations
import re
from typing import List, Tuple, Optional
from dataclasses import dataclass, field


@dataclass
class PIIConfig:
    detect: bool = True
    redact: bool = False
    use_ner: bool = False
    entity_types: List[str] = field(default_factory=lambda: [
        "PERSON", "GPE", "ORG", "DATE"
    ])
    patterns: dict = field(default_factory=lambda: {
        "SSN": re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
        "MRN": re.compile(r'\b[A-Z]{2}\d{7}\b'),
        "CREDIT_CARD": re.compile(r'\b(?:\d{4}[- ]?){3}\d{4}\b'),
        "PHONE": re.compile(r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b'),
        "EMAIL": re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
        "IP_ADDRESS": re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
    })


@dataclass
class PIIMatch:
    pii_type: str
    value: str
    start: int
    end: int
    source: str = "regex"  # "regex" or "ner"


class PIIDetector:
    """Multi-layer PII detector: regex + optional NER."""

    def __init__(self, config: Optional[PIIConfig] = None):
        self.config = config or PIIConfig()
        self._nlp = None
        if self.config.use_ner:
            self._init_ner()

    def _init_ner(self):
        try:
            import spacy
            self._nlp = spacy.load("en_core_web_sm")
        except (ImportError, OSError):
            self._nlp = None

    def detect(self, text: str) -> List[PIIMatch]:
        """Detect PII in text using all available methods."""
        if not self.config.detect:
            return []
        matches = []
        # Regex detection
        for pii_type, pattern in self.config.patterns.items():
            for m in pattern.finditer(text):
                matches.append(PIIMatch(
                    pii_type=pii_type, value=m.group(),
                    start=m.start(), end=m.end(), source="regex",
                ))
        # NER detection
        if self._nlp:
            doc = self._nlp(text)
            for ent in doc.ents:
                if ent.label_ in self.config.entity_types:
                    matches.append(PIIMatch(
                        pii_type=ent.label_, value=ent.text,
                        start=ent.start_char, end=ent.end_char,
                        source="ner",
                    ))
        return matches

    def redact(self, text: str, matches: Optional[List[PIIMatch]] = None) -> str:
        """Redact detected PII from text."""
        if matches is None:
            matches = self.detect(text)
        # Sort by position descending to preserve indices
        sorted_matches = sorted(matches, key=lambda m: m.start, reverse=True)
        result = text
        for m in sorted_matches:
            result = result[:m.start] + f"[REDACTED-{m.pii_type}]" + result[m.end:]
        return result
