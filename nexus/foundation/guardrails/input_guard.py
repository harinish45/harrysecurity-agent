import re, json, os, unicodedata
from rich.console import Console

from ._entropy import shannon_entropy

console = Console()

class InputGuardError(Exception):
    pass

class InputGuard:
    MAX_LENGTH = 4000
    ENTROPY_THRESHOLD = 4.8
    ENTROPY_MIN_LENGTH = 40

    _ZERO_WIDTH_CHARS = "​‌‍﻿⁠"

    # Common Cyrillic/Greek confusables mapped to their ASCII lookalikes.
    _HOMOGLYPHS = {
        # Cyrillic lowercase
        "а": "a", "е": "e", "о": "o", "р": "p", "с": "c",
        "х": "x", "у": "y", "і": "i", "ѕ": "s", "ј": "j",
        "ԁ": "d", "һ": "h", "к": "k", "м": "m", "т": "t",
        "в": "b", "н": "h",
        # Cyrillic uppercase
        "А": "A", "Е": "E", "О": "O", "Р": "P", "С": "C",
        "Х": "X", "У": "Y", "В": "B", "Н": "H", "К": "K",
        "М": "M", "Т": "T",
        # Greek
        "α": "a", "ε": "e", "ο": "o", "ρ": "p", "υ": "y",
        "τ": "t", "κ": "k", "ν": "v",
        "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H",
        "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O",
        "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X",
    }

    _patterns = [
        re.compile(r"(?i)ignore\s+(all\s+)?(previous\s+)?(instructions|rules|guidelines)"),
        re.compile(r"(?i)IGNORE\s+.*?SYSTEM\s+PROMPT"),
        re.compile(r"(?i)disregard\s+(all\s+)?(prior|previous)"),
        re.compile(r"(?i)pretend\s+you\s+are\s+admin"),
        re.compile(r"(?i)you\s+are\s+now\s+in\s+developer\s+mode"),
        re.compile(r"(?i)run\s+.*?(rm\s+-rf|del\s+/f|format\s+c:)"),
        re.compile(r"(?i)\$\{.*?\}"),
        re.compile(r"(?i)<script.*?>"),
        re.compile(r"(?i)/etc/passwd"),
        re.compile(r"(?i)\.\./"),
        re.compile(r"(?i)(DROP\s+TABLE|DELETE\s+FROM|UPDATE.*?SET)"),
    ]

    @classmethod
    def _layer_patterns(cls, payload):
        """Run the regex pattern layer against a single string. Raises on match."""
        for pattern in cls._patterns:
            if pattern.search(payload):
                console.print(f"[red][INPUT GUARD] Blocked: {pattern.pattern}[/red]")
                raise InputGuardError(f"Input blocked: {pattern.pattern}")
        return True

    @classmethod
    def _strip_zero_width(cls, text):
        for ch in cls._ZERO_WIDTH_CHARS:
            text = text.replace(ch, "")
        return text

    @classmethod
    def _normalize(cls, payload):
        """NFKC-normalize and strip zero-width characters."""
        normalized = unicodedata.normalize("NFKC", payload)
        normalized = cls._strip_zero_width(normalized)
        return normalized

    @classmethod
    def _layer_homoglyph(cls, normalized_payload):
        """Collapse common Cyrillic/Greek confusables to ASCII and re-run patterns."""
        collapsed = "".join(cls._HOMOGLYPHS.get(ch, ch) for ch in normalized_payload)
        if collapsed != normalized_payload:
            cls._layer_patterns(collapsed)
        return True

    @classmethod
    def _layer_entropy(cls, payload):
        """Reject overlong payloads and flag high-entropy (encoded) payloads."""
        if len(payload) > cls.MAX_LENGTH:
            console.print(f"[red][INPUT GUARD] Blocked: payload exceeds MAX_LENGTH ({cls.MAX_LENGTH})[/red]")
            raise InputGuardError(f"Input blocked: payload exceeds max length {cls.MAX_LENGTH}")
        if len(payload) > cls.ENTROPY_MIN_LENGTH:
            entropy = shannon_entropy(payload)
            if entropy > cls.ENTROPY_THRESHOLD:
                console.print(f"[red][INPUT GUARD] Blocked: high entropy payload ({entropy:.2f})[/red]")
                raise InputGuardError(f"Input blocked: high entropy payload ({entropy:.2f})")
        return True

    @classmethod
    def _layer_control_chars(cls, payload):
        """Reject non-printable control characters other than \\n \\t \\r."""
        allowed = ("\n", "\t", "\r")
        for ch in payload:
            if ch in allowed:
                continue
            if unicodedata.category(ch) == "Cc":
                console.print("[red][INPUT GUARD] Blocked: disallowed control character[/red]")
                raise InputGuardError("Input blocked: disallowed control character")
        return True

    @classmethod
    def validate(cls, payload, context=None):
        if not payload or not isinstance(payload, str):
            return True

        # Layer 1: length / entropy on the raw payload.
        cls._layer_entropy(payload)

        # Layer 2: control character check on the raw payload.
        cls._layer_control_chars(payload)

        # Layer 3: regex patterns against the original payload.
        cls._layer_patterns(payload)

        # Layer 4: normalize (NFKC + zero-width strip) and re-check patterns.
        normalized = cls._normalize(payload)
        if normalized != payload:
            cls._layer_patterns(normalized)

        # Layer 5: homoglyph collapse and re-check patterns.
        cls._layer_homoglyph(normalized)

        return True

    @classmethod
    def log(cls, message, level="info"):
        console.print(f"[dim][InputGuard] {message}[/dim]")
