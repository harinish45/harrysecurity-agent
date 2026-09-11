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

    # Bidi/directional-format control characters (U+202A-U+202E, U+2066-U+2069)
    # — a "Trojan Source"-style evasion: inserting e.g. U+202E (RIGHT-TO-LEFT
    # OVERRIDE) in the middle of a blocked keyword breaks the literal regex
    # match while the word still reads/renders as the original keyword to a
    # human. NFKC normalization does not remove these (they're formatting
    # controls, not compatibility-decomposable characters), so they need the
    # same explicit strip the zero-width characters already get.
    #
    # This constant legitimately contains the literal bidi control characters
    # it exists to detect and strip — that's the whole point of a filter list,
    # the same way an antivirus signature file legitimately contains malware
    # byte sequences. Bandit's B613 flags any Python source file containing
    # these characters as a blanket Trojan-Source precaution; it can't
    # distinguish "these characters are hidden in code to smuggle malicious
    # logic past a reviewer" (the real risk it defends against) from "this
    # string constant's job is enumerating these exact characters." The
    # latter is what this is.
    _BIDI_CONTROL_CHARS = "‪‫‬‭‮⁦⁧⁨⁩"  # nosec B613 — see comment above

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
        for ch in cls._BIDI_CONTROL_CHARS:
            text = text.replace(ch, "")
        return text

    @classmethod
    def _strip_combining_marks(cls, text):
        """Drop Unicode combining marks (categories Mn/Mc/Me) — a diacritic
        inserted mid-keyword (e.g. "i" + U+0307 COMBINING DOT ABOVE + "gnore")
        breaks the literal "ignore" substring match while the payload still
        reads/renders as the original word, the same evasion class as the
        bidi-override and zero-width tricks above, found by property-fuzz
        testing. NFKC normalization does not remove these — they're valid,
        separately-encoded combining characters, not compatibility-decomposable
        forms of anything — so they need their own explicit strip."""
        return "".join(ch for ch in text if unicodedata.category(ch) not in ("Mn", "Mc", "Me"))

    @classmethod
    def _normalize(cls, payload):
        """NFD-decompose (so a precomposed accented letter like "ì" splits
        into "i" + a combining grave accent BEFORE the mark-strip below runs),
        strip zero-width/bidi-control/combining-mark characters, then
        NFKC-normalize for compatibility folding (fullwidth forms, etc.).

        Order matters here and was itself a real bug this fuzz pass caught:
        doing NFKC first (as the original version did) COMPOSES a base
        letter plus an adjacent combining mark into one precomposed
        character whenever a canonical equivalent exists (e.g. "i" + U+0300
        COMBINING GRAVE ACCENT -> "ì", U+00EC) — by the time the mark-strip
        ran, there was no longer a separate mark to strip, and "ì" is a
        single codepoint that doesn't literally spell "i". Decomposing
        first guarantees every combining mark is present as its own
        codepoint for the strip step to remove, regardless of whether the
        original payload arrived pre-composed or already split apart.
        """
        decomposed = unicodedata.normalize("NFD", payload)
        stripped = cls._strip_zero_width(decomposed)
        stripped = cls._strip_combining_marks(stripped)
        normalized = unicodedata.normalize("NFKC", stripped)
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
