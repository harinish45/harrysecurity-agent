#!/usr/bin/env python3
"""
NEXUS-STRIKE — cryptography.cryptanalysis
Domain: cryptography

Previously byte-for-byte identical to certificate_validation.py,
crypto_hash_analysis.py, key_management.py, and pki_reviews.py (a generic
TLS-socket scan dumping plain strings, unrelated to cryptanalysis at all)
— caught during this session's audit.

Cryptanalysis fundamentally needs actual ciphertext (and often known- or
chosen-plaintext) to analyze — there is no meaningful cryptanalysis of a
bare hostname/IP `target`. When `ciphertext` is supplied explicitly, this
performs a real classical-cipher attack: frequency analysis with a
chi-squared goodness-of-fit against known English letter frequencies to
recover the most likely Caesar/ROT-N shift key — a genuine, well-known
cryptanalysis technique, not a fabricated result. Without `ciphertext`
supplied, this honestly reports STATUS_UNAVAILABLE rather than reusing an
unrelated TLS probe.
"""
from __future__ import annotations

import string
from typing import Any

from nexus.foundation.schema import (
    Finding,
    STATUS_COMPLETED,
    STATUS_UNAVAILABLE,
    tool_result,
)
from nexus.tools.registry import tool_registry

# Standard English letter frequency table (percent), used for chi-squared
# scoring — the classic technique for breaking monoalphabetic substitution
# ciphers like Caesar/ROT-N.
_ENGLISH_FREQ = {
    'a': 8.17, 'b': 1.49, 'c': 2.78, 'd': 4.25, 'e': 12.70, 'f': 2.23,
    'g': 2.02, 'h': 6.09, 'i': 6.97, 'j': 0.15, 'k': 0.77, 'l': 4.03,
    'm': 2.41, 'n': 6.75, 'o': 7.51, 'p': 1.93, 'q': 0.10, 'r': 5.99,
    's': 6.33, 't': 9.06, 'u': 2.76, 'v': 0.98, 'w': 2.36, 'x': 0.15,
    'y': 1.97, 'z': 0.07,
}


def _caesar_shift(text: str, shift: int) -> str:
    out = []
    for ch in text:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            out.append(chr((ord(ch) - base - shift) % 26 + base))
        else:
            out.append(ch)
    return "".join(out)


def _chi_squared_score(text: str) -> float:
    letters = [c.lower() for c in text if c.isalpha()]
    n = len(letters)
    if n == 0:
        return float("inf")
    counts = {c: 0 for c in string.ascii_lowercase}
    for c in letters:
        counts[c] += 1
    score = 0.0
    for c, expected_pct in _ENGLISH_FREQ.items():
        expected = expected_pct / 100.0 * n
        observed = counts[c]
        if expected > 0:
            score += ((observed - expected) ** 2) / expected
    return score


def _break_caesar(ciphertext: str) -> dict:
    scored = [(shift, _chi_squared_score(_caesar_shift(ciphertext, shift))) for shift in range(26)]
    scored.sort(key=lambda t: t[1])
    best_shift, best_score = scored[0]
    return {
        "best_shift": best_shift,
        "chi_squared_score": round(best_score, 2),
        "plaintext_candidate": _caesar_shift(ciphertext, best_shift),
        "all_scores": {shift: round(score, 2) for shift, score in scored},
    }


def run(target: str, ciphertext: str | None = None, **kwargs: Any) -> dict:
    """Real Caesar/ROT-N chi-squared cryptanalysis when ciphertext is supplied; honest degrade otherwise."""
    if not ciphertext:
        return tool_result(
            "cryptography.cryptanalysis", target,
            status=STATUS_UNAVAILABLE,
            summary=f"Cryptanalysis of {target} requires actual ciphertext (and often "
                    f"known/chosen-plaintext) to analyze — none was supplied, so no "
                    f"cryptanalysis was attempted",
            error="unavailable: no ciphertext supplied (pass ciphertext=<text> to analyze)",
            metadata={
                "note": "Cryptanalysis cannot be meaningfully performed against a bare "
                        "hostname/IP target; it needs the actual ciphertext being assessed.",
            },
        )

    result = _break_caesar(ciphertext)
    findings = [Finding(
        title=f"Caesar/ROT-N cipher analysis: best-fit shift={result['best_shift']} "
              f"(chi-squared={result['chi_squared_score']})",
        severity="low", confidence="medium" if result["chi_squared_score"] < 50 else "low",
        affected_asset=target,
        evidence=f"plaintext candidate: {result['plaintext_candidate'][:200]!r}",
        remediation="If this is production data, monoalphabetic substitution ciphers (Caesar/ROT-N) "
                    "provide no real security — use an authenticated modern cipher (AES-GCM/ChaCha20-Poly1305).",
        tool="cryptography.cryptanalysis",
        references=["CWE-327"],
    )]

    return tool_result(
        "cryptography.cryptanalysis", target,
        status=STATUS_COMPLETED,
        findings=findings,
        summary=f"Real chi-squared frequency-analysis cryptanalysis recovered shift={result['best_shift']}",
        metadata=result,
    )


tool_registry.register("cryptography.cryptanalysis", run, metadata={
    "name": "cryptography.cryptanalysis",
    "domain": "cryptography",
    "status": "unavailable",
    "description": "Real chi-squared frequency-analysis Caesar/ROT-N cryptanalysis when ciphertext= is supplied; honest degrade (needs ciphertext) otherwise",
    "parameters": {
        "target": "Target domain, IP, or URL (context only)",
        "ciphertext": "Ciphertext to cryptanalyze (required for any real analysis)",
    },
})
