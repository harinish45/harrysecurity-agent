"""Deepfake detection -- honest stub, not a working feature.

**What this would be:** analysis of image, video, or audio media to detect
signs of AI-generated or manipulated content (face-swap artifacts, GAN
fingerprints, audio synthesis artifacts, temporal inconsistency across
video frames, etc.), presumably for use in social-engineering / phishing
investigations where a deepfaked voice or video is part of an attack.

**Why a genuine working version isn't buildable in this engineering pass:**
this is a domain mismatch. NEXUS is a network/web/infrastructure
penetration-testing and assessment platform -- there is no image, video, or
audio processing pipeline anywhere in this codebase (no decoders,
frame-extraction, spectrogram analysis, or any of the media-handling
infrastructure a real detector needs even before the ML model). Beyond the
missing pipeline, a real deepfake detector needs labeled training data
(genuine and manipulated media pairs) that this project has no license to
use, collect, or produce -- shipping a detector without that would mean
either using someone else's model wholesale with no ability to validate it,
or shipping something with no real detection capability behind it.

**Recommendation:** drop this from the roadmap rather than half-build a
detector with no real capability. If deepfake analysis becomes a genuine
product need, it belongs in a dedicated media-forensics tool/service
integrated with NEXUS via its findings pipeline, not as a bolted-on module
here.
"""
from __future__ import annotations

from typing import Any


class DeepfakeDetector:
    """Placeholder for a deepfake-detection feature that this codebase has
    no business building today. See module docstring."""

    def analyze(self, media_path: str) -> dict[str, Any]:
        raise NotImplementedError(
            "NEXUS has no image/video/audio processing pipeline anywhere "
            "in this codebase (it's a network/web/infrastructure "
            "pentesting platform), and a real deepfake detector needs "
            "labeled training data this project has no license to use or "
            "produce. This is a domain mismatch -- recommend dropping "
            "this from the roadmap rather than half-building a detector "
            "with no real capability behind it."
        )
