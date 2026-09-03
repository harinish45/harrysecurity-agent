"""nexus.advanced.deepfake_detection is an honest documented stub: it must
import cleanly and fail loud (NotImplementedError with a specific,
non-generic message) rather than shipping a fake detector."""
import pytest

from nexus.advanced.deepfake_detection import DeepfakeDetector


def test_analyze_raises_specific_not_implemented_error():
    detector = DeepfakeDetector()
    with pytest.raises(NotImplementedError) as exc_info:
        detector.analyze("/path/to/video.mp4")

    message = str(exc_info.value)
    assert "image/video/audio processing pipeline" in message
    assert "domain mismatch" in message
