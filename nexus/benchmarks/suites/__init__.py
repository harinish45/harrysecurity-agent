from nexus.benchmarks.suites.intercode_smoke import InterCodeSmokeSuite
from nexus.benchmarks.suites.external_stub import CybenchSuite, NyuCtfSuite

SUITES = {
    "intercode_ctf": InterCodeSmokeSuite,
    "cybench": CybenchSuite,
    "nyu_ctf": NyuCtfSuite,
}

__all__ = ["SUITES", "InterCodeSmokeSuite", "CybenchSuite", "NyuCtfSuite"]
