"""ghidra_analysis.py and ida_analysis.py both had a duplicate, unreachable
elif branch: `if data[:4]==ELF: ... elif data[:2]==MZ: ... elif data[:4]==ELF:`
— the second ELF check could never fire. Caught during this session's audit."""
import tempfile
from pathlib import Path

import pytest

from nexus.tools.reverse_engineering.ghidra_analysis import run as ghidra_run
from nexus.tools.reverse_engineering.ida_analysis import run as ida_run


@pytest.mark.parametrize("run_fn", [ghidra_run, ida_run])
@pytest.mark.parametrize("magic,expected", [
    (b"\x7fELF" + b"\x00" * 20, "ELF binary"),
    (b"MZ" + b"\x00" * 20, "PE (Windows) binary"),
    (b"\xde\xad\xbe\xef" + b"\x00" * 20, "unknown"),
])
def test_file_type_detected_exactly_once(tmp_path, run_fn, magic, expected):
    path = tmp_path / "sample.bin"
    path.write_bytes(magic)

    result = run_fn(str(path))

    matches = [f for f in result["findings"] if f.startswith("File type:")]
    assert len(matches) == 1, f"expected exactly one 'File type:' finding, got {matches}"
    assert expected in matches[0]


@pytest.mark.parametrize("run_fn", [ghidra_run, ida_run])
def test_non_file_target_reports_not_a_file(run_fn):
    result = run_fn("not-a-real-path-on-disk")
    assert any("not a file" in f for f in result["findings"])
