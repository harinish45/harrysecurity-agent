import pytest

from nexus.foundation.paths import PathTraversalError, safe_join, safe_slug


def test_safe_join_normal_filename(tmp_path):
    (tmp_path / "report.json").write_text("{}")
    result = safe_join(tmp_path, "report.json")
    assert result == (tmp_path / "report.json").resolve()


def test_safe_join_rejects_forward_slash(tmp_path):
    with pytest.raises(PathTraversalError):
        safe_join(tmp_path, "../secrets.txt")


def test_safe_join_rejects_backslash(tmp_path):
    with pytest.raises(PathTraversalError):
        safe_join(tmp_path, "..\\..\\Windows\\win.ini")


def test_safe_join_rejects_dot_segment(tmp_path):
    with pytest.raises(PathTraversalError):
        safe_join(tmp_path, "..")
    with pytest.raises(PathTraversalError):
        safe_join(tmp_path, ".hidden")


def test_safe_join_rejects_empty_name(tmp_path):
    with pytest.raises(PathTraversalError):
        safe_join(tmp_path, "")


def test_safe_join_rejects_null_byte(tmp_path):
    with pytest.raises(PathTraversalError):
        safe_join(tmp_path, "report.json\x00.txt")


def test_safe_slug_collapses_unsafe_characters():
    slug = safe_slug("https://evil.example/../../etc/passwd")
    assert "/" not in slug
    assert ":" not in slug
    assert all(c.isalnum() or c in "._-" for c in slug)


def test_safe_slug_has_no_path_separators():
    slug = safe_slug("..\\..\\..\\Windows\\win.ini")
    assert "/" not in slug
    assert "\\" not in slug


def test_safe_slug_never_empty():
    assert safe_slug("...") == "target"
    assert safe_slug("   ") == "target"


def test_safe_slug_respects_max_length():
    slug = safe_slug("a" * 500, max_length=50)
    assert len(slug) <= 50
