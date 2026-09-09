"""webapp.dir_enum's COMMON_DIRS mixes leading-slash entries ("/admin") with
bare filename entries (".env", "wp-config.php", ...); joining them with
`f"{base}{path}"` silently produced malformed URLs like
"http://127.0.0.1.env" and "http://127.0.0.1admin.php" for the entire
second group — exactly the highest-severity checks this tool exists to run
(.env, wp-config.php, .git/config). Caught live during an end-to-end
mission run this session, not in a mocked test."""
from nexus.tools.webapp import dir_enum


def test_check_path_urls_are_well_formed_for_every_common_dirs_entry(monkeypatch):
    seen_urls = []

    def fake_http_request(url, timeout=5):
        seen_urls.append(url)
        return {"status": 404, "size": 0}

    monkeypatch.setattr(dir_enum, "_http_request", fake_http_request)

    dir_enum.run("127.0.0.1", max_checks=len(dir_enum.COMMON_DIRS))

    assert len(seen_urls) == len(dir_enum.COMMON_DIRS)
    for url in seen_urls:
        # Exactly one "/" between host and path, for both "/admin"-style and
        # bare-filename-style COMMON_DIRS entries.
        assert "127.0.0.1." not in url, f"malformed (missing '/' before path): {url}"
        after_host = url.split("127.0.0.1", 1)[1]
        assert after_host.startswith("/"), f"malformed (no leading '/'): {url}"
        assert not after_host.startswith("//"), f"malformed (double '/'): {url}"


def test_check_path_finds_dotenv_at_the_correct_url(monkeypatch):
    requested = []

    def fake_http_request(url, timeout=5):
        requested.append(url)
        if url == "http://127.0.0.1/.env":
            return {"status": 200, "size": 42}
        return {"status": 404, "size": 0}

    monkeypatch.setattr(dir_enum, "_http_request", fake_http_request)

    result = dir_enum.run("127.0.0.1", max_checks=len(dir_enum.COMMON_DIRS))

    assert "http://127.0.0.1/.env" in requested
    titles = [f.get("title", "") if isinstance(f, dict) else str(f) for f in result["findings"]]
    assert any(".env" in t for t in titles)
