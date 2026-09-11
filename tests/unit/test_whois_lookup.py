"""reconnaissance.whois_lookup used to do zero WHOIS protocol work at all —
just DNS resolution + an HTTP GET, fully duplicating dns_recon.py despite
the name. Replaced with a real RFC 3912 client (raw TCP/43, IANA/ARIN
referral-following). These tests mock the socket layer — no real network
calls, no dependency on any external WHOIS server being reachable."""
from unittest.mock import MagicMock, patch

from nexus.tools.reconnaissance import whois_lookup


def _mock_connection(responses: dict[str, bytes]):
    """responses: {server: bytes_to_return_for_that_server}."""
    def _create_connection(address, timeout):
        server = address[0]
        sock = MagicMock()
        sock.__enter__.return_value = sock
        sock.__exit__.return_value = False
        payload = responses.get(server, b"")
        chunks = [payload, b""]

        def _recv(n):
            return chunks.pop(0) if chunks else b""

        sock.recv.side_effect = _recv
        return sock
    return _create_connection


def test_whois_domain_follows_iana_referral_and_parses_fields():
    iana_response = b"domain: EXAMPLE.COM\nrefer: whois.example-registry.test\n"
    registry_response = (
        b"Domain Name: EXAMPLE.COM\r\n"
        b"Registrar: Example Registrar LLC\r\n"
        b"Creation Date: 1995-08-14T04:00:00Z\r\n"
        b"Name Server: NS1.EXAMPLE.COM\r\n"
    )
    responses = {
        whois_lookup._IANA_WHOIS: iana_response,
        "whois.example-registry.test": registry_response,
    }
    with patch("socket.create_connection", side_effect=_mock_connection(responses)):
        result = whois_lookup.run("example.com")

    assert result["status"] == "completed"
    joined = "\n".join(result["findings"])
    assert "Registrar: Example Registrar LLC" in joined
    assert "Creation Date: 1995-08-14T04:00:00Z" in joined
    assert "whois.iana.org -> whois.example-registry.test" in joined


def test_whois_ip_queries_arin_directly():
    with patch("socket.create_connection", side_effect=_mock_connection({
        whois_lookup._ARIN_WHOIS: b"NetRange: 93.184.216.0 - 93.184.216.255\r\nOrgName: Example Org\r\n",
    })):
        result = whois_lookup.run("93.184.216.34")

    assert result["status"] == "completed"
    assert any("NetRange" in f for f in result["findings"])
    assert any(f.startswith("Queried: whois.arin.net") for f in result["findings"])


def test_whois_empty_response_is_reported_honestly():
    with patch("socket.create_connection", side_effect=_mock_connection({
        whois_lookup._IANA_WHOIS: b"",
    })):
        result = whois_lookup.run("nonexistent-tld-example.invalid")

    assert result["status"] == "completed"
    assert any("Empty WHOIS response" in f for f in result["findings"])


def test_whois_query_failure_does_not_crash():
    with patch("socket.create_connection", side_effect=OSError("connection refused")):
        result = whois_lookup.run("example.com")

    assert result["status"] == "completed"
    assert any("WHOIS query failed" in f for f in result["findings"])


def test_whois_no_longer_duplicates_dns_recon_or_http_probe_behavior():
    """The old implementation's findings always included 'Resolved ... ->'
    and 'HTTP .../: status=...' lines — confirm those are gone."""
    with patch("socket.create_connection", side_effect=_mock_connection({
        whois_lookup._IANA_WHOIS: b"domain: EXAMPLE.COM\n",
    })):
        result = whois_lookup.run("example.com")

    joined = "\n".join(result["findings"])
    assert "Resolved example.com ->" not in joined
    assert "HTTP http://example.com/" not in joined
