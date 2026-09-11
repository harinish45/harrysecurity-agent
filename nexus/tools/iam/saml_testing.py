#!/usr/bin/env python3
"""
NEXUS-STRIKE — iam.saml_testing
Domain: iam
Real network check for SAML metadata endpoints (/saml/metadata,
/simplesaml/module.php/saml/sp/metadata) via safe_urlopen, followed by real
extraction of signing-certificate presence and signature algorithm from any
metadata document found.

Metadata is parsed with targeted regexes rather than a full XML parser:
`defusedxml` is not a declared dependency of this project, and stdlib
`xml.etree.ElementTree`/`xml.dom.minidom` are documented XXE risks against
untrusted XML without it. Since all that's needed here is the presence of
`<X509Certificate>` and the `Algorithm=` attribute of `<SignatureMethod>`,
a full parse (and its attendant XXE surface) isn't warranted — this is the
"parse carefully" honest path rather than a fabricated one.

Previously this was a bare DNS resolve + a handful of unauthenticated GETs
against generic paths like /login, /admin (byte-for-byte identical to 19
other stub tools, and none of it actually SAML-specific) — caught during
this session's audit.
"""
from __future__ import annotations

import re
import urllib.error
import urllib.request
from typing import Any

from nexus.foundation.net import safe_urlopen
from nexus.foundation.schema import (
    Finding,
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_NO_FINDINGS,
    tool_result,
)
from nexus.foundation.ssl_config import get_ssl_context
from nexus.tools.registry import tool_registry

_SAML_PATHS = ("/saml/metadata", "/simplesaml/module.php/saml/sp/metadata")
_ENTITY_RE = re.compile(r"<(?:\w+:)?EntityDescriptor\b", re.I)
_X509_RE = re.compile(r"<(?:\w+:)?X509Certificate>\s*([A-Za-z0-9+/=\s]+?)\s*</(?:\w+:)?X509Certificate>", re.I)
_SIGALG_RE = re.compile(r'SignatureMethod[^>]*Algorithm=["\']([^"\']+)["\']', re.I)
_WEAK_SIG_MARKERS = ("rsa-sha1", "dsa-sha1", "#sha1")


def run(target: str, **kwargs: Any) -> dict:
    """Real SAML metadata fetch and signing-certificate/algorithm analysis.

    Parameters
    ----------
    target : str
        Hostname or URL of the SAML service provider / identity provider.
    """
    tool_name = "iam.saml_testing"
    if not target or not target.strip():
        return tool_result(tool_name, target, status=STATUS_FAILED, error="Empty target")

    base = (target if "://" in target else f"https://{target}").rstrip("/")
    found_url = None
    body = ""
    for path in _SAML_PATHS:
        url = f"{base}{path}"
        try:
            ctx = get_ssl_context(target, allow_insecure=True)
            req = urllib.request.Request(url, headers={"User-Agent": "NexusStrike/1.0"})
            resp = safe_urlopen(req, timeout=5, context=ctx)
            if resp.status == 200:
                candidate = resp.read(131072).decode("utf-8", errors="replace")
                if _ENTITY_RE.search(candidate):
                    found_url = url
                    body = candidate
                    break
        except Exception:
            continue

    if not found_url:
        return tool_result(
            tool_name, target,
            status=STATUS_NO_FINDINGS,
            summary=f"No SAML metadata endpoint found at {target} (checked {', '.join(_SAML_PATHS)}).",
        )

    certs = _X509_RE.findall(body)
    sig_algs = _SIGALG_RE.findall(body)
    findings: list[Finding] = []

    if not certs:
        findings.append(Finding(
            title="SAML metadata has no embedded signing certificate",
            severity="high", confidence="high",
            affected_asset=found_url,
            evidence="No <X509Certificate> element found in the EntityDescriptor metadata (regex "
                     "extraction — no XML entity parser was used, to avoid XXE).",
            remediation="Publish signed SAML metadata with a valid X.509 signing certificate.",
            tool=tool_name,
            references=["CWE-347"],
        ))

    weak_algs = [a for a in sig_algs if any(w in a.lower() for w in _WEAK_SIG_MARKERS)]
    if weak_algs:
        findings.append(Finding(
            title="SAML metadata advertises a weak signature algorithm",
            severity="medium", confidence="high",
            affected_asset=found_url,
            evidence=f"SignatureMethod Algorithm value(s) found: {weak_algs}",
            remediation="Use rsa-sha256 (or stronger) for SAML signature validation; retire SHA-1-based signing.",
            tool=tool_name,
            references=["CWE-327"],
        ))

    status = STATUS_COMPLETED if findings else STATUS_NO_FINDINGS
    return tool_result(
        tool_name, target,
        status=status,
        findings=findings,
        summary=f"Real SAML metadata fetched from {found_url}: {len(certs)} signing certificate(s), "
                f"{len(findings)} issue(s) found.",
        metadata={"metadata_url": found_url, "certificate_count": len(certs), "signature_algorithms": sig_algs},
    )


tool_registry.register("iam.saml_testing", run, metadata={
    "name": "iam.saml_testing",
    "domain": "iam",
    "status": "completed",
    "description": "Real SAML metadata endpoint check and signing-certificate/algorithm analysis",
    "parameters": {
        "target": "Hostname or URL of the SAML service provider / identity provider",
    },
})
