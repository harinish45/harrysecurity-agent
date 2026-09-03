#!/usr/bin/env python3
"""
NEXUS-STRIKE — cloud.s3_audit
Domain: cloud
S3 bucket misconfiguration scanner: public listing, public read, weak ACLs, missing buckets.
"""
from __future__ import annotations

import re
import ssl
import urllib.request
import urllib.parse
import urllib.error
from typing import Any

from nexus.foundation.schema import (
    Finding,
    STATUS_COMPLETED,
    STATUS_NO_FINDINGS,
    STATUS_FAILED,
    tool_result,
)
from nexus.tools.registry import tool_registry
from nexus.foundation.ssl_config import get_ssl_context

# Common S3 bucket naming patterns for company-name variations
DEFAULT_PATTERNS = [
    "{name}",
    "{name}-assets",
    "{name}-backup",
    "{name}-backups",
    "{name}-bucket",
    "{name}-cdn",
    "{name}-data",
    "{name}-db",
    "{name}-dev",
    "{name}-development",
    "{name}-files",
    "{name}-images",
    "{name}-logging",
    "{name}-logs",
    "{name}-media",
    "{name}-prod",
    "{name}-production",
    "{name}-public",
    "{name}-s3",
    "{name}-static",
    "{name}-staging",
    "{name}-test",
    "{name}-uploads",
    "{name}-web",
    "{name}-website",
    "{name}-www",
]


def _s3_request(bucket: str, object_path: str = "", timeout: int = 10) -> dict:
    """Perform an anonymous HTTP request against an S3 bucket."""
    # Try HTTPS first (default for S3), then HTTP as fallback
    url = f"https://{bucket}.s3.amazonaws.com/{object_path}"
    ctx = get_ssl_context(url, allow_insecure=True)
    req = urllib.request.Request(url, headers={"User-Agent": "NEXUS-STRIKE/1.0.0 (S3 Auditor)"})
    try:
        resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        body = resp.read(65536).decode("utf-8", errors="replace")
        return {"status": resp.status, "body": body, "headers": dict(resp.headers), "url": url}
    except urllib.error.HTTPError as e:
        body = (e.read(65536).decode("utf-8", errors="replace") if e.fp else "") or ""
        return {"status": e.code, "body": body, "headers": dict(e.headers), "url": url}
    except Exception:
        # Fall back to HTTP
        try:
            url_http = f"http://{bucket}.s3.amazonaws.com/{object_path}"
            req_http = urllib.request.Request(url_http, headers={"User-Agent": "NEXUS-STRIKE/1.0.0 (S3 Auditor)"})
            resp = urllib.request.urlopen(req_http, timeout=timeout, context=ctx)
            body = resp.read(65536).decode("utf-8", errors="replace")
            return {"status": resp.status, "body": body, "headers": dict(resp.headers), "url": url_http}
        except urllib.error.HTTPError as e2:
            body2 = (e2.read(65536).decode("utf-8", errors="replace") if e2.fp else "") or ""
            return {"status": e2.code, "body": body2, "headers": dict(e2.headers), "url": url_http}
        except Exception as exc:
            return {"status": 0, "body": "", "headers": {}, "url": url, "error": str(exc)[:100]}


def run(
    target: str,
    bucket_names: str = None,
    timeout: int = 10,
    rate_limit: float = 0.0,
    **kwargs: Any,
) -> dict:
    """Audit S3 buckets for public access and misconfigurations.

    Parameters
    ----------
    target : str
        Company name, domain, or base name used to generate bucket name candidates.
    bucket_names : str, optional
        Explicit comma-separated bucket names to test. If omitted, generated from target.
    timeout : int
        Request timeout in seconds.
    rate_limit : float
        Delay in seconds between bucket probes (default: 0.0).
        Set to e.g. 0.5 to avoid tripping AWS rate limits / enumeration detection.
    """
    if not target or not target.strip():
        return tool_result("cloud.s3_audit", target, status=STATUS_FAILED, error="Empty target")

    findings: list[Finding] = []
    results: list[dict] = []

    # Build the bucket name list
    if bucket_names:
        buckets = [b.strip().lower() for b in bucket_names.split(",") if b.strip()]
    else:
        base = target.lower().strip(".")
        # Strip scheme and path if a URL was passed
        base = re.sub(r"^https?://", "", base)
        base = base.split("/")[0].split(":")[0]
        # Extract the registrable part (e.g. example.com → example)
        if "." in base:
            parts = base.split(".")
            base = parts[0] if len(parts) > 1 else base
        base = base.replace("_", "-").replace(".", "-")
        buckets = [pattern.format(name=base) for pattern in DEFAULT_PATTERNS]

    for bucket in buckets:
        # 1. Does the bucket exist?
        resp = _s3_request(bucket, timeout=timeout)

        if resp["status"] == 0 or (resp["status"] and "NoSuchBucket" in resp["body"]):
            results.append({"bucket": bucket, "test": "exists", "exists": False})
            continue

        results.append({"bucket": bucket, "test": "exists", "exists": True})

        # 2. Can we list the bucket contents (ListBucket)?
        access_denied = "AccessDenied" in resp["body"] or resp["status"] == 403
        if resp["status"] == 200 and "<ListBucketResult" in resp["body"]:
            findings.append(Finding(
                title=f"S3 bucket '{bucket}' allows public listing (ListBucket)",
                severity="high",
                confidence="high",
                affected_asset=f"{bucket}.s3.amazonaws.com",
                evidence=f"Anonymous GET returned ListBucketResult (HTTP {resp['status']})",
                remediation="Block public read/list ACLs and enforce bucket policies that deny anonymous access.",
                tool="cloud.s3_audit",
                references=["CWE-284", "OWASP-API5"],
            ))
            results.append({"bucket": bucket, "test": "public_listing", "vulnerable": True})
        else:
            results.append({"bucket": bucket, "test": "public_listing", "vulnerable": access_denied is False})

        # 3. Can we read an object directly? Try a common path.
        for obj_path in ("index.html", "robots.txt", "test.txt", "README"):
            obj_resp = _s3_request(bucket, obj_path, timeout)
            if obj_resp["status"] == 200 and "NoSuchKey" not in obj_resp["body"]:
                findings.append(Finding(
                    title=f"S3 bucket '{bucket}' allows anonymous object read",
                    severity="critical",
                    confidence="high",
                    affected_asset=f"{bucket}.s3.amazonaws.com/{obj_path}",
                    evidence=f"Anonymous GET of /{obj_path} returned HTTP {obj_resp['status']}",
                    remediation="Apply a deny-all anonymous policy and verify with the S3 Block Public Access feature.",
                    tool="cloud.s3_audit",
                    references=["CWE-284", "OWASP-API5"],
                ))
                results.append({"bucket": bucket, "test": "public_read", "object": obj_path, "vulnerable": True})
                break
        else:
            results.append({"bucket": bucket, "test": "public_read", "vulnerable": False})

        # 4. Check for AllUsers READ via headers (ACL sniffing)
        acl_headers = {
            "x-amz-acl": resp["headers"].get("x-amz-acl", ""),
            "x-amz-grant-read": resp["headers"].get("x-amz-grant-read", ""),
        }
        if "AllUsers" in acl_headers.get("x-amz-grant-read", ""):
            findings.append(Finding(
                title=f"S3 bucket '{bucket}' has AllUsers READ grant",
                severity="medium",
                confidence="medium",
                affected_asset=f"{bucket}.s3.amazonaws.com",
                evidence="Bucket response includes x-amz-grant-read: AllUsers grant header",
                remediation="Remove the AllUsers read grant from the bucket ACL.",
                tool="cloud.s3_audit",
                references=["CWE-284", "OWASP-API5"],
            ))
            results.append({"bucket": bucket, "test": "acl_allusers_read", "vulnerable": True})

    # Check if any buckets existed at all
    existing = [r for r in results if r.get("exists")]
    status = STATUS_COMPLETED if findings else STATUS_NO_FINDINGS
    summary = f"Checked {len(buckets)} bucket candidate(s): {len(existing)} existed, {len(findings)} issue(s) found"
    return tool_result(
        "cloud.s3_audit",
        target,
        status=status,
        findings=findings,
        summary=summary,
        metadata={"results": results},
    )


tool_registry.register("cloud.s3_audit", run, metadata={
    "name": "cloud.s3_audit",
    "domain": "cloud",
    "status": "completed",
    "description": "S3 bucket misconfiguration scanner: public listing, public read, weak ACLs",
    "parameters": {
        "target": "Company name, domain, or base name for bucket candidates",
        "bucket_names": "Explicit comma-separated bucket names to test (optional)",
        "timeout": "Request timeout in seconds (default: 10)",
    },
})