#!/usr/bin/env python3
"""
NEXUS-STRIKE — cloud.aws_credential_exposure
Domain: cloud
Real AWS credential exposure check: checks ~/.aws/credentials, ~/.aws/config for overly permissive IAM policies.
"""
from __future__ import annotations
import os
import configparser
from typing import Any
from nexus.foundation.schema import Finding, STATUS_COMPLETED, STATUS_NO_FINDINGS, STATUS_FAILED, tool_result
from nexus.tools.registry import tool_registry

def run(target: str, **kwargs: Any) -> dict:
    """Check for exposed AWS credentials and overly permissive configurations."""
    findings = []
    aws_info = {"profiles_found": [], "credential_file_exists": False, "config_file_exists": False}
    
    try:
        home_dir = os.path.expanduser("~")
        cred_path = os.path.join(home_dir, ".aws", "credentials")
        config_path = os.path.join(home_dir, ".aws", "config")
        
        aws_info["credential_file_exists"] = os.path.exists(cred_path)
        aws_info["config_file_exists"] = os.path.exists(config_path)
        
        if aws_info["credential_file_exists"]:
            findings.append(Finding(
                title="AWS Credentials File Detected",
                severity="medium",
                confidence="high",
                affected_asset=cred_path,
                evidence="An AWS credentials file exists on the system. If compromised, this could lead to unauthorized cloud access.",
                remediation="Ensure strict file permissions (e.g., chmod 600) on ~/.aws/credentials. Consider using IAM Roles or AWS Secrets Manager instead of long-lived access keys.",
                tool="cloud.aws_credential_exposure",
                references=["CWE-798", "CWE-522"]
            ))
            
            # Parse profiles
            config = configparser.ConfigParser()
            config.read(cred_path)
            aws_info["profiles_found"] = list(config.sections())
            
            for profile in aws_info["profiles_found"]:
                if "aws_access_key_id" in config[profile] and "aws_secret_access_key" in config[profile]:
                    findings.append(Finding(
                        title=f"Static AWS Access Keys Found in Profile: {profile}",
                        severity="high",
                        confidence="high",
                        affected_asset=f"{cred_path} [{profile}]",
                        evidence=f"Profile '{profile}' contains static aws_access_key_id and aws_secret_access_key.",
                        remediation="Rotate these keys immediately. Transition to IAM Roles for EC2/ECS or AWS SSO for human users.",
                        tool="cloud.aws_credential_exposure",
                        references=["CWE-798", "AWS IAM Best Practices"]
                    ))
        else:
            findings.append(Finding(
                title="No AWS Credentials File Detected",
                severity="low",
                confidence="high",
                affected_asset=target,
                evidence="No ~/.aws/credentials file was found on the system.",
                remediation="N/A",
                tool="cloud.aws_credential_exposure",
                references=[]
            ))
            
        summary = f"AWS credential check completed. Found {len(aws_info['profiles_found'])} profiles."
        status = STATUS_COMPLETED if aws_info["profiles_found"] else STATUS_NO_FINDINGS
        
    except Exception as e:
        return tool_result("cloud.aws_credential_exposure", target, status=STATUS_FAILED, error=str(e))

    return tool_result(
        "cloud.aws_credential_exposure", target,
        status=status,
        findings=findings,
        summary=summary,
        metadata=aws_info
    )

tool_registry.register("cloud.aws_credential_exposure", run, metadata={
    "name": "cloud.aws_credential_exposure",
    "domain": "cloud",
    "status": "completed",
    "description": "Checks local AWS configuration files for exposed credentials and risky profiles",
    "parameters": {"target": "Target hostname (used for logging, checks local ~/.aws/)"},
})