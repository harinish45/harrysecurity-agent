"""Tests for the 9 previously-fake cloud tools (nexus/tools/cloud/{azure_
assessment,container_scanning,docker_security,gcp_review,iac_review,
iam_audit,kubernetes_security,secret_detection,serverless_security}.py).

An audit found all 9 byte-for-byte identical: DNS resolve + a bare HTTP GET
on `/`, completely unrelated to what each tool claims to check. Each now
either does real work (subprocess-driven Docker/kubectl/az/gcloud CLI calls,
boto3 IAM calls, or local static-file regex scans) or honestly reports a
non-completed status (unavailable/requires_credentials/no_findings) when its
real prerequisite isn't met — never a fabricated finding.

These tests cover both paths:
  - honest-degrade: forced deterministically via monkeypatch/mock, since
    this dev environment realistically has no Docker daemon, no reachable
    Kubernetes cluster, no az/gcloud CLI, and no AWS credentials configured.
  - real logic: local synthetic files for the static-scan tools
    (iac_review, secret_detection, serverless_security), and mocked
    subprocess/boto3 responses for the CLI/SDK-driven tools so the actual
    parsing/finding logic is exercised end to end.
"""
from __future__ import annotations

import json
import subprocess
from unittest.mock import MagicMock, patch

import pytest

from nexus.tools.cloud import (
    azure_assessment,
    container_scanning,
    docker_security,
    gcp_review,
    iac_review,
    iam_audit,
    kubernetes_security,
    secret_detection,
    serverless_security,
)


def _completed(stdout="", returncode=0, stderr=""):
    return subprocess.CompletedProcess(args=["x"], returncode=returncode, stdout=stdout, stderr=stderr)


# ── docker_security ──────────────────────────────────────────────────────

def test_docker_security_unavailable_no_cli():
    with patch("nexus.tools.cloud.docker_security.shutil.which", return_value=None):
        result = docker_security.run("example.com")
    assert result["status"] == "unavailable"
    assert not result["findings"]


def test_docker_security_unavailable_daemon_unreachable():
    with patch("nexus.tools.cloud.docker_security.shutil.which", return_value="/usr/bin/docker"), \
         patch("nexus.tools.cloud.docker_security.subprocess.run",
               side_effect=subprocess.CalledProcessError(1, ["docker", "info"])):
        result = docker_security.run("example.com")
    assert result["status"] == "unavailable"
    assert not result["findings"]


def test_docker_security_real_logic_flags_privileged_and_socket_mount():
    inspect_payload = json.dumps([{
        "Name": "/risky",
        "Id": "abc123",
        "HostConfig": {"Privileged": True},
        "Mounts": [{"Source": "/var/run/docker.sock"}],
        "NetworkSettings": {"Ports": {"8080/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8080"}]}},
    }])

    def fake_run(cmd, **kwargs):
        if cmd[:2] == ["docker", "info"]:
            return _completed()
        if cmd[:2] == ["docker", "ps"]:
            return _completed(stdout="abc123\n")
        if cmd[:2] == ["docker", "inspect"]:
            return _completed(stdout=inspect_payload)
        raise AssertionError(f"unexpected command {cmd}")

    with patch("nexus.tools.cloud.docker_security.shutil.which", return_value="/usr/bin/docker"), \
         patch("nexus.tools.cloud.docker_security.subprocess.run", side_effect=fake_run):
        result = docker_security.run("example.com")

    assert result["status"] == "completed"
    titles = [f["title"] for f in result["findings"]]
    assert any("privileged" in t for t in titles)
    assert any("Docker socket" in t for t in titles)
    assert any("all interfaces" in t for t in titles)


def test_docker_security_no_containers_running():
    def fake_run(cmd, **kwargs):
        if cmd[:2] == ["docker", "info"]:
            return _completed()
        if cmd[:2] == ["docker", "ps"]:
            return _completed(stdout="")
        raise AssertionError(f"unexpected command {cmd}")

    with patch("nexus.tools.cloud.docker_security.shutil.which", return_value="/usr/bin/docker"), \
         patch("nexus.tools.cloud.docker_security.subprocess.run", side_effect=fake_run):
        result = docker_security.run("example.com")

    assert result["status"] == "no_findings"


# ── container_scanning ───────────────────────────────────────────────────

def test_container_scanning_unavailable_no_cli():
    with patch("nexus.tools.cloud.container_scanning.shutil.which", return_value=None):
        result = container_scanning.run("myimage:latest")
    assert result["status"] == "unavailable"


def test_container_scanning_failed_image_not_found():
    def fake_run(cmd, **kwargs):
        if cmd[:2] == ["docker", "info"]:
            return _completed()
        if cmd[:2] == ["docker", "inspect"]:
            return _completed(returncode=1, stderr="Error: No such object: nope")
        raise AssertionError(f"unexpected command {cmd}")

    with patch("nexus.tools.cloud.container_scanning.shutil.which", return_value="/usr/bin/docker"), \
         patch("nexus.tools.cloud.container_scanning.subprocess.run", side_effect=fake_run):
        result = container_scanning.run("nope:latest")

    assert result["status"] == "failed"


def test_container_scanning_real_logic_flags_secret_env_and_root_user():
    inspect_payload = json.dumps([{
        "Id": "sha256:deadbeef",
        "RepoTags": ["myimage:latest"],
        "Created": "2024-01-01T00:00:00Z",
        "Config": {
            "User": "",
            "ExposedPorts": {"80/tcp": {}},
            "Env": ["PATH=/usr/bin", "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"],
        },
    }])

    def fake_run(cmd, **kwargs):
        if cmd[:2] == ["docker", "info"]:
            return _completed()
        if cmd[:2] == ["docker", "inspect"]:
            return _completed(stdout=inspect_payload)
        raise AssertionError(f"unexpected command {cmd}")

    with patch("nexus.tools.cloud.container_scanning.shutil.which", return_value="/usr/bin/docker"), \
         patch("nexus.tools.cloud.container_scanning.subprocess.run", side_effect=fake_run):
        result = container_scanning.run("myimage:latest")

    assert result["status"] == "completed"
    titles = [f["title"] for f in result["findings"]]
    assert any("secret" in t.lower() for t in titles)
    assert any("runs as root" in t for t in titles)


# ── kubernetes_security ──────────────────────────────────────────────────

def test_kubernetes_security_unavailable_no_kubectl():
    with patch("nexus.tools.cloud.kubernetes_security.shutil.which", return_value=None):
        result = kubernetes_security.run("example.com")
    assert result["status"] == "unavailable"


def test_kubernetes_security_unavailable_no_kubeconfig():
    with patch("nexus.tools.cloud.kubernetes_security.shutil.which", return_value="/usr/bin/kubectl"), \
         patch("nexus.tools.cloud.kubernetes_security.os.environ.get", return_value=None), \
         patch("nexus.tools.cloud.kubernetes_security.os.path.exists", return_value=False):
        result = kubernetes_security.run("example.com")
    assert result["status"] == "unavailable"


def test_kubernetes_security_unavailable_cluster_unreachable():
    with patch("nexus.tools.cloud.kubernetes_security.shutil.which", return_value="/usr/bin/kubectl"), \
         patch("nexus.tools.cloud.kubernetes_security._kubeconfig_path", return_value="/fake/.kube/config"), \
         patch("nexus.tools.cloud.kubernetes_security.subprocess.run",
               return_value=_completed(returncode=1, stderr="dial tcp: no such host")):
        result = kubernetes_security.run("example.com")
    assert result["status"] == "unavailable"


def test_kubernetes_security_real_logic_flags_privileged_and_hostnetwork_pods():
    pods_payload = json.dumps({
        "items": [
            {
                "metadata": {"name": "bad-pod", "namespace": "default"},
                "spec": {
                    "hostNetwork": True,
                    "hostPID": True,
                    "containers": [
                        {"name": "c1", "securityContext": {"privileged": True}},
                    ],
                },
            },
            {
                "metadata": {"name": "good-pod", "namespace": "default"},
                "spec": {
                    "containers": [
                        {"name": "c2", "securityContext": {"runAsNonRoot": True, "runAsUser": 1000}},
                    ],
                },
            },
        ]
    })

    with patch("nexus.tools.cloud.kubernetes_security.shutil.which", return_value="/usr/bin/kubectl"), \
         patch("nexus.tools.cloud.kubernetes_security._kubeconfig_path", return_value="/fake/.kube/config"), \
         patch("nexus.tools.cloud.kubernetes_security.subprocess.run", return_value=_completed(stdout=pods_payload)):
        result = kubernetes_security.run("example.com")

    assert result["status"] == "completed"
    titles = [f["title"] for f in result["findings"]]
    assert any("hostNetwork" in t for t in titles)
    assert any("hostPID" in t for t in titles)
    assert any("privileged" in t for t in titles)
    assert not any("good-pod" in t for t in titles)


# ── iac_review ────────────────────────────────────────────────────────────

def test_iac_review_no_findings_path_not_found():
    result = iac_review.run("/definitely/not/a/real/path/xyz")
    assert result["status"] == "no_findings"
    assert not result["findings"]


def test_iac_review_real_logic_flags_open_ingress_and_wildcard_iam(tmp_path):
    tf_file = tmp_path / "main.tf"
    tf_file.write_text(
        'resource "aws_security_group_rule" "bad" {\n'
        '  type        = "ingress"\n'
        '  cidr_blocks = ["0.0.0.0/0"]\n'
        '}\n'
        'resource "aws_iam_policy" "admin" {\n'
        '  policy = jsonencode({\n'
        '    Statement = [{\n'
        '      Effect   = "Allow"\n'
        '      Action   = "*"\n'
        '      Resource = "*"\n'
        '    }]\n'
        '  })\n'
        '}\n',
        encoding="utf-8",
    )

    result = iac_review.run(str(tf_file))

    assert result["status"] == "completed"
    titles = [f["title"] for f in result["findings"]]
    assert any("0.0.0.0/0" in t for t in titles)
    assert any("wildcard" in t.lower() for t in titles)


def test_iac_review_real_logic_flags_hardcoded_aws_key(tmp_path):
    tf_file = tmp_path / "vars.tf"
    tf_file.write_text('access_key = "AKIAIOSFODNN7EXAMPLE"\n', encoding="utf-8")

    result = iac_review.run(str(tf_file))

    assert result["status"] == "completed"
    assert any("access key" in f["title"].lower() for f in result["findings"])


# ── secret_detection ─────────────────────────────────────────────────────

def test_secret_detection_no_findings_path_not_found():
    result = secret_detection.run("/definitely/not/a/real/path/xyz")
    assert result["status"] == "no_findings"


def test_secret_detection_real_logic_flags_aws_key_and_relabels_tool(tmp_path):
    secret_file = tmp_path / "config.env"
    secret_file.write_text("aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n", encoding="utf-8")

    result = secret_detection.run(str(secret_file))

    assert result["status"] == "completed"
    assert result["tool"] == "cloud.secret_detection"
    assert result["findings"], "expected at least one secret finding"
    for finding in result["findings"]:
        assert finding["tool"] == "cloud.secret_detection"


# ── serverless_security ──────────────────────────────────────────────────

def test_serverless_security_no_findings_path_not_found():
    result = serverless_security.run("/definitely/not/a/real/path/xyz")
    assert result["status"] == "no_findings"


def test_serverless_security_no_findings_when_no_config_file_present(tmp_path):
    (tmp_path / "readme.txt").write_text("nothing to see here", encoding="utf-8")
    result = serverless_security.run(str(tmp_path))
    assert result["status"] == "no_findings"


def test_serverless_security_real_logic_flags_wildcard_action_and_aws_key(tmp_path):
    sls_file = tmp_path / "serverless.yml"
    sls_file.write_text(
        "service: my-service\n"
        "provider:\n"
        "  name: aws\n"
        "  iamRoleStatements:\n"
        "    - Effect: Allow\n"
        "      Action: '*'\n"
        "      Resource: '*'\n"
        "functions:\n"
        "  hello:\n"
        "    handler: handler.hello\n"
        "    environment:\n"
        "      DB_PASSWORD: 'SuperSecretValue123'\n"
        "      NOTES: 'AKIAIOSFODNN7EXAMPLE'\n",
        encoding="utf-8",
    )

    result = serverless_security.run(str(sls_file))

    assert result["status"] == "completed"
    titles = [f["title"] for f in result["findings"]]
    assert any("wildcard" in t.lower() for t in titles)
    assert any("access key" in t.lower() for t in titles)


# ── iam_audit ─────────────────────────────────────────────────────────────

def test_iam_audit_unavailable_when_boto3_not_installed():
    with patch.dict("sys.modules", {"boto3": None}):
        result = iam_audit.run("account")
    assert result["status"] == "unavailable"


def test_iam_audit_requires_credentials_when_no_creds():
    from botocore.exceptions import NoCredentialsError

    fake_sts = MagicMock()
    fake_sts.get_caller_identity.side_effect = NoCredentialsError()
    fake_session = MagicMock()
    fake_session.client.return_value = fake_sts

    with patch("boto3.Session", return_value=fake_session):
        result = iam_audit.run("account")

    assert result["status"] == "requires_credentials"


def test_iam_audit_real_logic_flags_no_mfa_and_wildcard_policy():
    fake_sts = MagicMock()
    fake_sts.get_caller_identity.return_value = {"Account": "123456789012", "Arn": "arn:aws:iam::123456789012:user/admin"}

    fake_iam = MagicMock()
    fake_iam.list_users.return_value = {"Users": [{"UserName": "alice"}]}
    fake_iam.get_user.return_value = {"User": {"UserName": "alice", "PasswordLastUsed": "2024-01-01T00:00:00Z"}}
    fake_iam.list_mfa_devices.return_value = {"MFADevices": []}
    fake_iam.list_user_policies.return_value = {"PolicyNames": ["FullAdmin"]}
    fake_iam.get_user_policy.return_value = {
        "PolicyDocument": {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
    }
    fake_iam.list_attached_user_policies.return_value = {"AttachedPolicies": []}

    def client_factory(service_name):
        return {"sts": fake_sts, "iam": fake_iam}[service_name]

    fake_session = MagicMock()
    fake_session.client.side_effect = client_factory

    with patch("boto3.Session", return_value=fake_session):
        result = iam_audit.run("account")

    assert result["status"] == "completed"
    titles = [f["title"] for f in result["findings"]]
    assert any("without MFA" in t for t in titles)
    assert any("full admin" in t for t in titles)


# ── azure_assessment ──────────────────────────────────────────────────────

def test_azure_assessment_unavailable_no_cli():
    with patch("nexus.tools.cloud.azure_assessment.shutil.which", return_value=None):
        result = azure_assessment.run("sub")
    assert result["status"] == "unavailable"


def test_azure_assessment_requires_credentials_when_not_logged_in():
    with patch("nexus.tools.cloud.azure_assessment.shutil.which", return_value="/usr/bin/az"), \
         patch("nexus.tools.cloud.azure_assessment.subprocess.run",
               return_value=_completed(returncode=1, stderr="Please run 'az login'")):
        result = azure_assessment.run("sub")
    assert result["status"] == "requires_credentials"


def test_azure_assessment_real_logic_flags_public_storage_and_open_nsg():
    account_payload = json.dumps({"id": "sub-123", "name": "my-subscription"})
    storage_payload = json.dumps([{"name": "publicstorage", "allowBlobPublicAccess": True}])
    nsg_payload = json.dumps([{
        "name": "my-nsg",
        "securityRules": [{
            "name": "allow-all-in",
            "access": "Allow",
            "direction": "Inbound",
            "sourceAddressPrefix": "*",
            "destinationPortRange": "22",
        }],
    }])

    def fake_run(cmd, **kwargs):
        if cmd[:3] == ["az", "account", "show"]:
            return _completed(stdout=account_payload)
        if cmd[:3] == ["az", "storage", "account"]:
            return _completed(stdout=storage_payload)
        if cmd[:3] == ["az", "network", "nsg"]:
            return _completed(stdout=nsg_payload)
        raise AssertionError(f"unexpected command {cmd}")

    with patch("nexus.tools.cloud.azure_assessment.shutil.which", return_value="/usr/bin/az"), \
         patch("nexus.tools.cloud.azure_assessment.subprocess.run", side_effect=fake_run):
        result = azure_assessment.run("sub")

    assert result["status"] == "completed"
    titles = [f["title"] for f in result["findings"]]
    assert any("public blob access" in t for t in titles)
    assert any("internet" in t.lower() for t in titles)


# ── gcp_review ────────────────────────────────────────────────────────────

def test_gcp_review_unavailable_no_cli():
    with patch("nexus.tools.cloud.gcp_review.shutil.which", return_value=None):
        result = gcp_review.run("proj")
    assert result["status"] == "unavailable"


def test_gcp_review_requires_credentials_when_no_active_account():
    with patch("nexus.tools.cloud.gcp_review.shutil.which", return_value="/usr/bin/gcloud"), \
         patch("nexus.tools.cloud.gcp_review.subprocess.run", return_value=_completed(stdout="[]")):
        result = gcp_review.run("proj")
    assert result["status"] == "requires_credentials"


def test_gcp_review_real_logic_flags_open_firewall_rule():
    auth_payload = json.dumps([{"account": "me@example.com", "status": "ACTIVE"}])
    firewall_payload = json.dumps([{
        "name": "allow-all",
        "direction": "INGRESS",
        "sourceRanges": ["0.0.0.0/0"],
        "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}],
        "disabled": False,
    }])

    def fake_run(cmd, **kwargs):
        if cmd[:3] == ["gcloud", "auth", "list"]:
            return _completed(stdout=auth_payload)
        if cmd[:3] == ["gcloud", "config", "get-value"]:
            return _completed(stdout='"my-project"')
        if cmd[:3] == ["gcloud", "compute", "firewall-rules"]:
            return _completed(stdout=firewall_payload)
        if cmd[:3] == ["gcloud", "storage", "buckets"]:
            return _completed(stdout="[]")
        raise AssertionError(f"unexpected command {cmd}")

    with patch("nexus.tools.cloud.gcp_review.shutil.which", return_value="/usr/bin/gcloud"), \
         patch("nexus.tools.cloud.gcp_review.subprocess.run", side_effect=fake_run):
        result = gcp_review.run("proj")

    assert result["status"] == "completed"
    titles = [f["title"] for f in result["findings"]]
    assert any("0.0.0.0/0" in t for t in titles)
