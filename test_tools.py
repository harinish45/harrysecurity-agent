#!/usr/bin/env python3
"""Comprehensive tool testing against www.aabsweets.com"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ['NEXUS_LEGAL_ACK'] = 'I_HAVE_WRITTEN_AUTHORIZATION'
os.environ['ESCALATION_APPROVED'] = 'true'

TARGET = 'www.aabsweets.com'
URL = 'https://www.aabsweets.com/order/'

results = {'passed': 0, 'failed': 0, 'errors': []}

def test(name, func, *args, **kwargs):
    try:
        r = func(*args, **kwargs)
        status = r.get('status', 'unknown')
        findings = r.get('findings', [])
        if status == 'completed':
            print(f'  [PASS] {name}: {len(findings)} findings')
            results['passed'] += 1
            for f in findings[:3]:
                print(f'         {f}')
        else:
            print(f'  [FAIL] {name}: status={status}')
            results['failed'] += 1
    except Exception as e:
        print(f'  [ERROR] {name}: {e}')
        results['failed'] += 1
        results['errors'].append(f'{name}: {e}')

print('=' * 60)
print('COMPREHENSIVE TOOL TEST REPORT')
print(f'Target: {TARGET}')
print('=' * 60)

# ── RECONNAISSANCE ──
print('\n--- RECONNAISSANCE ---')
from nexus.tools.reconnaissance.dns_recon import run as dns_run
test('dns_recon', dns_run, TARGET)

from nexus.tools.reconnaissance.whois_lookup import run as whois_run
test('whois_lookup', whois_run, TARGET)

from nexus.tools.reconnaissance.subdomain_enum import run as sub_run
test('subdomain_enum', sub_run, TARGET)

from nexus.tools.reconnaissance.tech_fingerprint import run as tech_run
test('tech_fingerprint', tech_run, URL)

from nexus.tools.reconnaissance.cert_transparency import run as cert_run
test('cert_transparency', cert_run, TARGET)

from nexus.tools.reconnaissance.email_harvest import run as email_run
test('email_harvest', email_run, TARGET)

# ── WEBAPP ──
print('\n--- WEBAPP ---')
from nexus.tools.webapp.scanner import run as scan_run
test('scanner', scan_run, URL)

from nexus.tools.webapp.sqli import run as sqli_run
test('sqli', sqli_run, target=URL)

from nexus.tools.webapp.xss import run as xss_run
test('xss', xss_run, URL)

from nexus.tools.webapp.dir_enum import run as dir_run
test('dir_enum', dir_run, URL)

from nexus.tools.webapp.waf_detect import run as waf_run
test('waf_detect', waf_run, URL)

from nexus.tools.webapp.ssl_test import run as ssl_run
test('ssl_test', ssl_run, TARGET)

from nexus.tools.webapp.cmdi import run as cmdi_run
test('cmdi', cmdi_run, URL)

from nexus.tools.webapp.csrf import run as csrf_run
test('csrf', csrf_run, URL)

from nexus.tools.webapp.lfi import run as lfi_run
test('lfi', lfi_run, URL)

from nexus.tools.webapp.ssrf import run as ssrf_run
test('ssrf', ssrf_run, URL)

from nexus.tools.webapp.xxe import run as xxe_run
test('xxe', xxe_run, URL)

from nexus.tools.webapp.idor import run as idor_run
test('idor', idor_run, URL)

from nexus.tools.webapp.jwt_analysis import run as jwt_run
test('jwt_analysis', jwt_run, URL)

from nexus.tools.webapp.rate_limit import run as rate_run
test('rate_limit', rate_run, URL)

from nexus.tools.webapp.session_mgmt import run as sess_run
test('session_mgmt', sess_run, URL)

from nexus.tools.webapp.api_security import run as api_run
test('api_security', api_run, URL)

from nexus.tools.webapp.auth_test import run as auth_run
test('auth_test', auth_run, URL)

from nexus.tools.webapp.file_upload import run as file_run
test('file_upload', file_run, URL)

from nexus.tools.webapp.graphql import run as gql_run
test('graphql', gql_run, URL)

from nexus.tools.webapp.crawler import run as crawl_run
test('crawler', crawl_run, URL)

# ── NETWORK ──
print('\n--- NETWORK ---')
from nexus.tools.network.port_scan import run as port_run
test('port_scan', port_run, TARGET, ports=[80, 443, 8080, 8443])

from nexus.tools.network.service_enum import run as svc_run
test('service_enum', svc_run, TARGET)

from nexus.tools.network.firewall_detect import run as fw_run
test('firewall_detect', fw_run, TARGET)

from nexus.tools.network.banner_grab import run as banner_run
test('banner_grab', banner_run, TARGET)

from nexus.tools.network.host_discovery import run as host_run
test('host_discovery', host_run, TARGET)

from nexus.tools.network.os_fingerprint import run as os_run
test('os_fingerprint', os_run, TARGET)

# ── VULN ASSESSMENT ──
print('\n--- VULN ASSESSMENT ---')
from nexus.tools.vuln_assessment.cve_analysis import run as cve_run
test('cve_analysis', cve_run, TARGET)

from nexus.tools.vuln_assessment.web_vuln_scanning import run as webvuln_run
test('web_vuln_scanning', webvuln_run, URL)

from nexus.tools.vuln_assessment.network_vuln_scanning import run as netvuln_run
test('network_vuln_scanning', netvuln_run, TARGET)

from nexus.tools.vuln_assessment.risk_scoring import run as risk_run
test('risk_scoring', risk_run, TARGET)

# ── COMPLIANCE ──
print('\n--- COMPLIANCE ---')
from nexus.tools.compliance.security_audits import run as audit_run
test('security_audits', audit_run, URL)

from nexus.tools.compliance.pci_dss_audit import run as pci_run
test('pci_dss_audit', pci_run, URL)

from nexus.tools.compliance.gdpr_audit import run as gdpr_run
test('gdpr_audit', gdpr_run, URL)

# ── CRYPTOGRAPHY ──
print('\n--- CRYPTOGRAPHY ---')
from nexus.tools.cryptography.tls_testing import run as tls_run
test('tls_testing', tls_run, TARGET)

from nexus.tools.cryptography.certificate_validation import run as cert_run2
test('certificate_validation', cert_run2, TARGET)

# ── IAM ──
print('\n--- IAM ---')
from nexus.tools.iam.sso_testing import run as sso_run
test('sso_testing', sso_run, TARGET)

from nexus.tools.iam.oauth_testing import run as oauth_run
test('oauth_testing', oauth_run, TARGET)

# ── THREAT INTEL ──
print('\n--- THREAT INTEL ---')
from nexus.tools.threat_intel.ioc_enrichment import run as ioc_run
test('ioc_enrichment', ioc_run, TARGET)

from nexus.tools.threat_intel.threat_feeds import run as feed_run
test('threat_feeds', feed_run, TARGET)

# ── CLOUD ──
print('\n--- CLOUD ---')
from nexus.tools.cloud.container_scanning import run as cont_run
test('container_scanning', cont_run, TARGET)

from nexus.tools.cloud.docker_security import run as dock_run
test('docker_security', dock_run, TARGET)

# ── BLUE TEAM ──
print('\n--- BLUE TEAM ---')
from nexus.tools.blue_team.hardening import run as hard_run
test('hardening', hard_run, TARGET)

from nexus.tools.blue_team.log_review import run as log_run
test('log_review', log_run, TARGET)

# ── SOC ──
print('\n--- SOC ---')
from nexus.tools.soc.siem_monitoring import run as siem_run
test('siem_monitoring', siem_run, TARGET)

# ── INCIDENT RESPONSE ──
print('\n--- INCIDENT RESPONSE ---')
from nexus.tools.incident_response.alert_triage import run as alert_run
test('alert_triage', alert_run, TARGET)

# ── MALWARE ──
print('\n--- MALWARE ---')
from nexus.tools.malware.hash_analysis import run as hash_run
test('hash_analysis', hash_run, TARGET)

# ── FORENSICS ──
print('\n--- FORENSICS ---')
from nexus.tools.forensics.log_analysis import run as logf_run
test('log_analysis', logf_run, TARGET)

# ── MOBILE ──
print('\n--- MOBILE ---')
from nexus.tools.mobile.android_analysis import run as and_run
test('android_analysis', and_run, TARGET)

# ── IOT ──
print('\n--- IOT ---')
from nexus.tools.iot.smart_device_assessment import run as iot_run
test('smart_device_assessment', iot_run, TARGET)

# ── WIRELESS ──
print('\n--- WIRELESS ---')
from nexus.tools.wireless.wifi_audit import run as wifi_run
test('wifi_audit', wifi_run, TARGET)

# ── EXPLOIT DEV ──
print('\n--- EXPLOIT DEV ---')
from nexus.tools.exploit_dev.fuzzing import run as fuzz_run
test('fuzzing', fuzz_run, TARGET)

# ── PURPLE TEAM ──
print('\n--- PURPLE TEAM ---')
from nexus.tools.purple_team.detection_testing import run as det_run
test('detection_testing', det_run, TARGET)

# ── SUMMARY ──
print('\n' + '=' * 60)
print(f'RESULTS: {results["passed"]} passed, {results["failed"]} failed')
if results['errors']:
    print(f'ERRORS:')
    for e in results['errors']:
        print(f'  - {e}')
print('=' * 60)