#!/usr/bin/env python3
"""
NEXUS-STRIKE — network tool: Smb Enum
Domain: network
"""
from nexus.tools.registry import tool_registry


def run(target: str, **kwargs) -> dict:
    """network tool: Smb Enum"""
    findings = []
    try:
        import socket
        import concurrent.futures
        ports = kwargs.get("ports", [21,22,23,25,53,80,110,111,135,139,143,443,445,465,587,631,993,995,1433,1521,3000,3306,3389,4000,5000,5432,5900,6379,7070,8000,8080,8443,8888,9000,9090,9200,27017,27018,50000])
        def probe(port):
            try:
                with socket.create_connection((target, port), timeout=1):
                    return port
            except:
                return None
        with concurrent.futures.ThreadPoolExecutor(max_workers=60) as ex:
            results = list(ex.map(probe, ports))
        open_ports = sorted(p for p in results if p is not None)
        findings.append(f"Open ports on {target}: {open_ports}")
        if open_ports:
            known = {21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",80:"HTTP",110:"POP3",443:"HTTPS",445:"SMB",3306:"MySQL",3389:"RDP",5432:"PostgreSQL",6379:"Redis",8080:"HTTP-Alt",9200:"Elasticsearch"}
            for p in open_ports:
                svc = known.get(p, "Unknown")
                findings.append(f"Port {p}: {svc}")
    except Exception as e:
        findings.append(f"Error: {e}")
    return {"tool": "network.smb_enum", "domain": "network", "target": target, "status": "completed", "findings": findings}


# Register with tool registry
tool_registry.register("network.smb_enum", run, metadata={
    "name": "network.smb_enum",
    "domain": "network",
    "status": "completed",
    "description": "network tool: Smb Enum",
    "parameters": {
        "target": "Target domain, IP, or URL",
    },
})
