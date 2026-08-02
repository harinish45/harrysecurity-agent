#!/usr/bin/env python3
"""
NEXUS-STRIKE — reverse_engineering.disassemble
Domain: reverse_engineering
Real disassembly: uses capstone disassembly on .text section, returns first 20 instructions.
"""
from __future__ import annotations
import os
from typing import Any
from nexus.foundation.schema import Finding, STATUS_COMPLETED, STATUS_NO_FINDINGS, STATUS_FAILED, STATUS_UNAVAILABLE, tool_result
from nexus.tools.registry import tool_registry

def run(target: str, **kwargs: Any) -> dict:
    """Perform disassembly on a target binary file."""
    findings = []
    disasm_info = {"instructions": [], "architecture": "unknown"}
    
    try:
        if not os.path.exists(target):
            return tool_result("reverse_engineering.disassemble", target, status=STATUS_FAILED, error=f"File not found: {target}")
            
        try:
            import capstone
            import pefile
            
            pe = pefile.PE(target)
            disasm_info["architecture"] = "x86" if pe.FILE_HEADER.Machine == 0x14c else "x64"
            
            # Get .text section
            text_section = None
            for section in pe.sections:
                if b".text" in section.Name:
                    text_section = section
                    break
                    
            if not text_section:
                return tool_result("reverse_engineering.disassemble", target, status=STATUS_FAILED, error=".text section not found")
                
            # Initialize capstone
            mode = capstone.CS_MODE_32 if disasm_info["architecture"] == "x86" else capstone.CS_MODE_64
            md = capstone.Cs(capstone.CS_ARCH_X86, mode)
            
            # Disassemble first 1000 bytes of .text section
            code = text_section.get_data()[:1000]
            instructions = []
            for i in md.disasm(code, text_section.VirtualAddress):
                instructions.append(f"{i.address:x}:\t{i.mnemonic}\t{i.op_str}")
                if len(instructions) >= 20:
                    break
                    
            disasm_info["instructions"] = instructions
            
            findings.append(Finding(
                title="Binary Disassembly Successful",
                severity="low",
                confidence="high",
                affected_asset=target,
                evidence=f"Successfully disassembled {len(instructions)} instructions from the .text section.",
                remediation="Review disassembled output for obfuscation or anti-analysis techniques.",
                tool="reverse_engineering.disassemble",
                references=[]
            ))
            
            summary = f"Disassembly completed. Extracted {len(instructions)} instructions."
            status = STATUS_COMPLETED
            
        except ImportError:
            return tool_result(
                "reverse_engineering.disassemble", target,
                status=STATUS_UNAVAILABLE,
                findings=[Finding(
                    title="capstone or pefile library not installed",
                    severity="low",
                    confidence="high",
                    affected_asset=target,
                    evidence="The 'capstone' and 'pefile' modules are required for disassembly.",
                    remediation="pip install capstone pefile",
                    tool="reverse_engineering.disassemble",
                    references=[]
                )],
                summary="Disassembly unavailable: required libraries not installed.",
                metadata=disasm_info
            )
        except Exception as e:
            return tool_result("reverse_engineering.disassemble", target, status=STATUS_FAILED, error=str(e))
            
    except Exception as e:
        return tool_result("reverse_engineering.disassemble", target, status=STATUS_FAILED, error=str(e))

    return tool_result(
        "reverse_engineering.disassemble", target,
        status=status,
        findings=findings,
        summary=summary,
        metadata=disasm_info
    )

tool_registry.register("reverse_engineering.disassemble", run, metadata={
    "name": "reverse_engineering.disassemble",
    "domain": "reverse_engineering",
    "status": "completed",
    "description": "Disassembles target binary using Capstone engine to analyze .text section",
    "parameters": {"target": "Path to the target binary file"},
})