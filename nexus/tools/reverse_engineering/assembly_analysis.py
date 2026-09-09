#!/usr/bin/env python3
"""
NEXUS-STRIKE — reverse_engineering.assembly_analysis
Domain: reverse_engineering

Previously did only file-magic/hash inspection despite the name (no
assembly-level work at all) — genuinely useful as a baseline (kept below),
but the name overclaimed the capability, matching the pattern already
fixed in ghidra_analysis.py. Caught during this session's audit.

Now: when `capstone` is installed (it is NOT in this environment's
requirements.txt/venv — verified during this fix), this performs a real
Capstone disassembly of the binary's code section (PE .text located via a
hand-rolled struct parse of the PE header/section table, or ELF .text via
a struct parse of the ELF section headers — no `pefile`/`pyelftools`
dependency needed) and reports real mnemonic-frequency statistics. When
capstone is unavailable, it honestly falls back to the file-magic/hash
baseline and says so explicitly rather than claiming assembly analysis
happened.
"""
from __future__ import annotations

import hashlib
import os
import struct
from typing import Any

from nexus.foundation.schema import (
    Finding,
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_UNAVAILABLE,
    tool_result,
)
from nexus.tools.registry import tool_registry

_MAX_CODE_BYTES = 4096
_MAX_INSTRUCTIONS = 500


def _extract_code_section(data: bytes) -> tuple[bytes, str, str]:
    """Returns (code_bytes, arch_mode, format_label). arch_mode is one of
    'x86', 'x64'. Falls back to treating the whole file as a raw code blob
    if it isn't a recognised PE/ELF (e.g. shellcode)."""
    if data[:2] == b"MZ":
        try:
            e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
            if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
                raise ValueError("bad PE signature")
            file_hdr_off = e_lfanew + 4
            machine, num_sections, _, _, _, opt_hdr_size, _ = struct.unpack_from(
                "<HHIIIHH", data, file_hdr_off
            )
            arch = "x64" if machine == 0x8664 else "x86"
            sec_table_off = file_hdr_off + 20 + opt_hdr_size
            for i in range(num_sections):
                off = sec_table_off + i * 40
                name = data[off:off + 8].rstrip(b"\x00")
                _, _, size_raw, ptr_raw = struct.unpack_from("<8xIIII", data, off)
                if name == b".text":
                    return data[ptr_raw:ptr_raw + min(size_raw, _MAX_CODE_BYTES)], arch, "PE"
        except (struct.error, ValueError, IndexError):
            pass
        return data[:_MAX_CODE_BYTES], "x86", "PE (section parse failed, using file start)"

    if data[:4] == b"\x7fELF":
        try:
            ei_class = data[4]  # 1=32-bit, 2=64-bit
            is64 = ei_class == 2
            arch = "x64" if is64 else "x86"
            if is64:
                e_shoff, = struct.unpack_from("<Q", data, 0x28)
                e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 0x3A)
            else:
                e_shoff, = struct.unpack_from("<I", data, 0x20)
                e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 0x2E)

            def shdr(idx: int) -> tuple[int, int, int, int]:
                off = e_shoff + idx * e_shentsize
                if is64:
                    name_off, _, _, _, sh_offset, sh_size = struct.unpack_from("<IIQQQQ", data, off)
                else:
                    name_off, _, _, _, sh_offset, sh_size = struct.unpack_from("<IIIIII", data, off)
                return name_off, sh_offset, sh_size, off

            strtab_name_off, strtab_off, strtab_size, _ = shdr(e_shstrndx)
            for i in range(e_shnum):
                name_off, sh_offset, sh_size, _ = shdr(i)
                name_end = data.find(b"\x00", strtab_off + name_off)
                name = data[strtab_off + name_off:name_end]
                if name == b".text":
                    return data[sh_offset:sh_offset + min(sh_size, _MAX_CODE_BYTES)], arch, "ELF"
        except (struct.error, ValueError, IndexError):
            pass
        return data[:_MAX_CODE_BYTES], "x64", "ELF (section parse failed, using file start)"

    return data[:_MAX_CODE_BYTES], "x64", "unknown/raw (no PE/ELF signature — treated as raw code)"


def _hash_baseline(target: str, data: bytes) -> list[str]:
    lines = [
        f"File: {target}",
        f"Size: {len(data)} bytes",
        f"MD5: {hashlib.md5(data, usedforsecurity=False).hexdigest()}",
        f"SHA256: {hashlib.sha256(data).hexdigest()}",
    ]
    if data[:4] == b"\x7fELF":
        lines.append("File type: ELF binary")
    elif data[:2] == b"MZ":
        lines.append("File type: PE (Windows) binary")
    else:
        lines.append(f"File type: unknown (magic: {data[:4].hex()})")
    return lines


def run(target: str, **kwargs: Any) -> dict:
    """reverse_engineering tool: real Capstone-based assembly analysis when available."""
    if not os.path.isfile(target):
        return tool_result("reverse_engineering.assembly_analysis", target, status=STATUS_FAILED,
                            error=f"File not found: {target}")

    try:
        with open(target, "rb") as f:
            data = f.read()
    except OSError as e:
        return tool_result("reverse_engineering.assembly_analysis", target, status=STATUS_FAILED, error=str(e))

    baseline = _hash_baseline(target, data)

    try:
        import capstone
    except ImportError:
        return tool_result(
            "reverse_engineering.assembly_analysis", target,
            status=STATUS_UNAVAILABLE,
            findings=[Finding(
                title="capstone library not installed — assembly-level analysis unavailable",
                severity="low",
                confidence="high",
                affected_asset=target,
                evidence="\n".join(baseline),
                remediation="pip install capstone",
                tool="reverse_engineering.assembly_analysis",
            )],
            summary="Assembly analysis unavailable (capstone not installed); returned file-magic/hash baseline only.",
            metadata={"baseline": baseline},
        )

    code, arch, fmt = _extract_code_section(data)
    mode = capstone.CS_MODE_32 if arch == "x86" else capstone.CS_MODE_64
    md = capstone.Cs(capstone.CS_ARCH_X86, mode)

    mnemonic_counts: dict[str, int] = {}
    instructions = []
    for insn in md.disasm(code, 0):
        mnemonic_counts[insn.mnemonic] = mnemonic_counts.get(insn.mnemonic, 0) + 1
        if len(instructions) < _MAX_INSTRUCTIONS:
            instructions.append(f"{insn.address:#x}: {insn.mnemonic} {insn.op_str}")
        if len(instructions) >= _MAX_INSTRUCTIONS:
            break

    if not instructions:
        return tool_result(
            "reverse_engineering.assembly_analysis", target,
            status=STATUS_COMPLETED,
            findings=[Finding(
                title="No decodable instructions found in extracted code section",
                severity="low",
                confidence="medium",
                affected_asset=target,
                evidence=f"format={fmt}, arch={arch}, code_bytes={len(code)}",
                tool="reverse_engineering.assembly_analysis",
            )],
            summary=f"Disassembly attempted ({fmt}, {arch}) but produced 0 instructions.",
            metadata={"baseline": baseline, "format": fmt, "arch": arch},
        )

    top_mnemonics = sorted(mnemonic_counts.items(), key=lambda kv: -kv[1])[:10]
    call_count = mnemonic_counts.get("call", 0)
    ret_count = mnemonic_counts.get("ret", 0) + mnemonic_counts.get("retn", 0)
    int_count = sum(v for k, v in mnemonic_counts.items() if k.startswith("int"))

    findings = [Finding(
        title=f"Disassembled {len(instructions)} instructions from {fmt} {arch} code section",
        severity="low",
        confidence="high",
        affected_asset=target,
        evidence=f"Top mnemonics: {top_mnemonics}; call={call_count}, ret={ret_count}, int={int_count}",
        remediation="Review disassembly for obfuscation, anti-analysis, or shellcode-shaped patterns.",
        tool="reverse_engineering.assembly_analysis",
    )]
    if int_count > 0:
        findings.append(Finding(
            title=f"{int_count} interrupt instruction(s) found (possible syscall/anti-debug pattern)",
            severity="medium",
            confidence="medium",
            affected_asset=target,
            evidence=f"int instruction count: {int_count}",
            tool="reverse_engineering.assembly_analysis",
        ))

    return tool_result(
        "reverse_engineering.assembly_analysis", target,
        status=STATUS_COMPLETED,
        findings=findings,
        summary=f"Real Capstone disassembly: {len(instructions)} instructions from {fmt} {arch} code section",
        metadata={
            "baseline": baseline,
            "format": fmt,
            "arch": arch,
            "instruction_count": len(instructions),
            "sample_instructions": instructions[:20],
            "mnemonic_frequency": dict(top_mnemonics),
        },
    )


tool_registry.register("reverse_engineering.assembly_analysis", run, metadata={
    "name": "reverse_engineering.assembly_analysis",
    "domain": "reverse_engineering",
    "status": "completed",
    "description": "Real Capstone disassembly + mnemonic-frequency analysis of a local binary's code section when capstone is installed; honest file-magic/hash baseline otherwise",
    "parameters": {
        "target": "Path to the target binary file",
    },
})
