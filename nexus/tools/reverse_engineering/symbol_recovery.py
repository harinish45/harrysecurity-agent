#!/usr/bin/env python3
"""
NEXUS-STRIKE — reverse_engineering.symbol_recovery
Domain: reverse_engineering

Previously did only file-magic/hash inspection despite the name (no
symbol-table work at all), matching the pattern fixed in
ghidra_analysis.py/assembly_analysis.py. Caught during this session's audit.

Now: a real ELF/PE symbol-table parse using only `struct` (no
pyelftools/pefile dependency, neither of which is in this environment's
requirements.txt):
  - ELF: parses the section header table to locate .symtab/.strtab (or
    .dynsym/.dynstr as a fallback for stripped binaries with a dynamic
    symbol table), then decodes each Elf32_Sym/Elf64_Sym entry and
    resolves each symbol's name from the string table.
  - PE: parses the Optional Header's Data Directory to locate the Export
    Directory Table (IMAGE_EXPORT_DIRECTORY) and resolves every exported
    function name via its RVA — the standard way symbols are recovered
    from a DLL/EXE that ships an export table.
If neither a symbol table nor an export table is present (fully stripped),
this honestly reports that rather than fabricating symbol names.
"""
from __future__ import annotations

import os
import struct
from typing import Any

from nexus.foundation.schema import (
    Finding,
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_NO_FINDINGS,
    tool_result,
)
from nexus.tools.registry import tool_registry

_MAX_SYMBOLS = 300


# ── ELF ──────────────────────────────────────────────────────────────────

def _elf_sections(data: bytes) -> tuple[bool, dict[str, tuple[int, int, int]]]:
    """Returns (is64, {section_name: (file_offset, size, link)})."""
    is64 = data[4] == 2
    if is64:
        e_shoff, = struct.unpack_from("<Q", data, 0x28)
        e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 0x3A)
    else:
        e_shoff, = struct.unpack_from("<I", data, 0x20)
        e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 0x2E)

    def raw_shdr(idx: int) -> tuple[int, int, int, int]:
        off = e_shoff + idx * e_shentsize
        if is64:
            name_off, _, _, _, sh_offset, sh_size, sh_link = struct.unpack_from("<IIQQQQI", data, off)
        else:
            name_off, _, _, _, sh_offset, sh_size, sh_link = struct.unpack_from("<IIIIIII", data, off)
        return name_off, sh_offset, sh_size, sh_link

    strtab_name_off, strtab_off, strtab_size, _ = raw_shdr(e_shstrndx)
    sections: dict[str, tuple[int, int, int]] = {}
    for i in range(e_shnum):
        name_off, sh_offset, sh_size, sh_link = raw_shdr(i)
        name_end = data.find(b"\x00", strtab_off + name_off)
        name = data[strtab_off + name_off:name_end].decode("ascii", errors="replace")
        sections[name] = (sh_offset, sh_size, sh_link)
    return is64, sections


def _elf_symbols(data: bytes) -> tuple[list[dict], str]:
    is64, sections = _elf_sections(data)
    for symtab_name, strtab_name in ((".symtab", ".strtab"), (".dynsym", ".dynstr")):
        if symtab_name not in sections:
            continue
        sym_off, sym_size, _ = sections[symtab_name]
        str_off, str_size, _ = sections.get(strtab_name, (0, 0, 0))
        entry_size = 24 if is64 else 16
        count = sym_size // entry_size if entry_size else 0
        symbols = []
        for i in range(min(count, _MAX_SYMBOLS)):
            off = sym_off + i * entry_size
            if is64:
                st_name, st_info, st_other, st_shndx, st_value, st_size = struct.unpack_from("<IBBHQQ", data, off)
            else:
                st_name, st_value, st_size, st_info, st_other, st_shndx = struct.unpack_from("<IIIBBH", data, off)
            if st_name == 0:
                continue
            name_end = data.find(b"\x00", str_off + st_name)
            name = data[str_off + st_name:name_end].decode("ascii", errors="replace")
            if not name:
                continue
            sym_type = st_info & 0xF  # STT_FUNC = 2, STT_OBJECT = 1
            symbols.append({
                "name": name,
                "value": hex(st_value),
                "size": st_size,
                "type": "FUNC" if sym_type == 2 else ("OBJECT" if sym_type == 1 else str(sym_type)),
            })
        if symbols:
            return symbols, symtab_name
    return [], ""


# ── PE ───────────────────────────────────────────────────────────────────

def _pe_export_symbols(data: bytes) -> list[dict]:
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        return []
    file_hdr_off = e_lfanew + 4
    # Full IMAGE_FILE_HEADER (20 bytes): Machine(H), NumberOfSections(H),
    # TimeDateStamp(I), PointerToSymbolTable(I), NumberOfSymbols(I),
    # SizeOfOptionalHeader(H), Characteristics(H).
    _machine, num_sections, _, _, _, opt_hdr_size, _ = struct.unpack_from("<HHIIIHH", data, file_hdr_off)
    opt_hdr_off = file_hdr_off + 20
    magic, = struct.unpack_from("<H", data, opt_hdr_off)
    data_dir_off = opt_hdr_off + (96 if magic == 0x10B else 112)
    export_rva, export_size = struct.unpack_from("<II", data, data_dir_off)
    if export_rva == 0 or export_size == 0:
        return []

    sec_table_off = file_hdr_off + 20 + opt_hdr_size
    sections = []
    for i in range(num_sections):
        off = sec_table_off + i * 40
        # Skip the 8-byte Name field, then VirtualSize/VirtualAddress/
        # SizeOfRawData/PointerToRawData (4 bytes each).
        vsize, vaddr, raw_size, raw_ptr = struct.unpack_from("<8xIIII", data, off)
        sections.append((vaddr, vsize, raw_ptr))

    def rva_to_off(rva: int) -> int | None:
        for vaddr, vsize, raw_ptr in sections:
            if vaddr <= rva < vaddr + max(vsize, 1):
                return raw_ptr + (rva - vaddr)
        return None

    export_off = rva_to_off(export_rva)
    if export_off is None:
        return []

    (_, _, _, _, name_rva, ordinal_base, num_funcs, num_names,
     addr_functions_rva, addr_names_rva, addr_ordinals_rva) = struct.unpack_from(
        "<IIHHIIIIIII", data, export_off
    )

    names_off = rva_to_off(addr_names_rva)
    if names_off is None or num_names == 0:
        return []

    symbols = []
    for i in range(min(num_names, _MAX_SYMBOLS)):
        name_rva_i, = struct.unpack_from("<I", data, names_off + i * 4)
        n_off = rva_to_off(name_rva_i)
        if n_off is None:
            continue
        name_end = data.find(b"\x00", n_off)
        name = data[n_off:name_end].decode("ascii", errors="replace")
        if name:
            symbols.append({"name": name, "type": "EXPORT_FUNC"})
    return symbols


def run(target: str, **kwargs: Any) -> dict:
    """reverse_engineering tool: real ELF symbol-table / PE export-table parse via struct."""
    if not os.path.isfile(target):
        return tool_result("reverse_engineering.symbol_recovery", target, status=STATUS_FAILED,
                            error=f"File not found: {target}")

    try:
        with open(target, "rb") as f:
            data = f.read()
    except OSError as e:
        return tool_result("reverse_engineering.symbol_recovery", target, status=STATUS_FAILED, error=str(e))

    try:
        if data[:4] == b"\x7fELF":
            symbols, source = _elf_symbols(data)
            fmt = "ELF"
        elif data[:2] == b"MZ":
            symbols, source = _pe_export_symbols(data), "export table"
            fmt = "PE"
        else:
            return tool_result(
                "reverse_engineering.symbol_recovery", target,
                status=STATUS_FAILED,
                error=f"Unrecognised file format (magic: {data[:4].hex()}) — not a PE or ELF binary",
            )
    except (struct.error, IndexError, ValueError) as e:
        return tool_result("reverse_engineering.symbol_recovery", target, status=STATUS_FAILED,
                            error=f"Malformed {'/'.join(['PE', 'ELF'])} structure while parsing: {e}")

    if not symbols:
        return tool_result(
            "reverse_engineering.symbol_recovery", target,
            status=STATUS_NO_FINDINGS,
            summary=f"No symbol table or export table found in this {fmt} binary — likely stripped.",
            metadata={"format": fmt},
        )

    func_symbols = [s for s in symbols if s.get("type") in ("FUNC", "EXPORT_FUNC")]
    findings = [Finding(
        title=f"Recovered {len(symbols)} symbol(s) from {fmt} binary ({source})",
        severity="low",
        confidence="certain",
        affected_asset=target,
        evidence=f"Sample names: {[s['name'] for s in symbols[:15]]}",
        remediation="Symbol names can reveal internal architecture/library usage; strip "
                    "production binaries if this is unintentional exposure.",
        tool="reverse_engineering.symbol_recovery",
    )]

    return tool_result(
        "reverse_engineering.symbol_recovery", target,
        status=STATUS_COMPLETED,
        findings=findings,
        summary=f"Recovered {len(symbols)} symbol(s) ({len(func_symbols)} function-like) from {fmt} binary via {source}",
        metadata={"format": fmt, "source": source, "symbols": symbols[:100]},
    )


tool_registry.register("reverse_engineering.symbol_recovery", run, metadata={
    "name": "reverse_engineering.symbol_recovery",
    "domain": "reverse_engineering",
    "status": "completed",
    "description": "Real ELF .symtab/.dynsym or PE export-table symbol recovery via hand-rolled struct parsing (no pyelftools/pefile dependency)",
    "parameters": {
        "target": "Path to the target binary file",
    },
})
