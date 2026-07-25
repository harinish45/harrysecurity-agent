#!/usr/bin/env python3
"""Quick verification: count remaining stubs and check syntax."""
import os, glob

BASE = r'c:\Documents\Projects\Cyber Secuirty Agent\nexus-strike'
TOOLS_DIR = os.path.join(BASE, 'nexus', 'tools')

stubs = 0
total = 0
syntax_errors = 0

for f in glob.glob(os.path.join(TOOLS_DIR, '**', '*.py'), recursive=True):
    if f.endswith('__init__.py'):
        continue
    total += 1
    content = open(f, 'r', errors='replace').read()
    if '"status":"stub"' in content or "'status':'stub'" in content:
        stubs += 1
    try:
        compile(content, f, 'exec')
    except SyntaxError as e:
        syntax_errors += 1
        print(f'SYNTAX ERROR: {f}: {e}')

print(f'Total tool files: {total}')
print(f'Remaining stubs: {stubs}')
print(f'Syntax errors: {syntax_errors}')
