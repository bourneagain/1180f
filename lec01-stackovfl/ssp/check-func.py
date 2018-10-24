#!/usr/bin/env python3

import re
import sys
import subprocess

def objdump(pn):
    return subprocess.check_output(["objdump", "-M", "intel-mnemonic",
                                    "--no-show-raw-insn", "-d", pn],
                                   universal_newlines=True)

def check(pn, func):
    funcs = {}
    out = objdump(pn)

    cur_func = None
    for l in out.splitlines():
        m = re.match("[0-9a-f]+ <(\w+)>:.*", l)
        if m:
            cur_func = m.groups()[0]
            funcs[cur_func] = []
            continue

        l = l.strip()
        if cur_func and ":" in l:
            lnum, asm = l.split(":", 1)
            funcs[cur_func].append("  " + asm.strip())

    return "\n".join(funcs.get(func, [])).rstrip()
    
if len(sys.argv) != 3:
    print("%s [file] [func]")
    exit(1)

pn = sys.argv[1]
func = sys.argv[2]
disas = check(pn, func)

print("%s()@%s\n%s" % (func, pn, disas))