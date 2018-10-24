#!/usr/bin/env python3

import re
import sys
import subprocess

def check(pn):
    stat = {}
    
    out = subprocess.check_output(["objdump", "-M", "intel-mnemonic", "-d", pn],
                                  universal_newlines=True)

    cur_func = None
    for l in out.splitlines():
        m = re.match("[0-9a-f]+ <(\w+)>:.*", l)
        if m:
            cur_func = m.groups()[0]
            stat[cur_func] = False
            continue

        if "__stack_chk_fail" in l:
            stat[cur_func] = True

    print("%s" % pn)
    for k, v in stat.items():
        if k.startswith("func") or k == "main":
            print(" %-15s: %s" % (k, v))
    
for pn in sys.argv[1:]:
    check(pn)