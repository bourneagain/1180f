#!/usr/bin/env python3

import re
import sys
import subprocess

def check(pn):
    print("> %s" % pn)
    
    out = subprocess.check_output([pn], universal_newlines=True)

    stack = []
    cur_func = None
    for l in out.splitlines() + [None]:
        if l is None or l.startswith("func"):
            # flushing previous ones
            if cur_func:
                print("%s" % cur_func)
                for j in sorted(stack):
                    print("%s" % j)
            # done
            if l is None:
                return
            cur_func = l.strip()
            stack = []
            continue
        
        stack.append(l)
    
for pn in sys.argv[1:]:
    check(pn)