#!/usr/bin/env python3

import os
import glob
import subprocess
import optparse

ROOT = os.path.dirname(__file__)

parser = optparse.OptionParser()
parser.add_option("-f", "--force", help="force", action="store_true", default=False)
(opts, args) = parser.parse_args()

for pn in sorted(glob.glob("%s/lec*/ex*.c" % ROOT)):
    src = os.path.abspath(pn)
    pdf = os.path.splitext(src)[0] + ".pdf"

    if opts.force \
       or not os.path.exists(pdf) \
       or os.stat(src).st_mtime > os.stat(pdf).st_mtime:

        name = os.path.basename(src)[:-2]
        assert name.startswith("ex")

        lec = src.split("/")[-2]
        assert lec.startswith("lec")
        
        L = "%02d" % int(lec.split("-")[0][3:])
        N = "%02d" % int(name[2:].split("-")[0])
        TITLE = " ".join(name.split("-")[1:]).capitalize()
        CODE = open(src).read()

        template = open(os.path.join(ROOT, "exercise.md")).read()
        for k in ["N", "L", "TITLE", "CODE"]:
            template = template.replace("{{%s}}" % k, str(eval(k)))

        print("Generating: %s" % pdf)
        p = subprocess.Popen(["pandoc", "-o", pdf], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        p.stdin.write(template.encode("ascii"))
        p.stdin.close()
        p.wait()
    
pdfs = sorted(glob.glob("%s/lec*/ex*.pdf" % ROOT))
subprocess.check_output(["pdfjoin", "-q", "-o", "exercises.pdf"] + pdfs)
    