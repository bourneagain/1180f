#!/usr/bin/env python3

import os
import sys
import re

pn = sys.argv[1]

html = open(pn).read()
html = re.sub("</section>", "</div></section>", html)
html = re.sub("(<section.*>)", r"\1<div>", html)
html = re.sub('(<code class="sourceCode c">)', r"\1  ", html)

with open(pn, "w") as fd:
    fd.write(html)