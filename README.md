# suri-rule-gen
Suricata Rule Generation Scripts


notes

#!/usr/bin/env python3

import os.path
outfile = 'suri-rule-gen.rules'

if os.path.exists(outfile):
    f = open(outfile, "a")
    f.write('test123')
else:
    f = open(outfile, "x")
    f.write('oh well')

