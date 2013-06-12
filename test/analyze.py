#!/usr/bin/python

import pstats
import sys

if len(sys.argv) > 1:
    fname = sys.argv[1]
else:
    fname = "profile.stats"

p = pstats.Stats(fname)
p.strip_dirs()
p.sort_stats("time")
p.print_stats()

