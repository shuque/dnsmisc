#!/usr/bin/python3
#

import sys
import dns.name

n = dns.name.from_text(sys.argv[1])
labels = n.labels
wire = n.to_digestable()
print(len(wire))
print(wire)
for label in labels:
    print(label, len(label)+1)
