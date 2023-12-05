#!/usr/bin/env python3
#

"""
Decode DNSKEY RDATA provided in text form as the command line argument.

"""

import sys
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.dnssec


r = dns.rdata.from_text(dns.rdataclass.IN,
                        dns.rdatatype.DNSKEY,
                        sys.argv[1])
print(r)
print('')
print("keytag:", dns.dnssec.key_id(r))
print("flags:", r.flags)
print("protocol:", r.protocol)
print("algorithm:", r.algorithm)
print("keylength:", len(r.key)*8)
