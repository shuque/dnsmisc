#!/usr/bin/env python3
#

"""
Given a list of DNS RR types, print the wire representation of
the NSEC bitmaps field and associated breakdown by window number
and windowed bitmap.

"""

import argparse
from io import BytesIO
from binascii import hexlify
import dns.rdatatype
from dns.rdtypes.ANY.NSEC import Bitmap


def _to_wire(record):
    buf = BytesIO()
    record.to_wire(buf)
    return buf.getvalue()


def _make_rdtype(arg):
    try:
        value = dns.rdatatype.from_text(arg)
    except dns.rdatatype.UnknownRdatatype as unknown_rdtype:
        raise argparse.ArgumentError from unknown_rdtype
    return value


__description__ = """\
Given a list of DNS RR types, print the wire representation of
the NSEC bitmaps field and associated breakdown by window number
and windowed bitmap.
"""

parser = argparse.ArgumentParser(
    description=__description__)
parser.add_argument('rrtype',
                    type=_make_rdtype,
                    nargs='+')
args = parser.parse_args()

bitmaps = Bitmap.from_rdtypes(args.rrtype)
bitmaps_wire = _to_wire(bitmaps)
print("Bitmaps length:", len(bitmaps_wire))
print("Bitmaps wire:", hexlify(bitmaps_wire).decode())
print('')

for windownum, bitmap in bitmaps.windows:
    bitmap_hex = hexlify(bitmap).decode()
    print(f"{windownum:03d} len={len(bitmap):03d} 0x{bitmap_hex}")
