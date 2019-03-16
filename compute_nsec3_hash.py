#!/usr/bin/env python3

"""

Test Values:

$ nsec3hash 9EBA4228 1 0 appforce.com.
8J1MO1GNFAB00QV63ROFSL7DBDQU0QN2 (salt=9EBA4228, hash=1, iterations=0)

$ nsec3hash 4AB238F7CD74D23D 1 50 toshiba.com.
7QN218CACBDEVNJIT57L56TRVR6RRHBP (salt=4AB238F7CD74D23D, hash=1, iterations=50)

$ nsec3hash  4C44934802D3 1 8 verisign.com.
LVNT2DK6E38UB5HG27E7MCINT8M21C9P (salt=4C44934802D3, hash=1, iterations=8)

"""

import os
import sys
import hashlib
import base64
import dns.name

b32_to_ext_hex = bytes.maketrans(b'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567',
                                 b'0123456789ABCDEFGHIJKLMNOPQRSTUV')


def usage():
    PROGNAME = os.path.basename(sys.argv[0])
    print("""\
Usage: {0} <salt> <algorithm> <iterations> <domain-name>

       salt:        salt in hexadecimal string form
       algorithm:   must be 1 (SHA1)
       iterations:  number of iterations of the hash function
       domain-name: the domain-name
""".format(PROGNAME))
    sys.exit(1)


def hashalg(algnum):
    if algnum == 1:
        return hashlib.sha1
    else:
        raise ValueError("unsupported NSEC3 hash algorithm {}".format(algnum))


def nsec3hash(name, algnum, salt, iterations, binary_out=False):

    """Compute NSEC3 hash for given domain name and parameters"""

    if iterations < 0:
        raise(ValueError, "iterations must be >= 0")
    wire_name = dns.name.from_text(name).canonicalize().to_wire()
    wire_salt = bytes.fromhex(salt)
    hashfunc = hashalg(algnum)
    digest = wire_name
    while (iterations >= 0):
        s = hashfunc()
        s.update(digest + wire_salt)
        digest = s.digest()
        iterations -= 1
    if binary_out:
        return digest
    else:
        output = base64.b32encode(digest)
        output = output.translate(b32_to_ext_hex).decode()
        return output


if __name__ == '__main__':

    if len(sys.argv) != 5:
        usage()

    salt, algnum, iterations, name = sys.argv[1:]
    algnum = int(algnum)
    iterations = int(iterations)
    print(nsec3hash(name, algnum, salt, iterations))

