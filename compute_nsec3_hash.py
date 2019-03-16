#!/usr/bin/env python3

import os
import sys
import hashlib
import base64
import dns.name

b32_to_ext_hex = bytes.maketrans(b'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567',
                                 b'0123456789ABCDEFGHIJKLMNOPQRSTUV')

TEST_VECTORS = [
    [('9EBA4228', 1, 0, 'appforce.com.'), '8J1MO1GNFAB00QV63ROFSL7DBDQU0QN2'],
    [('', 1, 0, 'com.'), 'CK0POJMG874LJREF7EFN8430QVIT8BSM'],
    [('4C44934802D3', 1, 8, 'verisign.com.'), 'LVNT2DK6E38UB5HG27E7MCINT8M21C9P'],
    [('4AB238F7CD74D23D', 1, 50, 'toshiba.com.'), '7QN218CACBDEVNJIT57L56TRVR6RRHBP'],
]


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
        digest = hashfunc(digest + wire_salt).digest()
        iterations -= 1
    if binary_out:
        return digest
    else:
        output = base64.b32encode(digest)
        output = output.translate(b32_to_ext_hex).decode()
        return output


def run_tests():
    count = 0
    passed = 0
    print('Running tests ..')
    for (data, hashvalue) in TEST_VECTORS:
        count += 1
        salt, algnum, iterations, name = data
        out = nsec3hash(name, algnum, salt, iterations)
        if out == hashvalue:
            passed += 1
            print('OK: ', end='')
        else:
            print('ERROR: ', end='')
        print("{} {} {} {} = {}".format(
            name, algnum, salt, iterations, out))
    if passed == count:
        print('\nOK: All tests passed.')
        sys.exit(0)
    else:
        print('\nERROR: Not all tests passed.')
        sys.exit(1)


if __name__ == '__main__':

    if len(sys.argv) == 2 and sys.argv[1] == 'test':
        run_tests()

    if len(sys.argv) != 5:
        usage()

    salt, algnum, iterations, name = sys.argv[1:]
    algnum = int(algnum)
    iterations = int(iterations)
    print(nsec3hash(name, algnum, salt, iterations))
