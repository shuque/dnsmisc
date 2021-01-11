#!/usr/bin/env python3
#

"""
ip2asn.py

The name is a bit of a misnomer, since it returns more information
about the IP address than just the ASN.

Given an IP address, returns information about the advertising ASN,
covering network prefix, responsible RIR, and date?

Uses the specialized DNS zone service operated by CYMRU to obtain
this information from internet routing looking glasses.

"""

import os.path
import sys
import socket
import dns.resolver
import dns.reversename

PROGNAME = os.path.basename(sys.argv[0])
VERSION = "0.1"

IP2ASN_V4_SUFFIX = ".origin.asn.cymru.com."
IP2ASN_V6_SUFFIX = ".origin6.asn.cymru.com."


def usage():
    """Print usage string"""
    print("Usage: {} <address>".format(PROGNAME))
    sys.exit(1)


def get_resolver(timeout=5, edns=False):
    """return initialized resolver object"""
    r = dns.resolver.Resolver()
    r.lifetime = timeout
    if edns:
        r.use_edns(edns=0, ednsflags=0, payload=4096)
    return r


def do_query(r, qname, qtype, qclass='IN', quiet_notfound=False):
    """Perform DNS query and return answer RRset object"""
    response = None
    try:
        answers = r.resolve(qname, qtype, qclass)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        if not quiet_notfound:
            print("{}/{}/{}: No records found.".format(qname, qtype, qclass))
    except dns.exception.Timeout:
        print("{}/{}/{}: Query timed out.".format(qname, qtype, qclass))
    except Exception as e:
        print("{}/{}/{}: error: {}".format(qname, qtype, qclass,
                                           type(e).__name__))
    else:
        response = answers.rrset

    return response


def reverse_octets(packedstring):
    return ["%d" % x for x in packedstring]


def reverse_hexdigits(packedstring):
    return ''.join(["%02x" % x for x in packedstring])


def ip2asn(res, address):
    """
    TXT records queried return single strings of the form:
    ASN | IPprefix | CountryCode | RIR | date, e.g.
    '55 | 128.91.0.0/16 | US | arin | '
    '55 | 2607:f470::/32 | US | arin | 2008-05-01'
    """
    qname = None
    try:
        if address.find('.') != -1:
            packed = socket.inet_pton(socket.AF_INET, address)
            octetlist = reverse_octets(packed)
            qname = '.'.join(octetlist[::-1]) + IP2ASN_V4_SUFFIX
        elif address.find(':') != -1:
            packed = socket.inet_pton(socket.AF_INET6, address)
            hexlist = reverse_hexdigits(packed)
            qname = '.'.join(hexlist[::-1]) + IP2ASN_V6_SUFFIX
    except socket.error:
        pass
    if not qname:
        raise ValueError("%s isn't an IP address" % address)

    txt_rrset = do_query(res, qname, 'TXT')
    if txt_rrset:
        return txt_rrset[0].strings[0].decode('utf-8')

    return None


if __name__ == '__main__':

    if len(sys.argv) != 2:
        usage()

    address = sys.argv[1]
    res = get_resolver()

    print(ip2asn(res, address))
