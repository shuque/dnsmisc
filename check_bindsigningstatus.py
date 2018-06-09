#!/usr/bin/env python3
#

"""
Check the signing status of keys in a zone that is dynamically
signed and maintained by BIND9.

Given a master server IP address and zone name, this program
queries the private signing status record (RR type code 65534),
and prints out the status.

"""

import os, sys, struct
import dns.message, dns.query
from binascii import hexlify

SIGNING_STATUS_RECORD = 65534


def dnsQuery(ip, qname, qtype):
    resp = dns.query.udp(dns.message.make_query(qname, qtype),
                         ip)
    return resp


def printStatusRdata(rdata):
    alg = rdata[0]
    keyid = hexlify(rdata[1:3]).decode()
    keyid, = struct.unpack('!H', rdata[1:3])
    removal_flag = rdata[3]
    completed_flag = rdata[4]
    print("alg={} keyid={} remove={} complete={}".format(
        alg, keyid, removal_flag, completed_flag))
    return


if __name__ == '__main__':

    master_ip, zone = sys.argv[1:]
    resp = dnsQuery(master_ip, zone, SIGNING_STATUS_RECORD)
    if (resp.rcode() != 0) or (len(resp.answer) == 0):
        print("ERROR: record {} not found.".format(SIGNING_STATUS_RECORD))
        sys.exit(3)

    completed = False
    seenRecord = False

    for rrset in resp.answer:
        if rrset.rdtype != 65534:
            continue
        seenRecord = True
        for rr in rrset:
            printStatusRdata(rr.data)
            completed_flag = rr.data[-1]
            if completed_flag == 1:
                completed = True
            else:
                completed = False

    if not seenRecord:
        print("ERROR: Could not find signing status record.")
        sys.exit(2)
    if completed:
        print("OK: Signing completed")
        sys.exit(0)
    else:
        print("OK: Signing in progress")
        sys.exit(1)
