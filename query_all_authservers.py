#!/usr/bin/env python3
#

"""
Query all nameserver addresses for a given zone, qname, and qtype.

"""

import os
import sys
import getopt
import json
import time
import dns.resolver
import dns.query
import dns.rdatatype
import dns.rdataclass
import dns.rcode
from sortedcontainers import SortedList


PROGNAME = os.path.basename(sys.argv[0])
VERSION = "0.0.1"

TIMEOUT = 3
RETRIES = 2

EDNS = True
EDNS_UDP_ADV = 1420

JSON = False
IP_RRTYPES = [dns.rdatatype.AAAA, dns.rdatatype.A]


def usage(msg=None):
    """Print usage string and terminate program."""

    if msg:
        print(msg)

    print("""\
{0} version {1}
Usage: {0} [Options] <zone> <qname> <qtype>

       Options:
       -h          Print this help string
       -4          Use IPv4 transport only
       -6          Use IPv6 transport only
       -e          Disable EDNS (and NSID)
       -j          Output JSON (default is text output)
""".format(PROGNAME, VERSION)
)
    sys.exit(4)


def process_args(arg_vector):
    """Process command line options and arguments"""

    global IP_RRTYPES, EDNS, JSON

    try:
        (options, args) = getopt.getopt(arg_vector, 'h46ej')
    except getopt.GetoptError as exc_info:
        usage("{}".format(exc_info))

    if len(args) != 3:
        usage("Missing positional arguments. 3 required")

    for (opt, optval) in options:
        _ = optval
        if opt == "-h":
            usage()
        elif opt == "-4":
            IP_RRTYPES = [dns.rdatatype.A]
        elif opt == "-6":
            IP_RRTYPES = [dns.rdatatype.AAAA]
        elif opt == "-e":
            EDNS = False
        elif opt == "-j":
            JSON = True

    return args


def get_nslist(zone):
    """Get NS name list for given zone"""

    nslist = SortedList()
    msg = dns.resolver.resolve(zone, dns.rdatatype.NS).response
    for rrset in msg.answer:
        if rrset.rdtype != dns.rdatatype.NS:
            continue
        for rdata in rrset:
            nslist.add(rdata.target)
    return nslist


def get_iplist(name):
    """Get IP address list for given name"""

    global IP_RRTYPES
    iplist = []
    for rrtype in IP_RRTYPES:
        msg = dns.resolver.resolve(name, rrtype,
                                   raise_on_no_answer=False).response
        for rrset in msg.answer:
            if rrset.rdtype != rrtype:
                continue
            for rdata in rrset:
                iplist.append(rdata.address)
    return iplist


def send_query_tcp(msg, ipaddress, timeout=TIMEOUT):
    """send DNS query over TCP to given IP address"""

    res = None
    try:
        res = dns.query.tcp(msg, ipaddress, timeout=timeout)
    except dns.exception.Timeout:
        print("WARN: TCP query timeout for {}".format(ipaddress))
    return res


def send_query_udp(msg, ipaddress, timeout=TIMEOUT, retries=RETRIES):
    """send DNS query over UDP to given IP address"""

    gotresponse = False
    res = None
    while (not gotresponse) and (retries > 0):
        retries -= 1
        try:
            res = dns.query.udp(msg, ipaddress, timeout=timeout)
            gotresponse = True
        except dns.exception.Timeout:
            print("WARN: UDP query timeout for {}".format(ipaddress))
    return res


def send_query(ipaddress, qname, qtype):
    """Send DNS query"""

    res = None
    msg = dns.message.make_query(qname, qtype)
    msg.flags &= ~dns.flags.RD
    if EDNS:
        msg.use_edns(edns=0, payload=EDNS_UDP_ADV,
                     options=[dns.edns.GenericOption(dns.edns.NSID, b'')])
    res = send_query_udp(msg, ipaddress,
                         timeout=TIMEOUT, retries=RETRIES)
    if res and (res.flags & dns.flags.TC):
        print("WARN: response was truncated; retrying with TCP ..")
        return send_query_tcp(msg, ipaddress, timeout=TIMEOUT)
    return res


def get_answer(ipaddress, qname, qtype):
    """
    Return list of answer rdata for query at given server address.
    Also return rcode, and the value of the NSID option if present.
    """

    answers = SortedList()
    nsid = None

    msg = send_query(ipaddress, qname, qtype)

    if EDNS:
        for option in msg.options:
            if option.otype == dns.edns.NSID:
                nsid = option.data.decode()

    for rrset in msg.answer:
        for rdata in rrset:
            answers.add(rdata.to_text())
    return msg.rcode(), answers, nsid


def main(zone, qname, qtype):
    """main function, invoked by either command line or lambda"""

    result = {}
    result['timestamp'] = time.time()
    result['query'] = {
        "zone": zone,
        "qname": qname,
        "qtype": qtype
    }
    result['answer'] = []

    nslist = get_nslist(zone)
    for nsname in nslist:
        for ipaddr in get_iplist(nsname):
            rcode, answers, nsid = get_answer(ipaddr, qname, qtype)
            answers = ",".join(answers)
            answer_dict = {}
            answer_dict['name'] = nsname.to_text()
            answer_dict['ip'] = ipaddr
            if nsid:
                answer_dict['nsid'] = nsid
            answer_dict['rcode'] = dns.rcode.to_text(rcode)
            answer_dict['answers'] = answers
            result['answer'].append(answer_dict)
    return result


def lambda_handler(event, context):
    """AWS Lambda function to return results"""

    global EDNS, IP_RRTYPES

    # Lambda still doesn't support IPv6, sigh ..
    IP_RRTYPES = [dns.rdatatype.A]

    print("Received event: " + json.dumps(event, indent=2))

    _ = context
    if "edns" in event:
        EDNS = event['edns']
    zone = event['zone']
    qname = event['qname']
    qtype = event['qtype']
    response = main(zone, qname, qtype)
    return response


if __name__ == '__main__':

    ZONE, QNAME, QTYPE = process_args(sys.argv[1:])
    RESULT = main(ZONE, QNAME, QTYPE)
    if JSON:
        print(json.dumps(RESULT))
    else:
        for ADICT in RESULT['answer']:
            NSID = ADICT['nsid'] if 'nsid' in ADICT else ''
            print("{} {} {} {}".format(ADICT['answers'],
                                       ADICT['name'],
                                       ADICT['ip'],
                                       NSID))
