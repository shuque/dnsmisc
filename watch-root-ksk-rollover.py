#!/usr/bin/env python3
#

"""
Monitor a root zone KSK rollover. Periodically query the root DNSKEY
RRset directly at every root server address, and record when each one
starts serving a DNSKEY RRset signed by the new KSK.

Runs until interrupted with Control-C, then prints a summary.

How it works:

  At startup, the root server names are obtained by querying ". NS"
  via the system resolver, and their IPv4 and IPv6 addresses by
  querying A and AAAA records for each name (-4 or -6 restricts this
  to one address family). This list of (server name, address) targets
  is fixed for the life of the program.

  Every interval (-i, default 60 seconds), a ". DNSKEY" query is sent
  to all targets in parallel. Queries are sent directly to the root
  server addresses (not via a resolver) to avoid caching effects. Each
  query has the RD (recursion desired) flag cleared, and uses EDNS0
  with the DO (DNSSEC OK) bit set, a 1232 byte UDP payload size, and
  an empty NSID option. UDP queries are retried on timeout, and are
  retried over TCP if the response is truncated. The NSID returned in
  the response identifies the particular anycast instance of the root
  server that answered.

  From each response, the keytags of the RRSIG records covering the
  DNSKEY RRset are extracted, along with their inception and
  expiration times. The program tracks the most recently seen set of
  signing keytags for each target, and prints a line only when that
  set changes. Each line is labelled with one of these events:

    INIT    First observation of this target
    NEWKSK  First time this target has been seen signed by the new KSK
    REVERT  Target was signed by the new KSK, but no longer is. This
            can happen with anycast, when routing shifts the queries to
            an instance that has not yet loaded the newly signed zone.
    CHANGE  Any other change in the signing keytag set. For example,
            the appearance of a revoked old KSK's signature.
    ERROR   Query timed out, failed, or returned a non-NOERROR rcode.
            The target's tracked state is left unchanged.

  After each round, a ROUND line reports how many targets are
  currently signed by the new KSK, and how many queries failed.

  When interrupted with Control-C, a summary table is printed showing
  each target's current signing keytags, the time it was first seen
  signed by the new KSK, and the number of reverts. A first seen time
  prefixed with "<=" means the new KSK was already present when the
  program started, so the actual changeover happened at or before it.

  With -o FILE, every observation (one per target per round) is also
  appended to FILE as a JSON object per line, for later analysis.

  The new KSK keytag defaults to 38696 (the root KSK that took over
  from 20326 on 2026-10-11), and can be changed with -k for future
  rollovers.

"""

import os
import sys
import getopt
import json
import time
import concurrent.futures
import dns.resolver
import dns.query
import dns.message
import dns.flags
import dns.edns
import dns.rdatatype
import dns.rcode
import dns.exception


PROGNAME = os.path.basename(sys.argv[0])
VERSION = "0.0.1"

INTERVAL = 60
TIMEOUT = 3
RETRIES = 2
EDNS_UDP_ADV = 1232

OLD_KEYTAG = 20326
NEW_KEYTAG = 38696

IP_RRTYPES = [dns.rdatatype.AAAA, dns.rdatatype.A]
OBSFILE = None
ONESHOT = False


def usage(msg=None):
    """Print usage string and terminate program."""

    if msg:
        print(msg)

    print("""\
{0} version {1}
Usage: {0} [Options]

       Options:
       -h          Print this help string
       -4          Use IPv4 transport only
       -6          Use IPv6 transport only
       -i N        Query interval in seconds (default: {2})
       -k N        Keytag of new KSK (default: {3})
       -o FILE     Append every observation to FILE as JSON lines
       -1          Run one round of queries and exit
""".format(PROGNAME, VERSION, INTERVAL, NEW_KEYTAG)
)
    sys.exit(4)


def process_args(arg_vector):
    """Process command line options and arguments"""

    global IP_RRTYPES, INTERVAL, NEW_KEYTAG, OBSFILE, ONESHOT

    try:
        (options, args) = getopt.getopt(arg_vector, 'h46i:k:o:1')
    except getopt.GetoptError as exc_info:
        usage("{}".format(exc_info))

    if args:
        usage("No positional arguments expected")

    for (opt, optval) in options:
        if opt == "-h":
            usage()
        elif opt == "-4":
            IP_RRTYPES = [dns.rdatatype.A]
        elif opt == "-6":
            IP_RRTYPES = [dns.rdatatype.AAAA]
        elif opt == "-i":
            INTERVAL = int(optval)
        elif opt == "-k":
            NEW_KEYTAG = int(optval)
        elif opt == "-o":
            OBSFILE = optval
        elif opt == "-1":
            ONESHOT = True


def timestr(epoch):
    """Return UTC timestamp string for given epoch time"""

    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch))


def tagstr(keytags):
    """Return printable string for a tuple of keytags"""

    if keytags is None:
        return "NONE"
    return ",".join(str(x) for x in keytags) or "NOSIG"


def get_targets():
    """Return sorted list of (nsname, ipaddress) for root servers"""

    targets = []
    msg = dns.resolver.resolve('.', dns.rdatatype.NS).response
    for rrset in msg.answer:
        if rrset.rdtype != dns.rdatatype.NS:
            continue
        for rdata in rrset:
            nsname = rdata.target.to_text()
            for rrtype in IP_RRTYPES:
                answer = dns.resolver.resolve(nsname, rrtype,
                                              raise_on_no_answer=False)
                if answer.rrset is None:
                    continue
                for ip in answer.rrset:
                    targets.append((nsname, ip.address))
    return sorted(targets)


def send_query(msg, ipaddress):
    """Send DNS query over UDP with retries, falling back to TCP"""

    res = None
    for _ in range(RETRIES):
        try:
            res = dns.query.udp(msg, ipaddress, timeout=TIMEOUT)
            break
        except dns.exception.Timeout:
            continue
    if res is None:
        raise dns.exception.Timeout()
    if res.flags & dns.flags.TC:
        res = dns.query.tcp(msg, ipaddress, timeout=TIMEOUT)
    return res


def query_dnskey(target):
    """
    Query root DNSKEY at given target. Return dictionary describing
    the observation: rcode, NSID, and keytags/inception/expiration of
    the RRSIG(s) covering the DNSKEY RRset.
    """

    nsname, ipaddress = target
    obs = {'name': nsname, 'ip': ipaddress, 'timestamp': time.time()}

    msg = dns.message.make_query('.', dns.rdatatype.DNSKEY,
                                 want_dnssec=True, use_edns=0,
                                 payload=EDNS_UDP_ADV,
                                 options=[dns.edns.GenericOption(
                                     dns.edns.NSID, b'')])
    msg.flags &= ~dns.flags.RD

    try:
        res = send_query(msg, ipaddress)
    except dns.exception.Timeout:
        obs['error'] = "timeout"
        return obs
    except (dns.exception.DNSException, OSError) as exc_info:
        obs['error'] = "{}: {}".format(type(exc_info).__name__, exc_info)
        return obs

    obs['rcode'] = dns.rcode.to_text(res.rcode())
    for option in res.options:
        if option.otype == dns.edns.NSID:
            data = getattr(option, 'nsid', None) or \
                getattr(option, 'data', b'')
            obs['nsid'] = data.decode(errors='replace')

    sigs = []
    for rrset in res.answer:
        if rrset.rdtype == dns.rdatatype.RRSIG and \
           rrset.covers == dns.rdatatype.DNSKEY:
            sigs.extend(rrset)
    sigs.sort(key=lambda x: x.key_tag)
    obs['keytags'] = [x.key_tag for x in sigs]
    obs['inception'] = [timestr(x.inception) for x in sigs]
    obs['expiration'] = [timestr(x.expiration) for x in sigs]
    return obs


class TargetState:
    """Tracked state of one root server address"""

    def __init__(self):
        self.keytags = None
        self.first_new = None
        self.new_at_start = False
        self.reverts = 0


def process_observation(obs, state):
    """Update target state with observation, printing any change"""

    ts = timestr(obs['timestamp'])
    desc = "{} {} [{}]".format(obs['name'], obs['ip'], obs.get('nsid', ''))

    if 'error' in obs:
        print("{} ERROR  {} {}".format(ts, desc, obs['error']))
        return
    if obs['rcode'] != 'NOERROR':
        print("{} ERROR  {} rcode {}".format(ts, desc, obs['rcode']))
        return

    keytags = tuple(obs['keytags'])
    if keytags == state.keytags:
        return

    has_new = NEW_KEYTAG in keytags
    if state.keytags is None:
        event = "INIT  "
        state.new_at_start = has_new
    elif has_new and state.first_new is None:
        event = "NEWKSK"
    elif NEW_KEYTAG in state.keytags and not has_new:
        event = "REVERT"
        state.reverts += 1
    else:
        event = "CHANGE"
    if has_new and state.first_new is None:
        state.first_new = obs['timestamp']

    print("{} {} {} {} -> {} (inception {})".format(
        ts, event, desc, tagstr(state.keytags), tagstr(keytags),
        ",".join(obs['inception'])))
    state.keytags = keytags


def print_summary(targets, states):
    """Print summary table of all targets"""

    print("\nSummary (new KSK {}):".format(NEW_KEYTAG))
    print("(\"<=\" means the new KSK was already present at program start)")
    print("{:<22} {:<26} {:<12} {:<23} {}".format(
        "Server", "Address", "Keytags", "First seen new KSK", "Reverts"))
    for target in targets:
        state = states[target]
        first_new = timestr(state.first_new) if state.first_new else "-"
        if state.new_at_start:
            first_new = "<=" + first_new
        print("{:<22} {:<26} {:<12} {:<23} {}".format(
            target[0], target[1], tagstr(state.keytags),
            first_new, state.reverts))


def run_round(executor, targets, states, obsfile, roundnum):
    """Query all targets once, and process the results"""

    observations = list(executor.map(query_dnskey, targets))
    for obs in observations:
        process_observation(obs, states[(obs['name'], obs['ip'])])
        if obsfile:
            obsfile.write(json.dumps(obs) + "\n")
    if obsfile:
        obsfile.flush()

    count_new = sum(1 for x in states.values()
                    if x.keytags and NEW_KEYTAG in x.keytags)
    count_err = sum(1 for x in observations
                    if 'error' in x or x['rcode'] != 'NOERROR')
    print("{} ROUND {}: {}/{} signed by {} (errors: {})".format(
        timestr(time.time()), roundnum, count_new, len(targets),
        NEW_KEYTAG, count_err))
    sys.stdout.flush()


def main():
    """main function"""

    targets = get_targets()
    states = {x: TargetState() for x in targets}
    obsfile = open(OBSFILE, 'a') if OBSFILE else None

    print("Monitoring {} root server addresses every {}s for new KSK {}".format(
        len(targets), INTERVAL, NEW_KEYTAG))

    roundnum = 0
    try:
        with concurrent.futures.ThreadPoolExecutor(
                max_workers=len(targets)) as executor:
            next_time = time.time()
            while True:
                roundnum += 1
                run_round(executor, targets, states, obsfile, roundnum)
                if ONESHOT:
                    break
                next_time += INTERVAL
                time.sleep(max(0, next_time - time.time()))
    except KeyboardInterrupt:
        pass
    finally:
        if obsfile:
            obsfile.close()
        print_summary(targets, states)


if __name__ == '__main__':

    process_args(sys.argv[1:])
    main()
