#!/usr/bin/env python3
#

"""
Print statistics from a BIND 9.x format zone journal file.

This program processes the output of "named-journalprint -x" on
a BIND journal file, and prints out statistics for number of
serial update transactions and record count and sizes per
transaction.

Lines processed are like:
Transaction: version 2 offset 168601825 size 3914 rrcount 26 start 2013178356 end 2013178357

One way to run this program is the following (bash shell syntax):

    journalinfo.py <(named-journalprint -x zonefile.jnl)

"""


import sys
import re
import numpy as np


REGEXP = r'^Transaction: version (?P<version>\d+) ' \
    r'offset (?P<offset>\d+) size (?P<size>\d+) ' \
    r'rrcount (?P<rrcount>\d+) start (?P<start>\d+) end (?P<end>\d+)$'


def named_subgroup(matchobject, name):
    """Return value from regex named subgroup"""

    return matchobject.groupdict()[name]


def print_stats(name, array):
    """Print statistics"""

    print(f"Stat name: {name}:")
    print("\tmin = {}".format(np.min(array)))
    print("\tmax = {}".format(np.max(array)))
    print("\tmean = {:.1f}".format(np.mean(array)))
    print("\tmedian = {:.1f}".format(np.median(array)))
    print("\tstd = {:.1f}".format(np.std(array)))


if __name__ == '__main__':

    ARGLEN = len(sys.argv)
    if ARGLEN > 2:
        print("Usage: journalinfo [journalfile]")
        sys.exit(1)
    elif ARGLEN == 2:
        INFILE = open(sys.argv[1], 'r')
    else:
        INFILE = sys.stdin

    values_rrcount = []
    values_size = []

    for line in INFILE:
        line = line.rstrip('\n')
        m = re.search(REGEXP, line)
        if m is None:
            continue
        rrcount = int(named_subgroup(m, 'rrcount'))
        size = int(named_subgroup(m, 'size'))
        values_rrcount.append(rrcount)
        values_size.append(size)

    print('\nStats:')
    values_rrcount = np.array(values_rrcount)
    values_size = np.array(values_size)
    print("#Serial Updates: {}".format(values_rrcount.size))
    print_stats("rrcount", values_rrcount)
    print_stats("size", values_size)
