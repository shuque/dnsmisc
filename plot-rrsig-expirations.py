#!/usr/bin/env python3
#

"""
Reads a DNS zone in textual presentation format from standard input,
inspects all the RRSIG records and plots their expiration times.

The input zone must present 1 DNS RR per line (RRs can't be broken
up across multiple lines with continuation line syntax). This input
can be generated easily via 'dig' for example, e.g.:

  dig @<ip> +nocmd +nostats +onesoa <zone> AXFR

And you can pipe that input to the program directly:

  dig @<ip> +nocmd +nostats +onesoa <zone> AXFR | plot-rrsig-expirations.py

"""

import os, sys, getopt, math
from datetime import datetime, timedelta
from collections import defaultdict, OrderedDict
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

PROGNAME = os.path.basename(sys.argv[0])
SIG_TIMESTAMP_FORMAT = "%Y%m%d%H%M%S"
DEFAULT_OUTFILE = "out.png"
DEFAULT_TITLE = "RRSIG Expiration Times Distribution"


# Options with initialized defaults
class Opts:
    plot_type = "line"                     # "line" or "histo"
    verbose = False
    outfile = DEFAULT_OUTFILE
    title = DEFAULT_TITLE


def usage(msg=None):
    if msg:
        print("{}\n".format(msg))
    print("""\
Usage: {0} [Options] [<outfile>]

       Options:
       --help           Print this help message and exit
       --line           Create a line plot (this is the default)
       --histo          Create a histogram plot
       --out=<file>     Output file (default is {1})
       --title=<title>  Use specified title above the graph

Reads a presentation format DNS zonefile from standard input, one RR per
line, and then produces a plot of signature expiration times (in days),
writing the output to a file.

Input suitable for this program can be generated with dig, e.g.
dig @<ip> +nocmd +nostats +onesoa <zone> AXFR | {0}
""".format(PROGNAME, DEFAULT_OUTFILE))
    sys.exit(1)


def process_args(arguments):
    """Process command line arguments"""
    global verbose

    longopts = [
        "help",
        "line",
        "histo",
        "out=",
        "title=",
    ]
    try:
        (options, args) = getopt.getopt(arguments, "", longopts=longopts)
    except getopt.GetoptError as e:
        usage(e)

    for (opt, optval) in options:
        if opt == "--help":
            usage()
        elif opt == "--line":
            Opts.plot_type = "line"
        elif opt == "--histo":
            Opts.plot_type = "histo"
        elif opt == "--out":
            Opts.outfile = optval
        elif opt == "--title":
            Opts.title = optval

    if args:
        usage("Error: too many arguments")
    else:
        return


def getDaysLeft(rrsigExpire):
    e = datetime.strptime(rrsigExpire, SIG_TIMESTAMP_FORMAT)
    days_left = (e - datetime.now()).total_seconds() / 86400.0
    return math.floor(days_left + 0.5)


def getExpirationDict():
    counts = defaultdict(int)
    for line in sys.stdin:
        parts = line.split()
        if parts[3] == 'RRSIG':
            days_left = getDaysLeft(parts[8])
            counts[days_left] += 1
    orderedCounts = OrderedDict(sorted(counts.items()))
    return orderedCounts


def getExpirationCounts():
    expirations = []
    for line in sys.stdin:
        parts = line.split()
        if parts[3] == 'RRSIG':
            days_left = getDaysLeft(parts[8])
            expirations.append(days_left)
    return expirations


def plotLine(data, outfile):
    if not data:
        raise ValueError("No input data to process")
    max_value = max(data.keys())
    max_count = max(data.values())
    plt.axis([0, max_value*1.10, 0, max_count*1.10])
    plt.title(Opts.title)
    plt.xlabel('RRSIG Expiration Times (days)')
    plt.ylabel('RRSIG Counts')
    try:
        plt.plot(data.keys(), data.values())
    except TypeError:
        plt.plot(np.fromiter(data.keys(), dtype=float),
                 np.fromiter(data.values(), dtype=float))
    plt.savefig(outfile, dpi=150)
    print("Plot output saved in {}".format(outfile))


def plotHistogram(data, outfile):
    if not data:
        raise ValueError("No input data to process")
    MINVAL = 0
    MAXVAL = max(expirations) + 1
    BINSIZE = 1
    plt.hist(data, bins=np.arange(MINVAL, MAXVAL+BINSIZE, BINSIZE))
    plt.title(Opts.title)
    plt.xlabel('RRSIG Expiration Times (days)')
    plt.ylabel('RRSIG Counts')
    plt.xticks(range(0, MAXVAL+BINSIZE, 5))
    plt.savefig(outfile, dpi=150)
    print("Plot output saved in {}".format(outfile))

    
if __name__ == '__main__':

    process_args(sys.argv[1:])

    if Opts.plot_type == 'line':
        expirations = getExpirationDict()
        plotLine(expirations, Opts.outfile)
    elif Opts.plot_type == 'histo':
        expirations = getExpirationCounts()
        plotHistogram(expirations, Opts.outfile)
