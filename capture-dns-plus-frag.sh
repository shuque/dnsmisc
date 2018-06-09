#!/bin/sh
#
# Small script that uses tcpdump to capture DNS packets continuously
# to a set of output files. It captures both UDP and TCP packets. And
# also non-initial UDP fragments for large DNS messages that resulted
# in IP fragmentation.
#
# Limitations: tcpdump (as far as I can tell) can't do stateful packet
# capture, so we can't surgically capture only subsequent fragments of a DNS
# message. So we just capture all non-initial fragments. This is potentially
# more than we need, but will include all DNS fragments.
# 
# For IPv4 fragments, we examine the 'Fragment Offset' field and capture
# anything with a non-zero offset. The following pcap expression is
# used: 'ip[6:2] & 0x1fff != 0'
# 
# For IPv6, we simply capture any packet that has the fragment header in
# the next header field. This is imprecise, because it's possible that the
# fragment header is not the first of the extension headers in an IPv6
# packet. But it usually is. Precisely capturing fragment headers in possibly
# arbitrary positions in an extension header chain probably requires a more
# sophisticated tool than tcpdump. The following pcap expression is used:
# 'ip6[6] == 44'
#
# So the complete pcap expression is the following:
#     port 53 or \('ip[6:2] & 0x1fff != 0'\) or \('ip6[6] == 44'\)
#
#   Reference: IPv4 Header:
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |Version|  IHL  |Type of Service|          Total Length         |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |         Identification        |Flags|      Fragment Offset    |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |  Time to Live |    Protocol   |         Header Checksum       |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                       Source Address                          |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                    Destination Address                        |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                    Options                    |    Padding    |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#
#        Flags: 3 bits
#                bit 0 = reserved; must be 0
#                bit 1 = DF (Don't Fragment, 1 = do not fragment)
#                bit 2 = MF (More Fragments, 1 = there are more)
#        FragmentOffset 13 bits; in units of 8 octets (64 bits), 1st frag = 0
#
# To keep this running in the background indefinitely, run it like:
# 
#      sudo nohup capture-dns-plus-frag.sh /usr/local/bind/capture/log.pcap &
#
# Author: Shumon Huque
#

USERNAME=named                               # user to drop privileges to
SNAPLEN=0                                    # capture size (0 = full packet)
NUMFILES=5                                   # -W: max number of files
FILESIZE=100                                 # -C: max filesize in MB

OUTPUT=${1:-"out.pcap"}
echo Capturing packets to file: $OUTPUT

exec tcpdump -s $SNAPLEN -Z $USERNAME -w $OUTPUT -W $NUMFILES -C $FILESIZE \
     port 53 or \('ip[6:2] & 0x1fff != 0'\) or \('ip6[6] == 44'\)
