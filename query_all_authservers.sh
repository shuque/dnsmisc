#!/bin/sh
#

RESOLVER=8.8.8.8             # For resolving current nameserver set
DIGOPTS="+norecurse +time=2 +retry=2"

progname=`basename $0`

usage() {
    cat <<EOF
Usage: $progname [Options] <zone> <record> <type>

       <zone> :   name of the zone (force.com, my.salesforce.com etc)
       <record> : DNS record name (e.g. ap6.force.com)
       <type> :   DNS record type (e.g. A, CNAME, etc)

	Options:
	-4: Only query IPv4 addresses
	-6: Only query IPv6 addresses

e.g.
       $progname my.salesforce.com ap6.my.salesforce.com CNAME

Queries the DNS record and type at all authoritative DNS servers for the
specified zone.

EOF
    exit 1
}

if [ "$1" = "-4" -o "$1" = "-6" ]; then
    TRANSPORT="$1"
    shift
fi

if [ $# -ne 3 ]; then
    usage
fi

ZONE=$1
RECORD=$2
RRTYPE=$3

dig @$RESOLVER $ZONE NS +short | while read nsname
do
    if [ "$TRANSPORT" != "-6" ]; then
	ip4list=`dig +short $nsname A`
    fi
    if [ "$TRANSPORT" != "-4" ]; then
	ip6list=`dig +short $nsname AAAA`
    fi
    for ip in $ip6list $ip4list
    do
	RESULT=`dig $DIGOPTS @$ip $RECORD $RRTYPE +short | sort | tr '\n' ',' | sed 's:,$::'`
	echo "$RESULT	$nsname $ip"
    done
done
