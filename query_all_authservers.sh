#!/bin/sh
#

ZONE=$1
RECORD=$2
RRTYPE=$3

RESOLVER=8.8.8.8             # For resolving current nameserver set

progname=`basename $0`

usage() {
    cat <<EOF
Usage: $progname <zone> <record> <type>

       <zone> :   name of the zone (force.com, my.salesforce.com etc)
       <record> : DNS record name (e.g. ap6.force.com)
       <type> :   DNS record type (e.g. A, CNAME, etc)

e.g.
       $progname my.salesforce.com ap6.my.salesforce.com CNAME

Queries the DNS record and type at all authoritative DNS servers for the
specified zone.

EOF
    exit 1
}


if [ $# -ne 3 ]; then
    usage
fi

dig @$RESOLVER $ZONE NS +short | while read nsname
do
    ip4list=`dig +short $nsname A`
    ip6list=`dig +short $nsname AAAA`
    for ip in $ip6list $ip4list
    do
	RESULT=`dig +norecurse $DIGOPTS @$nsname $RECORD $RRTYPE +short | sort | tr '\n' ',' | sed 's:,$::'`
	echo "$RESULT	$nsname $ip"
    done
done
