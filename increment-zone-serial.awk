#!/bin/awk -f
#
# Takes as input, a zonefile in DNS master zonefile format, with no
# macros or continuation lines, and increments only the SOA record's
# serial number by 1.
#

/^[^;]/ && $4 == "SOA" {print $1,$2,$3,$4,$5,$6,$7+1,$8,$9,$10,$11}
/^;/ || $4 != "SOA"
