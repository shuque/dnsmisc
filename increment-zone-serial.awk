#!/bin/awk -f
#
# Takes as input, a zonefile in DNS master zonefile format, with no
# continuation lines (comments and $macros are allowed), and increments
# only the SOA record's serial number by 1.
#

/^[^;$]/ && $4 == "SOA" { $7 += 1; print }
/^[;$]/ || $4 != "SOA"
