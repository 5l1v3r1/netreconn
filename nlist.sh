#!/bin/sh
# Script ----------------------------------------------------------------------
# nlist: Thin wrapper for nstrobe -P
#------------------------------------------------------------------------------
# CONFIG: Change to match your install if not default:
NSTROBE_EXEC=/usr/local/bin/nstrobe
NSTROBE_OPTS="-P"
PROG=${0##*/}
TOPPID=$$
HOST=$(hostname 2>/dev/null)

trap "exit 1" 1 2 3 15

#-----------------------------------------------------------------------------
# bomb - Simple death routine; display ERRORMESSAGE, kill TOPPID and exit.
#
# requires: ERRORMESSAGE
# returns : exit 1
#-----------------------------------------------------------------------------
bomb()
{
        cat >&2 <<ERRORMESSAGE

ERROR: $@
*** ${PROG} aborted ***
ERRORMESSAGE
        kill ${TOPPID}      # in case we were invoked from a subshell
        exit 1
}

#-----------------------------------------------------------------------------
# usage - Usage message
#-----------------------------------------------------------------------------
usage()
{
    if [ -n "$*" ]; then
        echo " "
        echo "${PROG}: $*"
    fi
    cat <<_usage_
${PROG} [option]||[address_specification1,address_specification2...]
${PROG} [-u||-usage]
Options:
  -u         Print usage message and exit
Example:
  ${PROG} 192.168.1.10-24,192.168.2.2-254
_usage_
}

#-----------------------------------------------------------------------------
# Main
#-----------------------------------------------------------------------------
if [ ! -x $NSTROBE_EXEC ]; then
	bomb "${NSTROBE_EXEC} not found: make make sure nstrobe is installed"
fi

# Input parsing - the usage explains what each one does
if [ $# -gt 0 -a "$1" = "-u" ];then
    usage
    exit 0
fi
if [ $# -gt 0 -a "$1" = "-usage" ];then
    usage
    exit 0
fi

if [ ! $1 ]; then
	echo "Error: No networks defined"
	usage
	exit 1
fi

netlist=`echo ${@}|sed -e 's/,/ /g'`
for netspec in ${netlist} ; do
	$NSTROBE_EXEC $NSTROBE_OPTS $netspec  |grep -vi timeout
done
