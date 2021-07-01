#!/bin/bash
FDATE=`date "+%m-%d-%Y.%H%M.%N"`
BLCHAR='-'
BORDER='80'

function do_pf() { 
	MSG="$1"
	printf '%s\n' "$MSG"
}

function do_bl() {
	BCHAR="$1"

	if [[ "$BCHAR" == '' ]];
		then
			BCHAR="$BLCHAR"
		fi

	printf -v borderline '%*s' "$BORDER"
	echo ${borderline// /$BCHAR}

}

function do_masscan() { 
	TARGET="$1"
	TARGETPORT='139,445'
	ETHDEVICE='eno1np0'
	SRCPORT='65444'
	PACKETRATE='9000'
	FULLOUTPUT="$PWD/MASSCAN_FULLOUTPUT.$FDATE.txt"
	LISTOUTPUT="$PWD/MASSCAN_LISTOUTPUT.$FDATE.txt"
	FINALREPORT="$PWD/VULNSCAN_REPORT.$FDATE.txt"
	EXECUTE_CHECK='1'

	if [[ -z "$TARGET" ]]; 
		then
			do_pf "ERROR: PROVIDE TARGET IP ADDRESS OR IP ADDRESS/CIDR"
			exit
		fi

	iptables -A INPUT -p tcp -i "$ETHDEVICE" --dport "$SRCPORT" -j DROP
	
	SCAN=`masscan --adapter="$ETHDEVICE" --adapter-port "$SRCPORT" --rate="$PACKETRATE" --range="$TARGET" --ports="$TARGETPORT" --banners --open-only -oG "$FULLOUTPUT"`
	do_pf "$SCAN"
	FIXOUTPUT=`cat "$FULLOUTPUT"|grep 'Host:'|cut -f2 -d :|cut -f 1 -d \(|sort|uniq|sed -e 's/^[ \t]*//'`

	while read SCANRESULT
		do
			do_pf "$SCANRESULT" >> "$LISTOUTPUT"
		done <<< $(do_pf "$FIXOUTPUT")

	if [[ "$EXECUTE_CHECK" == '1' ]]; 
		then
			do_check_list "$LISTOUTPUT"|tee -a "$FINALREPORT"
		fi

}

function do_find_dc() { 
	INPUTDOMAIN="$1"
	OUTOPT="$2"

	if [[ -z "$INPUTDOMAIN" ]];
		then
			do_pf "ERROR: DOMAIN NAME NEEDED"
			exit
		fi

	case "$OUTOPT" in 
		0)	#RIGHT SIDE ONLY
			ANSWER=`for thing in $( dig -t srv +short _ldap._tcp.$INPUTDOMAIN | awk '{print $NF}' | sort ) ; do printf "%s %s\n" "${thing}" "$( dig +short ${thing} )" ; done|awk '{print $2}'|sort|uniq|sed -e '/^\s*$/d'`
		;;
		
		*)	#LEFT AND RIGHT SIDES
			ANSWER=`for thing in $( dig -t srv +short _ldap._tcp.$INPUTDOMAIN | awk '{print $NF}' | sort ) ; do printf "%s %s\n" "${thing}" "$( dig +short ${thing} )" ; done`
		;;
	esac

	do_pf "$ANSWER"
}

function do_checkpq() { 
	INPUTIP="$1"
	RPCQ=`python3 rpcdump.py "$INPUTIP"|grep 'MS-RPRN'`
	RDNS=`dig +short -x "$INPUTIP"|head -n1|rev|cut -f2- -d\.|rev`
	
	if [[ -z "$RDNS" ]]; 
		then
			DNSRESULT='DNS_NOT_AVAILABLE'
		else
			DNSRESULT="$RDNS"
		fi

	if [[ -z "$RPCQ" ]]; 
		then
			RPCANSWER='RPC_PRINT_SYSTEM_NOT_FOUND'
		else
			RPCANSWER="$RPCQ"
		fi

	do_pf "$INPUTIP|$DNSRESULT|$RPCANSWER"
}

function do_check_dclist() { 
	INPUTDOMAIN="$1"
	HEADOPT='1'

	if [[ -z "$INPUTDOMAIN" ]]; 
		then
			do_pf "ERROR: DOMAIN NAME NEEDED"
			exit
		fi

	GETDCLIST=`do_find_dc "$INPUTDOMAIN" '0'`
	COUNT='1'
	
	do_pqlistheader "$HEADOPT"

	while read "DCLIST" 
		do
			DCRESULT=`do_checkpq "$DCLIST"`
			do_pf "$COUNT|$DCRESULT"
			COUNT=`expr "$COUNT" + '1'`
		done <<< $(do_pf "$GETDCLIST")

	if [[ "$HEADOPT" -ne 'NONE' ]];
		then
			do_bl
		fi
}

function do_check_single() { 
	INPUTHOST="$1"
	HEADOPT='1'
	do_pqlistheader "$HEADOPT"
	CHECKRESULT=`do_checkpq "$INPUTHOST"`
	do_pf "$CHECKRESULT"

	if [[ "$HEADOPT" -ne 'NONE' ]];
		then
			do_bl
		fi
}

function do_check_list() { 
	INPUTLIST="$1"
	HEADOPT='1'

	if [[ -z "$INPUTLIST" ]]; 
		then
			do_pf "ERROR: HOSTLIST NEEDED"
			exit
		fi

	GETTARGETS=`cat "$INPUTLIST"`
	COUNT='1'

	do_pqlistheader "$HEADOPT"

	while read "HOSTLIST"
		do
			HRESULT=`do_checkpq "$HOSTLIST"`
			do_pf "$COUNT|$HRESULT"
			COUNT=`expr "$COUNT" + '1'`
		done <<< $(do_pf "$GETTARGETS")

	if [[ "$HEADOPT" -ne 'NONE' ]]; 
		then
			do_bl
		fi
}

function do_pqlistheader() {
	LHOPT="$1"

	case "$LHOPT" in
		0)	do_pf "IP_ADDRESS|DNS_NAME|RPC_RESULT"
			do_bl	
		;;

		1)	do_pf "#|IP_ADDRESS|DNS_NAME|RPC_RESULT"
			do_bl	
		;;
		NONE);;
	esac
}

do_pqmenu() { 
	ARG1="$1"
	ARG2="$2"
	ARG3="$3"

	if [[ -z "$ARG1" ]]; 
		then
			do_bl "="
			do_pf "[0] - LIST ALL DOMAIN CONTROLLERS"
			do_pf "[1] - CHECK FOR PRINT SERVICE [ALL DOMAIN CONTROLLERS]"
			do_pf "[2] - CHECK SINGLE HOST FOR PRINT SERVICE"
			do_pf "[3] - CHECK LIST FOR PRINT SERVICE"
			do_pf "[4] - PERFORM MASSCAN/CHECK RESULT FOR PRINT SERVICE"
			do_bl "="
			exit
		fi

	case "$ARG1" in 
		0)	do_find_dc "$ARG2" "$ARG3";;
		1)	do_check_dclist "$ARG2";;
		2)	do_check_single "$ARG2";;
		3)	do_check_list "$ARG2";;
		4)	do_masscan "$ARG2";;
		*)	do_pf "ERROR: SELECT OPTION";;
	esac

}

do_pqmenu "$1" "$2" "$3"
