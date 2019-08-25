#!/bin/sh

BL_IPSET_DOMAIN=/tmp/dnsmasq.d/bl_ipset_domain
BL_LIST=/tmp/bl.list

usage()
{
	echo "$0 add_mac|del_mac mac"
	echo "$0 add_mac_list mac1 mac2 mac3 ...."                                                             
	echo "$0 del_mac_list mac1 mac2 mac3 ...."   
	echo "$0 get_mac_list"
	echo "$0 flush_mac"
	echo "$0 set_domain"
	echo "$0 flush_domain"
	echo "$0 get_domain_list"
	exit 1
}

set_domain()
{
	[ -f "$BL_LIST" ] && {
		[ -f $BL_IPSET_DOMAIN ] && rm -f $BL_IPSET_DOMAIN
		while read -r line
		do
    		name="$line"
    		echo "ipset=/.$name/BLdomain" >> $BL_IPSET_DOMAIN
		done < "$BL_LIST"
		/etc/init.d/dnsmasq restart
	} || {
		[ $# -ge 1 ] && {
			[ -f $BL_IPSET_DOMAIN ] && rm -f $BL_IPSET_DOMAIN
			for name in "$@"; do
    			echo "ipset=/.$name/BLdomain" >> $BL_IPSET_DOMAIN
			done
			/etc/init.d/dnsmasq restart
		} 
	} 
}

get_domain_list()
{
	[ -f "$BL_IPSET_DOMAIN" ] && {
		i=0
		while read -r line
		do
			name=`echo $line|cut -d'/' -f 2|sed 's/^.//'`		
			[ $i = 0 ] && {
				printf $name
				i=1
			} || {
				printf ",%s" $name
			} 	
		done < "$BL_IPSET_DOMAIN"
	} 
}

case "$1" in
	"add_mac")
		ipset add BLmac $2 >/dev/null 2>&1
		;;
	"add_mac_list")
		shift
		for mac in "$@"; do
			ipset add BLmac $mac >/dev/null 2>&1
		done
		;;
	"del_mac")
		ipset del BLmac $2 >/dev/null 2>&1
		;;
	"del_mac_list")                                                                                        
		shift                                                                                          
		for mac in "$@"; do                                                                            
			ipset del BLmac $mac  >/dev/null 2>&1                                                                 
		done                                                                                           
		;;                                                                                             
	"get_mac_list")                                                                                        
		i=0                                                                                            
		for line in `ipset list  BLmac -o save |grep add|cut -d' ' -f 3`; do                           
		[ $i = 0 ] && {                                                                        
				printf $line                                                                   
				i=1                                                                            
		} || {                                                                                 
				printf ",%s" $line                                                             
		}                                                                                      
		done                                                                                           
		;;                 
	"flush_mac")
		ipset flush BLmac
		;;
	"set_domain")
		shift
		set_domain $@
		;;
	"flush_domain")
		[ -f "$BL_IPSET_DOMAIN" ] && {
			rm -f $BL_IPSET_DOMAIN
			ipset flush BLdomain
			/etc/init.d/dnsmasq restart
		}
		;;
	"get_domain_list")
		get_domain_list
		;;
	*)
		echo "command not support, usage:"
		usage
		;;
esac

exit 0
