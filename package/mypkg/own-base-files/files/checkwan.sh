#!/bin/sh

. /usr/share/libubox/jshn.sh

INTERFACE="wan"
WANTYPE=$(uci get network.wan.proto)
WANADDR=""

LOGFILE="/var/log/checkwan.log"

echo -e "\n$(date) Run wan interface check. " >$LOGFILE

log_append() {
	local value="$1"

	echo "$(date "+%T") ${value#--}" >> $LOGFILE
}

wan_status() {

	ubus -S list "network.interface.$INTERFACE" >/dev/null || {
			log_append "Interface $INTERFACE not found" 
			exit 1
	}
	
	local status_info=$(ubus call network.interface status "{ \"interface\" : \"$INTERFACE\" }")
	
	json_load "$status_info"
	json_get_var var1 uptime
	json_get_var var2 proto
	
	json_select "ipv4-address"
	json_select "1"
	json_get_var var3 "address"
	
	WANADDR=$var3
	
	log_append "Uptime:$var1" 
	log_append "Proto :$var2" 
	log_append "Ipaddr:$var3" 
}

check_gateway() {
	local gateway=$(/sbin/route | awk '/default/ {print $2}')
	
	[ -z  "$gateway" ] && log_append "There is no gateway."
	
	[ -z "$WANADDR" ] || {
		log_append "Has gateway. Go ping it"
		
		ping $gateway -c 1 -W 2 &>/dev/null		
		if [ $? -eq 0 ]; then
			log_append "Gateway $gateway pingable, Need try to reconnect "
			break
		fi
	}
	
	log_append "Something is wrong with WAN (Gateway unreachable). reload wan interface"
	
	ifup wan
}

check_net_by_ping() {
	log_append "Proceeding with domain check."
	
	local rv=1
	local domains="www.z.cn www.bing.com www.baidu.com www.taobao.com www.qq.com"
	local ipaddrs="114.114.114.114 8.8.8.8"
	
	for d in $domains; do
		log_append "Pinging $d to to check for internet connection."
		
		ping $d -c 1 -W 2 &>/dev/null		
		if [ $? -eq 0 ]; then
			rv=0
			break
		fi		
	done
	
	if [ "$rv" -eq 1 ]; then
		log_append "Proceeding with ip check."
		
		for d in $ipaddrs; do
			log_append "Pinging $d to check for internet connection."
			
			ping $d -c 1 -W 2 &>/dev/null			
			if [ $? -eq 0 ]; then
				log_append "$d pingable, Dns resolution error, Go reload dnsmasq"
				/etc/init.d/dnsmasq restart
				break
			fi
		done
	fi
	
	return $rv
}

check_net_by_nslookup() {
	local rv=1
	local dnsserver=""
	local server=""
	
	log_append "Get DNS server in resolv.conf to check name resolution"
	
	dnsserver=$(awk  '{if ($1== "nameserver") print $2}' /tmp/resolv.conf.auto)
	if [ -z "$dnsserver" ]; then
		log_append "/tmp/resolv.conf.auto not exist, reload dnsmasq"
		/etc/init.d/dnsmasq restart
		return $rv
	else
		for  server in $dnsserver; do
			nslookup www.baidu.com $server 2>/dev/null
			rv=$?
			if [ $rv -eq 0 ]; then
				break
			fi
		done
	fi
	
	if [ "$rv" -eq 1 ]; then
		nslookup www.baidu.com 114.114.114.114 2>/dev/null
		if [ $? -eq 0 ]; then
			echo nameserver 114.114.114.114 >>/tmp/resolv.conf.auto
			log_append "Dns server error, Add  114.114.114.114 to /tmp/resolv.conf.auto"
			rv=0
		fi
	fi
	
	return $rv
}

#Check wan status
wan_status

if [ "$WANTYPE" == "dhcp" ]; then

	#Check internet
	check_net_by_ping && exit 0
	log_append "Could not establish internet connection. (no packets received)."

	#Check dnsmasq
	check_net_by_nslookup && exit 0	
	log_append "Could not establish internet connection to DNS. Something may be wrong here." 
		
	#Pinging gateway to check for LAN connectivity
	check_gateway 
fi
exit 0
