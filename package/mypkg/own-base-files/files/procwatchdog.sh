#!/bin/sh
check()
{
	proccnt=`ps|grep $1|grep -v grep|wc -l`;
	return $proccnt;
	
}

watch()
{
	result=`ps|grep $1|grep -v grep|wc -l`

	if [ 1 -ne  $result ]
	then
		eval $2;
	fi
}

watch_dnsmasq() 
{
	dnsmasq_dhcpscript=`uci get dhcp.@dnsmasq[0].dhcpscript  2> /dev/null`
	dnsmasq_pid_num=`pidof dnsmasq|wc -w`
	
	[ ! -z $dnsmasq_dhcpscript ] && {
		[ $dnsmasq_pid_num != 1 ] && /etc/init.d/dnsmasq restart
	}
}

#[ -x /usr/sbin/watch_wifidog ] && /usr/sbin/watch_wifidog
#watch_dnsmasq
#watch wifidog "/etc/init.d/wifidog start"
#watch mosquitto "/etc/init.d/mosquitto start"
#watch mqtt-client "/etc/init.d/mqtt-client start"
#watch rsyslog "/etc/init.d/rsyslog start"
[ -e /etc/rc.d/S97mac-onoffline ] && watch mac-onoffline "/etc/init.d/mac-onoffline start"
[ -e /etc/rc.d/S92quectel-CM ] && watch quectel-CM "/etc/init.d/quectel-CM start"
#[ -e /etc/rc.d/S97loadbalance ] && watch loadbalance "/etc/init.d/loadbalance start"

# gukq commit basicgrab watchdog
# watch basicgrab "/usr/bin/basicgrab start &"
