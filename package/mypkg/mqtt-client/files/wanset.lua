#!/usr/bin/lua

--[[ 
	arg[1] : pppoe
	arg[2] : username
	arg[3] : password
	arg[4] : main_dns
	
	arg[1] : static
	arg[2] : ipaddr
	arg[3] : netmask
	arg[4] : gateway
	arg[5] : main_dns
]]--


function cleanwanset(proto)
    local uci  = require "luci.model.uci"   
    local _uci = uci.cursor()   
    _uci:set("network","wan","proto",proto)
    _uci:set("network","wan","username","")
    _uci:set("network","wan","password","")
    _uci:set("network","wan","ipaddr","")
    _uci:set("network","wan","netmask","")
    _uci:set("network","wan","gateway","")
    _uci:set("network","wan","dns","")
    _uci:commit("network")
end

if #arg >= 1 and (arg[1] == "dhcp" or arg[1] == "pppoe" or arg[1] == "static")then

	local uci  = require "luci.model.uci"                                                                                                          
	local util  = require "luci.util"                                                                                                          
	local _uci = uci.cursor() 
	ret = true
	
	if(arg[1] == "pppoe") then
	
		if arg[2] == nil or arg[3] == nil then
			ret = false
		else	
			cleanwanset("pppoe")
			_uci:set("network","wan","username",arg[2]) 
			_uci:set("network","wan","password",arg[3]) 
			
			if arg[4] then
				_uci:set("network","wan","dns",arg[4]) 
			end
			
			_uci:commit("network")
		end
		
	elseif (arg[1] == "dhcp") then
		cleanwanset("dhcp")
		
		if arg[2] or arg[2] ~= nil then
			_uci:set("network","wan","dns",arg[2]) 
		end
		
		_uci:commit("network")
		
	elseif (arg[1] == "static") then
	
		if arg[2] == nil or arg[3] == nil or arg[4] == nil or arg[5] == nil then
			ret = false
		else		
			cleanwanset("static")
			_uci:set("network","wan","ipaddr",arg[2])
			_uci:set("network","wan","netmask",arg[3])
			_uci:set("network","wan","gateway",arg[4])
			_uci:set("network","wan","dns",arg[5])
			_uci:commit("network")
		end
	end
	print(ret and 0 or 1)
	if ret then util.exec("sleep 1;/sbin/luci-reload network;/etc/init.d/dnsmasq restart;kill -USR1 $(pidof udhcpc);/etc/init.d/firewall restart;sleep 1;/etc/init.d/wifidog stop;/etc/init.d/wifidog start") end
else
	print("Usage: "..arg[0].." <proto> [proto-arguments, ...]")
	print("Proto:")
	print("\tdchp\t [dns]")
	print("\tpppoe\t <username> <password> [dns]")
	print("\tstatic\t <ipaddr> <netmask> <gateway> [dns]")
end

