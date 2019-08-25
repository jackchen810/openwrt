#!/usr/bin/lua

function usage()
	print("Usage: " ..arg[0].. " <del|add> <section> [section-arguments, ...]")
	print("section:")
	print("\tglobal <upRate> <downRate>")
	print("\tip <ipaddr> <upRate> <downRate>")
	print("\tvip <macaddr>")
	print("\tblack <macaddr>")
end

if #arg < 2 and (arg[1] ~= "del" or arg[1] ~= "add") then
	usage()
end

QOSCONFIG = "apfreeqos"

local uci  = require "luci.model.uci".cursor()
local util  = require "luci.util" 

function _getIpRuleSection(addr)
	local z
	uci:foreach(QOSCONFIG, "ip_rule",
		function(s)
			if addr and uci:get(QOSCONFIG, s['.name'], "ip") == addr then
				z = s['.name']
			end
		end)
	return z
end

function _addNewIpRule(addr, upRate, downRate)
	
	if upRate == "0" and downRate == "0" then
		return false
	end
	
	local z = uci:section(QOSCONFIG, "ip_rule", nil, {
		ip		= addr,
		up		= upRate,
		down	= downRate
	})
	
	return z
end

function _setListConfig(s, h, d)
	local r = 1
	
	uci:section(QOSCONFIG, s .. "_rule", s, nil)
	
	local l = uci:get_list(QOSCONFIG, s, "mac")
	for i, v in ipairs(l) do
		if v == d then
			table.remove(l, i)
		end
	end
	
	if h == "add" then
		table.insert(l, d)
	end
	
	if uci:set_list(QOSCONFIG, s, "mac", l) then	
		r = 0
	end	
	
	uci:commit(QOSCONFIG)
	
	return r
end

function _getClientLimitData(addr)
	local u = 0
	local d = 0
	
	local s = _getIpRuleSection(addr)
	if s then
		u = uci:get(QOSCONFIG, s, "up")
		d = uci:get(QOSCONFIG, s, "down")
	end
	
	return u, d
end

local option = arg[1] -- add or del
local section = arg[2] -- global, iprule, vip, black
local rspData = 1

if (section == "global") then
	
	if option == "del" then		
		-- uci:delete("apfreeqos", "global")
		uci:section(QOSCONFIG, "global_rule", "global", nil)
		uci:set(QOSCONFIG, "global", "enable", "0")
	elseif #arg < 4 then		
		usage()
		return 1
	else
		local upRate	= arg[3]
		local downRate	= arg[4]
		
		uci:section(QOSCONFIG, "global_rule", "global", nil)

		uci:set(QOSCONFIG, "global", "up", upRate)
		uci:set(QOSCONFIG, "global", "down", downRate)	
		uci:set(QOSCONFIG, "global", "enable", "1")		
	end

elseif (section == "iprule") then
	
	local upRate	= "0"
	local downRate	= "0"
	
	if (option == "add" and #arg < 5) or (option == "del" and #arg < 3) then
		usage()
		return 1
	end
	
	local ipaddr 		= arg[3]
	
	if option == "add" then
		upRate		= arg[4]
		downRate	= arg[5]
	end
	
	local sname = _getIpRuleSection(ipaddr)
	if sname then
		if option == "add" then
			uci:set(QOSCONFIG, sname, "up", upRate)
			uci:set(QOSCONFIG, sname, "down", downRate)
		end
		
		if option == "del" or (upRate == "0" and downRate == "0") then
			uci:delete(QOSCONFIG, sname)
		end
	else
		if option == "add" then
			_addNewIpRule(ipaddr, upRate, downRate)
		else
			print("cannot delete: no this ip rule.")
			return 1
		end
	end
	
elseif section == "vip" or section == "black" then
	if not arg[3] then 
		usage()
		return 1
	end
	
	local macaddr = arg[3]
	_setListConfig(section, option, macaddr)	
else
	return
end

uci:commit(QOSCONFIG)
util.exec("/usr/sbin/service-reload apfreeqos")
