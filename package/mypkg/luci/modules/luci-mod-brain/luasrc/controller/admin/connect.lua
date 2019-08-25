-- Copyright 2016 kunteng.org zhangzf@kunteng.org

module("luci.controller.admin.connect", package.seeall)

function index()

	entry({"admin", "connect"}, firstchild(), _("Connect"), 10)
	entry({"admin", "connect", "connect_list"},  template("connect/connect"), _("Connect"), 10).index = true
	entry({"admin", "connect", "disabledev"},  template("connect/disabledev"), _("Disabledev"), 20).index = true
	entry({"admin", "connect", "limiting"},  template("connect/limiting"), _("Limiting"), 30).index = true
	entry({"admin", "connect", "getAllClientList"},  call("getAllClientList"))

	-- 白名单操作
	entry({"admin", "connect", "setVipList"},  call("setVipList"))

	-- 黑名单操作
	entry({"admin", "connect", "getBlackList"},  call("getBlackList"))
	entry({"admin", "connect", "addToBlackList"},  call("addToBlackList"))
	entry({"admin", "connect", "delFromBlackList"},  call("delFromBlackList"))

	-- qos设置
	entry({"admin", "connect", "getQosStatus"}, call("getQosStatus"))
	entry({"admin", "connect", "setQosGlobalRule"}, call("setQosGlobalRule"))
	entry({"admin", "connect", "setQosIpRule"}, call("setQosIpRule"))

	-- 其他
	entry({"admin", "connect", "speedTest"}, call("doSpeedTest"))
	entry({"admin", "connect", "getSessions"}, call("getSessions"))
	entry({"admin", "connect", "flushSessions"}, call("flushSessions"))
end

local uci  = require "luci.model.uci".cursor()

-- 文件名称
QOSCONFIG = "apfreeqos"

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
		return 0
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

function _clearConntrack(ipaddr)
	return luci.util.exec("/usr/sbin/conntrack -D -s %q" % ipaddr)
end
--------------------------------------Controller Api--------------------------------------------

function getAllClientList()
	local client = require "ktapi.ktClient"

	local respData = client.getClientList()
	local statInfo = client.getTigerIpStat()

	local vipList = uci:get_list(QOSCONFIG, "vip", "mac")
	local blackList = uci:get_list(QOSCONFIG, "black", "mac")

	local blackMacHash = {}
	for _, user in ipairs(blackList) do
		blackMacHash[string.lower(user)] = 1
	end

	local vipMacHash = {}
	for _, user in ipairs(vipList) do
		vipMacHash[string.lower(user)] = 1
	end

	if respData then
		for _, c in ipairs(respData) do
			if statInfo[c["ipaddr"]] ~= nil then
				c["up_rate"] 	= statInfo[c["ipaddr"]].upload_rate
				c["down_rate"] = statInfo[c["ipaddr"]].download_rate
			else
				c["up_rate"] 	= 0
				c["down_rate"] = 0
			end

			c["up_quota"], c["down_quota"] = _getClientLimitData(c["ipaddr"])

			c["is_vip"] = (vipMacHash[c['macaddr']] and 1 or 0)
			c["is_black"] = (blackMacHash[c['macaddr']] and 1 or 0)

			local vendor = luci.util.exec("ktpriv get_mac_vendor "..c['macaddr'])
			c["vendor"] = vendor:gsub("\n", "")

		end
	end

	luci.http.write_json(respData)
end

function setVipList()
	local rspData = {}
	local status = 0

	local macaddr = luci.http.formvalue("mac")
	local ipaddr = luci.http.formvalue("ip")
	local handle = luci.http.formvalue("handle")

	rspData.status = _setListConfig("vip", handle, macaddr)

	luci.util.exec("/usr/sbin/service-reload apfreeqos")
	if handle == "del" then
		_clearConntrack(ipaddr)
	end

	luci.http.prepare_content("application/json")
	luci.http.write_json(rspData)
end

function getBlackList()
	local uci  = require "luci.model.uci".cursor()
	local repData = {}

	local blocakList = uci:get_list(QOSCONFIG, "black", "mac")

	for _, user in ipairs(blocakList) do
		local vendor = luci.util.exec("ktpriv get_mac_vendor "..user)

		table.insert(repData, {
			["macaddr"] = user,
			["vendor"] =  vendor:gsub("\n", "")
		})
	end

	luci.http.prepare_content("application/json")
	luci.http.write_json(repData)
end

function addToBlackList()
	local rspData = {}
	local status = 0

	local macaddr = luci.http.formvalue("mac")
	local ipaddr = luci.http.formvalue("ip")

	rspData.status = _setListConfig("black", "add", macaddr)

	luci.util.exec("/usr/sbin/service-reload apfreeqos")
	_clearConntrack(ipaddr)

	luci.http.prepare_content("application/json")
	luci.http.write_json(rspData)

end

function delFromBlackList()
	local rspData = {}

	local macaddr = luci.http.formvalue("mac")

	rspData.status = _setListConfig("black", "del", macaddr)

	luci.util.exec("/usr/sbin/service-reload apfreeqos")
	luci.http.prepare_content("application/json")
	luci.http.write_json(rspData)

end

function getQosStatus()
	local rspData = {}
	local upRate, downRate, enable

	upRate = uci:get(QOSCONFIG, "global", "up") or 0
	downRate = uci:get(QOSCONFIG, "global", "down") or 0
	enable = uci:get(QOSCONFIG, "global", "enable") or 0

	rspData["upRate"] = upRate
	rspData["downRate"] = downRate
	rspData["enable"] = enable
	rspData["code"] = 0

	luci.http.prepare_content("application/json")
	luci.http.write_json(rspData)
end

function setQosGlobalRule()
	local rspData = {}

	local enable = luci.http.formvalue("enable")

	if enable == "1" then
		-- local lanIpaddr = uci:get("network", "lan", "ipaddr")
		-- local lanNetmask = uci:get("network", "lan", "netmask")
		-- uci:set(QOSCONFIG, "global", "ip", lanIpaddr)
		-- uci:set(QOSCONFIG, "global", "netmask", lanNetmask)

		local upRate = luci.http.formvalue("upSpeed")
		local downRate = luci.http.formvalue("downSpeed")

		uci:section(QOSCONFIG, "global_rule", "global", nil)

		uci:set(QOSCONFIG, "global", "enable", "1")
		uci:set(QOSCONFIG, "global", "up", upRate)
		uci:set(QOSCONFIG, "global", "down", downRate)
	else
		--	uci:delete("apfreeqos", "global")
		uci:set(QOSCONFIG, "global", "enable", "0")
	end

	uci:commit(QOSCONFIG)

	rspData.status = 1

	luci.util.exec("/usr/sbin/service-reload apfreeqos")

	luci.http.prepare_content("application/json")
	luci.http.write_json(rspData)
end

function setQosIpRule()
	local rspData = {}
	local code = 1, z

	local ipaddr = luci.http.formvalue("ip")
	local upRate = luci.http.formvalue("upSpeed")
	local downRate = luci.http.formvalue("downSpeed")

	local s = _getIpRuleSection(ipaddr)
	if s then
		uci:set(QOSCONFIG, s, "up", upRate)
		uci:set(QOSCONFIG, s, "down", downRate)

		if upRate == "0" and downRate == "0" then
			uci:delete(QOSCONFIG, s)
		end
		code = 0
	else
		if _addNewIpRule(ipaddr, upRate, downRate) then 
			code = 0
		end
	end

	uci:commit(QOSCONFIG)

	rspData.code = code

	luci.util.exec("/usr/sbin/service-reload apfreeqos")
	luci.http.prepare_content("application/json")
	luci.http.write_json(rspData)
end

function doSpeedTest()
	local M = require "ktapi.ktSpeedTest"

	luci.http.prepare_content("application/json")
	luci.http.write_json(M.speedTest())
end

function getSessions()
	local rspCode = 1
	local rspData = {}

	local conntrackMax = luci.util.exec("grep nf_conntrack_max /etc/sysctl.conf | cut -d= -f2") or 0
	local sessionNum = luci.util.exec("cat /proc/net/nf_conntrack | wc -l") or 0

	if tonumber(conntrackMax) > 0 then
		rspCode = 0
	end

	rspData["code"] = rspCode
	rspData["max"] = conntrackMax:gsub("\n", "")
	rspData["session"] = sessionNum:gsub("\n", "")
	
	luci.http.prepare_content("application/json")
	luci.http.write_json(rspData)
end

function flushSessions()
	luci.http.write(luci.util.exec("conntrack -F"))
end