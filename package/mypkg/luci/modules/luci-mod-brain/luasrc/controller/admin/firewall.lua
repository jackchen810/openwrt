-- Copyright 2016 kunteng.org zhangzf@kunteng.org

module("luci.controller.admin.firewall", package.seeall)

function index()

	entry({"admin", "firewall"}, firstchild(), _("Firewall"), 60)
	entry({"admin", "firewall", "setPortForward"}, call("setPortForward"))
	entry({"admin", "firewall", "delPortForward"}, call("delPortForward"))

end

local uci  = require "luci.model.uci".cursor()

function delPortForward()
	local rspData = {}
	local codeResp = 1

	local sport = luci.http.formvalue("srcport")

	if _deletePortForward(sport) then 
		codeResp = 0
		uci:commit("firewall")
	end

	rspData["code"] = codeResp

	luci.util.exec("service-reload firewall")
	luci.http.prepare_content("application/json")
	luci.http.write_json(rspData)
end

function setPortForward()
	local rspData = {}
	local codeResp = 1

	local ip = luci.http.formvalue("ip")
	local name = luci.http.formvalue("name")
	local proto = luci.http.formvalue("proto")
	local sport = tonumber(luci.http.formvalue("sport"))
	local dport = tonumber(luci.http.formvalue("dport"))

	local codeResp = _setPortForward(name, ip, sport, dport, proto)

	rspData["code"] = codeResp
	rspData["sname"] = _portConflictCheck(sport)

	luci.util.exec("service-reload firewall")
	luci.http.prepare_content("application/json")
	luci.http.write_json(rspData)
end

-- 修改为按源端口删除. section设置name规则显示太乱. cfgname每次commit后有可能会变
function _deletePortForward(port)
	local result = false

	uci:foreach("firewall", "redirect",
		function(s)
			if s.src_dport == port or s.proto == "all"then
				uci:delete("firewall", s[".name"])
				result = true
			end
		end)

	return result
end

function _portCheck(port)
	if port and type(port) == "number" and port > 0 then
		return true
	else
		return false
	end
end

function _sportOverInConfig(port1, port2)
	local LuciUtil = require("luci.util")

	if port1 and port2 then
		port1 = tostring(port1)
		port2 = tostring(port2)
		if port1 == port2 then
			return true
		end

--[[		 local range1 = {}
		local range2 = {}
		if port1:match("-") then
			local sp = LuciUtil.split(port1, "-")
			range1["f"] = tonumber(sp[1])
			range1["t"] = tonumber(sp[2])
		else
			range1["f"] = tonumber(port1)
			range1["t"] = tonumber(port1)
		end
		if port2:match("-") then
			local sp = LuciUtil.split(port2, "-")
			range2["f"] = tonumber(sp[1])
			range2["t"] = tonumber(sp[2])
		else
			range2["f"] = tonumber(port2)
			range2["t"] = tonumber(port2)
		end
		if (range1.f >= range2.f and range1.f <= range2.t) or
			(range1.t >= range2.f and range1.t <= range2.t) then
			return true
		end]]
	end 

	return false
end

function _portConflictCheck(port)
	local result = nil
	uci:foreach("firewall", "redirect",
		function(s)
			if  _sportOverInConfig(port, s.src_dport) then
				result = s[".name"]
			end
		end
	)
	return result
end

-- return
-- 0: 设置成功
-- 1: 参数不合法
-- 2: 端口冲突(设置的端口和已有端口有重叠)
-- 3: 功能冲突由于DMZ开启
-- 4: 功能冲突无法设置DMZ
function _setPortForward(name, ip, sport, dport, proto)
	if ip and name and proto then
		if proto == "all" and _portForwardInfo() ~= nil then
			return 4
		end

		if _portDMZForwardCheck() ~= nil then
			return 3
		end

		if sport and _portConflictCheck(sport) ~= nil then
			return 2
		end

		local options = {
			["name"]		= name or "",
			["src"]			= "wan",
			["dest"]		= "lan",
			["src_dport"]	= sport, 
			["dest_ip"]		= ip,
			["dest_port"]	= dport,
			["proto"]		= proto,
			["target"]		= "DNAT",
		}

		uci:section("firewall", "redirect", nil, options)
		uci:commit("firewall")
		return 0
	end
	return 1
end

-- status
-- 0:关闭
-- 1:开启
-- 2:冲突(DMZ功能开启，NAT功能就不能开启)
function _portDMZForwardCheck()
	local result = nil

	uci:foreach("firewall", "redirect",
		function(s)
			if s.proto == "all" then
				result = s[".name"]
			end
		end
	)

	return result
end

function _portForwardInfo()
	local result = nil

	uci:foreach("firewall", "redirect",
		function(s)
			if s.proto then
				result = s[".name"]
			end
		end
	)

	return result
end
