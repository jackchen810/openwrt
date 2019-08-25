module("luci.controller.application.app_aisino", package.seeall)

function index()
	entry({"admin", "application", "aisino"},  firstchild())
	entry({"admin", "application", "aisino", "get51BoxConfig"}, call("get51BoxConfig"))
	entry({"admin", "application", "aisino", "set51BoxNetwork"}, call("set51BoxNetwork"))
	entry({"admin", "application", "aisino", "setCloudPrinter"}, call("setCloudPrinter"))
end

local uci  = require "luci.model.uci".cursor()

function get51BoxConfig()
	local rspData = {}

	rspData["taxnum"] = uci:get("aisino", "global", "taxnumber")
	rspData["boxnum"] = uci:get("aisino", "global", "boxnumber")
	rspData["cloudprinter"] = uci:get("aisino", "global", "cloudprinter")
	rspData["network"] = uci:get_all("aisino", "network")

	luci.http.prepare_content("application/json")
	luci.http.write_json(rspData)
end

function set51BoxNetwork()
	local rspData = {}
	local proto = ((luci.http.formvalue("proto")or "1") == "1" and "dhcp" or "static")

	uci:set("aisino", "global", "taxnumber", luci.http.formvalue("taxnum")or "")
	uci:set("aisino", "global", "boxnumber", luci.http.formvalue("boxnum")or "")
	uci:set("aisino", "network", "proto", proto)
	uci:set("aisino", "network", "ipaddr", luci.http.formvalue("ipaddr")or "")
	uci:set("aisino", "network", "netmask", luci.http.formvalue("netmask")or "")
	uci:set("aisino", "network", "gateway", luci.http.formvalue("gateway")or "")
	uci:set("aisino", "network", "dns1", luci.http.formvalue("primayDns")or "")
	uci:set("aisino", "network", "dns2", luci.http.formvalue("secondDns")or "")

	uci:commit("aisino")

	rspData["code"] = 0
	luci.http.prepare_content("application/json")
	luci.http.write_json(rspData)
end

function _deletePrinterProxy()
	local result = false

	uci:foreach("xfrpc", "proxy",
		function(s)
			if s.name == "printer" then
				uci:delete("xfrpc", s[".name"])
				result = true
			end
		end)

	return result
end

function setCloudPrinter()
	local rspData = {}
	local codeResp = 0

	local disable = luci.http.formvalue("disabled") or '0'
	local taxNumber = luci.http.formvalue("taxnum")
	local boxNumber = luci.http.formvalue("boxnum")
	local xfrpServer = uci:get("xfrpc", "common", "server_addr")

	if _deletePrinterProxy() then 
		uci:commit("xfrpc")
	end

	if disable == '0' then
		uci:set("aisino", "global", "taxnumber", taxNumber)
		uci:set("aisino", "global", "boxnumber", boxNumber)
		uci:set("aisino", "global", "cloudprinter", 1)
		uci:commit("aisino")

		local cloudPrinterURI = 'zs' .. taxNumber .. boxNumber .. '.' .. xfrpServer

		local options = {
			["name"]		= "printer",
			["type"]		= "http",
			["local_ip"]	= "127.0.0.1",
			["local_port"]	= "80",
			["custom_domains"] = cloudPrinterURI,
		}

		uci:section("xfrpc", "proxy", nil, options)
		uci:commit("xfrpc")
	else
		uci:set("aisino", "global", "cloudprinter", 0)
		uci:commit("aisino")
	end

	luci.util.exec("sleep 1;/etc/init.d/xfrpc restart")
	rspData["code"] = codeResp

	luci.http.prepare_content("application/json")
	luci.http.write_json(rspData)
end