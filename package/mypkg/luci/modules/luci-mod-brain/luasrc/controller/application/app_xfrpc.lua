module("luci.controller.application.app_xfrpc", package.seeall)

function index()
		entry({"admin", "application", "xfrpc"}, template("application/app_xfrpc"), _("内网映射"), 36).index = true
		entry({"admin", "application", "xfrpc", "getServices"}, call("getServicesStatus"))
		entry({"admin", "application", "xfrpc", "addWebProxy"}, call("addWebProxy"))
		entry({"admin", "application", "xfrpc", "delWebProxy"}, call("delWebProxy"))
		entry({"admin", "application", "xfrpc", "setServer"}, call("setServer"))
		entry({"admin", "application", "xfrpc", "getRemotePort"}, call("getRemotePort"))
end

local uci  = require "luci.model.uci".cursor()

function getRemotePort()
	local deviceRunID = luci.http.formvalue("run_id")
	local proxyProto = luci.http.formvalue("proto")
	local serverAddr = uci:get("xfrpc", "common", "server_addr")
	local serverDashboardPort = tonumber(uci:get("xfrpc", "common", "server_port")) + 1

	local requestURL = "http://" .. serverAddr .. ":" .. serverDashboardPort .. "/api/port/tcp/"
	local requestURI = requestURL .. (proxyProto == "tcp" and "getport/" or "getftpport/") .. deviceRunID

	local httpClient = require "ktapi.httpClient"

	luci.http.write(httpClient.request_to_buffer(requestURI, nil))
end

function getServicesStatus()
	local rspData = {}
	local config = {}

	uci:foreach("xfrpc", "proxy",
		function(s)
			local t = {}
			t.sname = s[".name"]
			t.name = s.name
			t.type = s.type
			t.local_ip = s.local_ip
			t.local_port = s.local_port
			t.custom_domains = s.custom_domains

			table.insert(config, t)
		end
	)

	rspData["config"] = config
	rspData["server"] = uci:get_all("xfrpc", "common")
	rspData["runid"] = luci.util.exec("/usr/bin/xfrpc_op -r"):gsub("\n", "")

	luci.http.prepare_content("application/json")
	luci.http.write_json(rspData)
end

function delWebProxy()
	local rspData = {}
	local codeResp = 1

	local name = luci.http.formvalue("name")

	if _deleteWebProxy(name) then 
		codeResp = 0
		uci:commit("xfrpc")
	end

	rspData["code"] = codeResp

	luci.util.exec("/etc/init.d/xfrpc restart")
	luci.http.prepare_content("application/json")
	luci.http.write_json(rspData)
end

function addWebProxy()
	local rspData = {}
	local codeResp = 0

	local proxyType		= luci.http.formvalue("type")
	local localIP		= luci.http.formvalue("ip")
	local localPort		= luci.http.formvalue("port")
	local customDomains	= luci.http.formvalue("domain")
	local name = os.time()

	local codeResp = _addWebProxy(name, proxyType, localIP, localPort, customDomains)

	rspData["code"] = codeResp
	rspData["sname"] = name

	if codeResp == 0 then
		luci.util.exec("/etc/init.d/xfrpc restart")
	end

	luci.http.prepare_content("application/json")
	luci.http.write_json(rspData)
end

function setServer()
	local rspData = {}
	local codeResp = 1
	local addr = luci.http.formvalue("addr")
	local port = luci.http.formvalue("port")

	if addr and port then
		uci:set("xfrpc", "common", "server_addr" , addr)
		uci:set("xfrpc", "common", "server_port" , port)
		uci:commit("xfrpc")

		codeResp = 0
		luci.util.exec("/etc/init.d/xfrpc restart")
	end

	rspData["code"] = codeResp
	luci.http.prepare_content("application/json")
	luci.http.write_json(rspData)
end

function _proxyConflictCheck(t, domain)
	local result = nil
	uci:foreach("xfrpc", "proxy",
		function(s)
			if not t:match("http") and s.type == t then
				result = s[".name"]
			elseif s.type == t and s.custom_domains == domain then
				result = s[".name"]
			end
		end
	)
	return result
end

function _deleteWebProxy(name)
	local result = false

	uci:foreach("xfrpc", "proxy",
		function(s)
			if s.name == name then
				uci:delete("xfrpc", s[".name"])
				result = true
			end
		end)

	return result
end


function _addWebProxy(name, tp, ip, port, domain)
	if _proxyConflictCheck(tp, domain) ~= nil then
		return 2
	end

	local options = {
		["name"]		= name or "",
		["type"]		= tp,
		["local_ip"]	= ip,
		["local_port"]	= port,
		["custom_domains"] = domain,
	}

	uci:section("xfrpc", "proxy", nil, options)
	uci:commit("xfrpc")
	return 0
end