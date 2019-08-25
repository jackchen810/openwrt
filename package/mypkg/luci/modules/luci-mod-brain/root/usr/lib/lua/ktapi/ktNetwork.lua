-- kunteng network api

module ("ktapi.ktNetwork", package.seeall)

function getLanInfo()
	local ntm = require("luci.model.network").init()
	local rv = {}

	local net = ntm:get_network("lan")
	if net then
		local device = net and net:get_interface()

		if device and table.getn(device:ipaddrs()) > 0 then
			for _, a in ipairs(device:ipaddrs()) do
				rv["ipaddr"] = a:host():string()
				rv["netmask"] = a:mask():string()
			end

			if device:mac()~="00:00:00:00:00:00" then
				rv["macaddr"] = device:mac()
			end

			rv["is_up"] = device:is_up()
		end

		rv["uptime"] = net:uptime()
		rv["proto"] = net:proto()
	end

	return rv
end

function getWanInfo()
	local ntm = require("luci.model.network").init()
	local ubus = require "ubus".connect()
	local uci = require "luci.model.uci".cursor()

	local rv = {}

	local net = ntm:get_network("wan")
	if net then
		local device = net and net:get_interface()

		if device:mac()~="00:00:00:00:00:00" then
			rv["macaddr"] = device:mac()
		end
	end

    local uwan = ubus:call("network.interface.wan", "status", {})
	if uwan then
		rv["is_up"] = uwan.up
		rv["proto"]	= uwan.proto
	end

	if uci:get("network", "wan", "apclient") == "1" then
		rv["proto"]	= "relay"
	end

	local wan = ntm:get_wannet()
	if wan then
		rv["ipaddr"]	= wan:ipaddr()
		rv["netmask"]	= wan:netmask()
		rv["gateway"]	= wan:gwaddr()
		rv["uptime"]	= wan:uptime()
		rv["ifname"]	= wan:ifname()
		rv["dns"]		= wan:dnsaddrs()
	end

	return rv
end

function getSwitchInfo()
	local json = require "ktapi.ktJson"
	local fs   = require "nixio.fs"
	local util   = require "luci.util"

	local stateByHotplugEvent = "/tmp/state/switch"

	if fs.stat(stateByHotplugEvent) then
		return json.Decode(fs.readfile(stateByHotplugEvent))
	else
		return json.Decode(util.exec("netdoctor get port")) or ""
	end
end

function getMacByIP(ipaddr)
	local sys = require ("luci.sys")
	local mac = nil 
	sys.net.arptable(function(e)
		if e["IP address"] == ipaddr then
			mac = e["HW address"]
		end 
	end)

	return mac 
end