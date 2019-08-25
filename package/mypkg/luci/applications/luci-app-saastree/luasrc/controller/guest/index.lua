-- Copyright 2008 Steven Barth <steven@midlink.org>
-- Licensed to the public under the Apache License 2.0.

module("luci.controller.guest.index", package.seeall)

function index()
	local root = node()
	if not root.target then
		root.target = alias("admin")
		root.index = true
	end

	local page   = node("admin")
	page.target  = firstchild()
	page.title   = _("Administration")
	page.ucidata = true
	page.index = true

	entry({"guest"}, call("querymac"),nil, 1)
	entry({"guest", "mac"}, call("querymac"),nil, 2)
	entry({"guest", "list"}, call("getMacList"),nil, 2)
	entry({"guest", "info"}, call("getDeviceInfo"),nil, 2)
	entry({"guest", "login"}, call("getRouteInfo"),nil, 2)
	entry({"guest", "netStatus"}, call("getNetStatus"),nil, 2)
end

local uci = require "luci.model.uci".cursor()

function querymac()
	require("aeslua")
	local nixio = require "nixio"
	local key = "flzx3qc,1syhl9t."
	local iv = {5,0,7,5,4,2,8,6,3,6,4,9,9,1,5,3}

	local jsoncode, cipher

	local apmac = uci:get("network", "lan", "macaddr")
	local ipaddr = luci.http.getenv("REMOTE_ADDR")
	local macaddr = luci.util.exec("ktpriv get_mac_by_ip " .. ipaddr)
	local ctime = luci.util.exec("date +%s")

	jsoncode = string.format('{"mac":%q,"ip":%q,"routermac":%q,"time":%q}', macaddr:gsub("\n", ""), ipaddr, apmac, ctime:gsub("\n", ""))

	cipher = aeslua.encrypt(key, jsoncode, nil, nil, iv)

	luci.http.header("Access-Control-Allow-Origin", "*")
	luci.http.write(nixio.bin.b64encode(cipher))
end

function getMacList()
	local client = require "ktapi.ktClient"
	luci.http.write_json(client.getClientList())
end

function getDeviceInfo()
	local ktWifi = require "ktapi.ktWifi"
	local fs = require "nixio.fs"

	local version, ssid1, ssid2, boradName, macaddr

	version  = uci:get("firmwareinfo", "info", "firmware_version")
	boradName = fs.readfile("/tmp/sysinfo/board_type")
	macaddr = uci:get("network", "lan", "macaddr")

	if (fs.stat("/etc/config/wireless", "size") or 0) > 0 then
		local cfg2g  = ktWifi.get_wifi_iface_cfg_id("2G")
		ssid1 = uci:get("wireless", cfg2g, "ssid")

		if ktWifi.get_wifi_device_cfg_id("5G") then
			local cfg5g = ktWifi.get_wifi_iface_cfg_id("5G")
			ssid2 = uci:get("wireless", cfg5g, "ssid")
		end
	end

	luci.http.write_json({borad = boradName:gsub("\n", ""):upper(), version = version, SSID2G = ssid1, SSID5G = ssid2, macaddr = macaddr})
end

function getRouteInfo()
	local ktNetwork = require "ktapi.ktNetwork"
	local ktClient	= require "ktapi.ktClient"
	local ktUtil 	= require "ktapi.ktUtil"

	local wanInfo = ktNetwork.getWanInfo()
	local sysinfo = luci.util.ubus("system", "info") or { }

	local dataResp = {
		port		= ktNetwork.getSwitchInfo(),
		runTime		= sysinfo.uptime or 0,
		wanipaddr	= wanInfo.ipaddr or "",
		sessionNum	= ktClient.getClientNum(),
	}

	if (uci:get("apfreeqos", "bandwidth", "download") or 0) == 0 then
		ktUtil.fork_exec("/usr/sbin/speedtest")
	end

	ktUtil.fork_exec("echo -n $(/usr/sbin/netdoctor -c) > /tmp/state/internet")

	luci.http.prepare_content("application/json")
	luci.http.write_json(dataResp)
end

function getNetStatus()
	local netStatus = luci.util.exec("/usr/sbin/netdoctor check")

	luci.http.prepare_content("application/json")
	luci.http.write(netStatus)
end