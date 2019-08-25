-- Copyright 2008 Steven Barth <steven@midlink.org>
-- Licensed to the public under the Apache License 2.0.

module("luci.controller.aisino.index", package.seeall)

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

	entry({"aisino"}, firstchild())
	entry({"aisino", "router_info"}, call("getDeviceInfo"))
	entry({"aisino", "check_network"}, call("getNetStatus"))
	entry({"aisino", "do_speedTest"}, call("doSpeedTest"))
	entry({"aisino", "scan_wireless_env"}, call("scanWirelessEnv"))

	entry({"aisino", "speedtest"}, template("aisino/speedtest"))
	entry({"aisino", "wifi_env_scan"}, template("aisino/wifimon"))
end

local uci = require "luci.model.uci".cursor()

function getDeviceInfo()
	local fs = require "nixio.fs"
	local ktWifi = require "ktapi.ktWifi"
	local rspData = {}

	rspData["version"]  = uci:get("firmwareinfo", "info", "firmware_version")
	rspData["macaddr"] = uci:get("network", "lan", "macaddr")

	local boradName = fs.readfile("/tmp/sysinfo/board_type")
	rspData["boradName"] = boradName:gsub("\n", ""):upper()

	local cfg2g  = ktWifi.get_wifi_iface_cfg_id("2G")
	if cfg2g then
		rspData["ssid1"] = uci:get("wireless", cfg2g, "ssid")
	end

	local cfg5g  = ktWifi.get_wifi_iface_cfg_id("5G")
	if cfg5g then
		rspData["ssid2"] = uci:get("wireless", cfg5g, "ssid")
	end

	luci.http.write_json(rspData)
end

function getNetStatus()
	local netStatus = luci.util.exec("/usr/sbin/netdoctor check")

	luci.http.prepare_content("application/json")
	luci.http.write(netStatus)
end

function doSpeedTest()
	local M = require "ktapi.ktSpeedTest"

	luci.http.prepare_content("application/json")
	luci.http.write_json(M.speedTest())
end

function scanWirelessEnv()
	local ktWifi = require "ktapi.ktWifi"

	local codeResp = 1
	local arryOutput = {}

	local apList = ktWifi.platform_scan_ap_list()

	local channelArry = {}

	local i, v
	for i = 1, 11 do
		channelArry[i] = {}
		channelArry[i]['count'] = 0
		channelArry[i]['factor'] = 0
		channelArry[i]['channel'] = i
	end

	if apList then
		codeResp = 0
		arryOutput["apList"] = apList

		for i, v in ipairs(apList) do
			local n = tonumber(v.channel)
			if n <= 11 then
				channelArry[n]["count"] = channelArry[n]["count"] + 1
				channelArry[n]['factor'] = channelArry[n]['factor'] + v.signal + 5

				local near
				for near = -4, 4, 1 do
					if channelArry[n + near] then
						channelArry[n + near]['factor'] = channelArry[n + near]['factor'] + (5 - math.abs(near)) * v.signal
					end
				end
			end
		end
	end

	local function comps(a,b)
		return a.factor < b.factor
	end
	table.sort(channelArry, comps)

	arryOutput["code"] = codeResp
	arryOutput["chEnv"] = channelArry

	luci.http.prepare_content("application/json")
	luci.http.write_json(arryOutput, true)
end