module ("ktapi.ktWifi", package.seeall)

local uci = require "luci.model.uci".cursor()

function getWifiDevsInfo()
	local ntm = require("luci.model.network").init()
	local rv = { }

	local dev
	for _, dev in ipairs(ntm:get_wifidevs()) do
		local net
		for _, net in ipairs(dev:get_wifinets()) do
			if net:get("mode") == "ap" then
				local rd = {
					device	= dev:name(),
					band	= dev:get("band"),
					channel	= dev:get("channel"),
					txpower	= dev:get("txpower"),
					ssid	= net:get("ssid"),
					is_up	= net:get("disabled"),
					encry	= net:get("encryption"),
					key		= net:get("key"),
					hidden	= net:get("hidden"),
				}
			rv[#rv+1] = rd
			end
		end
	end

	return rv
end

function get_wifi_net(band)
	local ntm = require("luci.model.network").init()
	local rv = { }
	local guest = false

	if band == "guest" then
		band = "2.4G"
		guest = true
	end

	local dev
	for _, dev in ipairs(ntm:get_wifidevs()) do
		local net
		for _, net in ipairs(dev:get_wifinets()) do
			if dev:get("band") ~= band then break end
			rv['device']	= dev:name()
			rv['channel']	= dev:get("channel")
			rv['txpower']	= dev:get("txpower")

			if net:get("mode") == "ap" then
				rv['ifname']	= net:shortname()
				rv['ssid']		= net:get("ssid")
				rv['is_up']		= net:get("disabled")
				rv['encry']		= net:get("encryption")
				rv['key']		= net:get("key")
				rv['hidden']	= net:get("hidden") or 0

				if not guest then break else rv = {} end
				guest = false
			end
		end
	end

	return rv
end

function getCurrentChannel()
	local util = require "luci.util"
	local ifname = "ath0"

	local boardInfo = util.ubus("system", "board") or { }
	local targetBoard = boardInfo.release.target

	if targetBoard:find("ramips") then
		ifname = "ra0"
	end

	if targetBoard:find("ipq") then
		ifname = "ath1"
	end
--[[
	local iw = util.exec("iwlist " .. ifname .. " channel | grep Channel")
	if iw then
		channel = iw:match(".+=(%d+)")
	end

	if not channel then
		iw = util.exec("iwinfo " .. ifname .. " info| grep Channel")
		channel = iw:match(".+: (%d+)")
		if not channel or tonumber(channel) > 13 then
			channel = 0
		end
	end
 ]]
	local channel = util.exec("iwinfo %q info | grep Channel " % ifname):match(".+: (%d+)") or 0

	return channel
end

function getWifiDeviceCfg(band)
	local cfgName = nil

	if band == "2.4G" or band == "5G" then
		uci:foreach("wireless", "wifi-device",
			function(s)
				if s.band == band then
					cfgName = s[".name"]
				end
			end)
	end

	return cfgName
end

function getWifiIfaceCfg(iface)
	local deviceName = nil
	local cfgName = nil
	local guest = false

	if iface == "guest" then
		iface = "2.4G"
		guest = true
	end

	cfgName = getWifiDeviceCfg(iface)
	if cfgName then
		deviceName = uci:get("wireless", cfgName, "type")
	end

	if deviceName then
		uci:foreach("wireless", "wifi-iface",
			function(s)
				if s.device == deviceName and s.mode == "ap" then
					cfgName = s[".name"]

					if not guest then return end

					cfgName = nil
					guest = false
				end
			end)
	end

	return cfgName
end

-- 原 ktuci_api 依赖luci_platform
local function getUciConfigId(config, section_type, option, option_value)
	local ret = nil

	assert(config ~= nil, 1);
	assert(section_type ~= nil, 1);
	assert(option ~= nil, 1);
	assert(option_value ~= nil, 1);

	uci:foreach(config, section_type,
			function(s)
				local s_name = s[".name"]
				local value = uci:get(config, s_name, option)

				if section_type == "wifi-iface" then
					if uci:get(config, s_name, "mode") ~= "ap" then
						return
					end
				end

				if value == option_value then
					ret = s_name
				end
			end
	)

	return ret
end

function get_wifi_device_cfg_id(band)
	if band == "2G" or band == "5G" then
		option = uci:get("luci_platform", "wireless", "device_option_" .. band)
		value = uci:get("luci_platform", "wireless", "device_option_value_" .. band)

		if option and value then
			return getUciConfigId("wireless", "wifi-device", option, value)
		end
	end

	return nil
end

function get_wifi_iface_cfg_id(iface)
	if iface == "2G" or iface == "5G" or iface == "guest" then
		option = uci:get("luci_platform", "wireless", "iface_option_" .. iface)
		value = uci:get("luci_platform", "wireless", "iface_option_value_" .. iface)

		if option and value then
			return getUciConfigId("wireless", "wifi-iface", option, value)
		end
	end

	return nil
end


-----------------------------------扫描无线网络---------------------------------------------
--[[
ralink:~# iwpriv apcli0 set SiteSurvey=0;sleep 4;iwpriv apcli0 get_site_survey
"Ch", "SSID", "BSSID", "Security", "signal(%)W-Mode", "ExtCH", "NT", "WPS", "DPID"

qca:~# iwinfo ath0 scan

Cell 43 - Address: BC:46:99:49:A6:5E
          ESSID: "YGG-work"
          Mode: Master  Channel: 1
          Signal: -85 dBm  Quality: 21/94
          Encryption: mixed WPA/WPA2 PSK (CCMP)
]]--

function qca_get_dev_name()
	local util = require "luci.util"
	local wifidev = "wifi0"
	local iface   = "ath0"

	local boardInfo = util.ubus("system", "board") or { }
	local targetBoard = boardInfo.release.target

	if targetBoard:find("ipq") then
		wifidev = "wifi1"
		iface   = "ath1"
	end

	return wifidev, iface
end

function qca_scan_ap_list()
	local iw = require "iwinfo"
	local aplist = {}

	local _, dev = qca_get_dev_name()

	local t = assert(iw.type(dev), "Not a wireless device")

	--信号强度
	local function percent_wifi_signal(info)
		local qc = info.quality or 0
		local qm = info.quality_max or 0

		if info.bssid and qc > 0 and qm > 0 then
			return (100 / qm) * qc
		else
			return 0
		end
	end

	--处理加密方式
	local function format_wifi_encryption(info)
		if info.wep == true then
			return "wep"
		elseif info.wpa > 0 then
			return 	(info.wpa == 3) and "mixed-psk" or (info.wpa == 2 and "psk2" or "psk")
		elseif info.enabled then
			return "unknown"
		else
			return "NONE"
		end
	end

	--扫描无线网络
	local i, k, v
	local s = { }
	for i = 1, 2 do
		for k, v in ipairs(iw[t].scanlist(dev)or { }) do
			if not s[v.bssid] then
				if v.ssid then
					table.insert(aplist, {
						['ssid'] = v.ssid,
						['channel'] = v.channel,
						['signal'] = math.floor(percent_wifi_signal(v) / 20),
						['quality'] = v.signal + 100,
						['security'] = format_wifi_encryption(v.encryption),
						['bssid'] = v.bssid
						})
				end
				s[v.bssid] = true
			end
		end
	end

	return aplist
end

function ralink_scan_ap_list(arg)
	local util = require "luci.util"
	local aplist = {}
	local loopLineCount = 0

	util.exec("ifconfig apcli0 up")
	util.exec("iwpriv apcli0 set SiteSurvey=0")

	local i = 0
	while i <= 10 do
		util.exec("sleep 3")

		local getSiteSurvey = util.execl("iwpriv apcli0 get_site_survey")
		if #getSiteSurvey == loopLineCount or i == 10 then
			for _, line in ipairs(getSiteSurvey) do
				local channel, ssid, bssid, security, signal, other = line:match('^(%S+)%s+"(.+)"%s+(%S+)%s+(%S+)%s+(%S+)%s+(.*)')
				if not ssid then
					channel, ssid, bssid, security, signal, other = line:match("^(%S+)%s+(%S+)%s+(%S+)%s+(%S+)%s+(%S+)%s+(.*)")
					if ssid == '""' then ssid = nil end
				end

				if channel and channel ~= "Ch" and ssid then
					if tonumber(signal) then
						table.insert(aplist, {
							['ssid'] 	= ssid,
							['bssid'] 	= bssid,
							['channel'] = channel,
							['signal'] 	= math.floor((tonumber(signal) / 20)),
							['quality']	= tonumber(signal),
							['security'] = security
						})
					end
				end
			end

			break
		end

		loopLineCount = #getSiteSurvey
		i = i + 1
	end

	return aplist
end

function platform_scan_ap_list()
	local fs  = require "nixio.fs"
	local ifac = get_wifi_net("2.4G")
	if ifac.is_up == '1' then
		return false
	end

	if fs.stat("/sys/class/net/apcli0/") then
		return ralink_scan_ap_list()
	elseif
		fs.stat("/sys/class/net/wifi0/") then
		return qca_scan_ap_list()
	else
		return false
	end
end

function scanWirelessEnv()
	local channelArry = {}
	local apList = {}
	local i, v
	for i = 1, 11 do
		channelArry[i] = {}
		channelArry[i]['count'] = 0
		channelArry[i]['factor'] = 0
		channelArry[i]['channel'] = i
	end

	apList = platform_scan_ap_list()
	if apList then
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

	return apList, channelArry
end