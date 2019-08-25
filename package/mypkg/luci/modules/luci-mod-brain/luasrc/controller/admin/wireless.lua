-- Copyright 2016 kunteng.org zhangzf@kunteng.org

module("luci.controller.admin.wireless", package.seeall)

function index()
	entry({"admin", "wireless", "scan_ap_list"}, call("scan_ap_list"))
	entry({"admin", "wireless", "set_apclient"}, call("set_apclient"))
	entry({"admin", "wireless", "set_channel"}, call("set_channel"))
	entry({"admin", "wireless", "set_txpower"}, call("set_txpower"))
	entry({"admin", "wireless", "ctrl_apclient"}, call("ctrl_apclient"))
	entry({"admin", "wireless", "wifi_setup"}, call("wifi_setup"))

	entry({"admin", "wireless", "reconnect"}, call("reconnect"))
	entry({"admin", "wireless", "shutdown"}, call("shutdown"))

	entry({"admin", "wireless", "getApclientStatus"}, call("getApclientStatus"))
end

local uci = require "luci.model.uci".cursor()
local fs  = require "nixio.fs"

local ktWifi = require "ktapi.ktWifi"
local ktUtil = require "ktapi.ktUtil"

function set_wireless_iface(cfg, ssid, encryption, key, hide, disable)
	assert(cfg ~= nil, 1);

	if ssid == nil then return 0 end

	if encryption ~= "none" and key ~= nil and #key < 8 then return 0 end

	if encryption == "none" then key = "" end

	uci:set("wireless",cfg, "ssid", ssid)
	uci:set("wireless",cfg, "encryption", encryption)
	uci:set("wireless",cfg, "key", key)
	uci:set("wireless",cfg, "hidden", hide)
	uci:set("wireless",cfg, "disabled", disable)

--	uci:commit("wireless")

	return 0
end

function wifi_setup()
	local json = require "luci.jsonc"
	local respCode = 0

	local reqData = json.parse(luci.http.formvalue("reqdata"))

	local cfg2g = ktWifi.get_wifi_iface_cfg_id("2G")
	local cfg5g = ktWifi.get_wifi_iface_cfg_id("5G")

	local dev2g = ktWifi.get_wifi_device_cfg_id("2G")

	if set_wireless_iface(cfg2g, reqData.wifi0_ssid, reqData.wifi0_encryption, reqData.wifi0_password, reqData.wifi0_hidden, reqData.wifi0_disabled) == 1 then
		respCode = 1
	end

	uci:set("wireless",dev2g, "channel", reqData.wifi0_channel)
	uci:set("wireless",dev2g, "txpower", reqData.wifi0_txpower)
	uci:set("wireless",dev2g, "disabled", reqData.wifi0_disabled)

	if cfg5g ~= nil then
		if reqData.merge == 1 then
			if set_wireless_iface(cfg5g, reqData.wifi0_ssid, reqData.wifi0_encryption, reqData.wifi0_password, reqData.wifi0_hidden, reqData.wifi0_disabled) == 1 then
				respCode = 1
			end
		else
			if set_wireless_iface(cfg5g, reqData.wifi1_ssid, reqData.wifi1_encryption, reqData.wifi1_password, reqData.wifi1_hidden, reqData.wifi1_disabled) == 1 then
				respCode = 1
			end
		end
	end

	local dev5g = ktWifi.get_wifi_device_cfg_id("5G")
	if dev5g ~= nil then
		uci:set("wireless",dev5g, "channel", reqData.wifi1_channel)
		uci:set("wireless",dev5g, "txpower", reqData.wifi1_txpower)
		uci:set("wireless",dev5g, "disabled", reqData.wifi1_disabled)
	end

	if reqData.wifi0_guest_ssid then
		local cfg = ktWifi.getWifiIfaceCfg("guest")
		if set_wireless_iface(cfg, reqData.wifi0_guest_ssid, reqData.wifi0_guest_encryption, reqData.wifi0_guest_password, reqData.wifi0_guest_hidden, reqData.wifi0_guest_disabled) == 1 then
			respCode = 1
		end
	end

	uci:commit("wireless")

	luci.http.prepare_content("application/json")
	luci.http.write_json({ code = respCode })

	local reload_cmd = "sleep 1;wifi reload" .. ((uci:get("network", "wan", "apclient") == "1") and ";sleep 1;ifup wan" or "")

	ktUtil.fork_exec(reload_cmd)

end

------------------------------------------------- 中继设置 --------------------------------------------
function ralink_set_apclient(apClientConfig)
	local wifiNet = ktWifi.get_wifi_iface_cfg_id("2G")
	local wifiDev = ktWifi.get_wifi_device_cfg_id("2G")

	if not apClientConfig.ssid then
		return false
	end
	-- 设置外网
	local n = require "luci.controller.admin.network"

	n.clean_wan_set("dhcp")

	uci:set("network", "wan", "ifname", "apcli0")
	uci:set("network", "wan", "apclient", "1")
	uci:commit("network")

	if apClientConfig.channel then
		uci:set("wireless", wifiDev, "channel", apClientConfig.channel)
	end

	uci:set("wireless", wifiNet, "apcli_enable", "1")
	uci:set("wireless", wifiNet, "apcli_ssid", apClientConfig.ssid)
	--uci:set("wireless", wifiNet, "apcli_bssid", apClientConfig.bssid)

	if apClientConfig.authmode ~= "NONE" then
		uci:set("wireless", wifiNet, "apcli_authmode", "WPA2PSK")
		uci:set("wireless", wifiNet, "apcli_encryptype", "AES")
		uci:set("wireless", wifiNet, "apcli_wpapsk", apClientConfig.key)
	else
		uci:set("wireless", wifiNet, "apcli_authmode", "OPEN")
		uci:set("wireless", wifiNet, "apcli_encryptype", "NONE")
		uci:set("wireless", wifiNet, "apcli_wpapsk", "")
	end

	uci:commit("wireless")

	return true
end

function find_qca_sta_vap()
	local section
	uci:foreach("wireless", "wifi-iface", function(s)
			local iface = s[".name"]
			if uci:get("wireless",iface,"mode") == "sta" then
				section = iface
				end
			end
		)
	return section
end

function qca_set_apclient(section)
	local wifidev, iface = ktWifi.qca_get_dev_name()

	if section.channel then
		uci:set("wireless", wifidev, "channel", section.channel)
	end

	if not section.ssid then
		return false
	end

	local nw = require "luci.controller.admin.network"
	nw.clean_wan_set("dhcp")

	uci:set("network", "wan", "ifname", iface .. '1')
	uci:set("network", "wan", "apclient", "1")
	uci:commit("network")

	--删除已配置过的vap
	local cVap = find_qca_sta_vap()
	if cVap then
		uci:delete("wireless", cVap)
	end

	--重新添加新的sta
	local vap = uci:add("wireless", "wifi-iface")
	uci:set("wireless", vap, "device", wifidev)
	uci:set("wireless", vap, "mode", "sta")
	uci:set("wireless", vap, "network", "wan")
	uci:set("wireless", vap, "ssid", section.ssid)

	--uci:set("wireless", vap, "bssid", section.bssid)
	uci:set("wireless", vap, "extap", "1")

	--添加SID加密类型和密码，如果没有加密设置none
	if section.authmode ~= "NONE"then
		uci:set("wireless", vap, "encryption", section.authmode)
		uci:set("wireless", vap, "key", section.key)
	else
		uci:set("wireless", vap, "encryption", "none")
	end

	uci:commit("wireless")

	return true
end

function platform_set_apclient(config)
	if fs.stat("/sys/class/net/apcli0/") then
		return ralink_set_apclient(config)
	elseif
		fs.stat("/sys/class/net/wifi0/") then
		return qca_set_apclient(config)
	else
		return false
	end

end

function scan_ap_list()
	local codeResp = 0
	local arryOutput = {}

	local apList = ktWifi.platform_scan_ap_list()

		local function comps(a,b)
			return a.signal > b.signal
		end

		-- 按信号强度排序并返回
		if apList then
			table.sort(apList, comps)
		else
			codeResp = 1
		end

	arryOutput["aplist"] = apList
	arryOutput["code"] = codeResp
	luci.http.write_json(arryOutput, true)
end

function set_apclient()
	local apClientConfig	= {
		channel 	= luci.http.formvalue("channel"),
		ssid		= luci.http.formvalue("ssid"),
		bssid		= luci.http.formvalue("bssid"),
		authmode	= luci.http.formvalue("authmode"),
		key			= luci.http.formvalue("key")
	}

	luci.http.prepare_content("application/json")

	if platform_set_apclient(apClientConfig) then
		luci.http.write_json({result = true})
		ktUtil.fork_exec("/usr/sbin/lan-gateway-reload")
		ktUtil.fork_exec("/usr/sbin/repeat-dog")
	else
		luci.http.write_json({result = false})
	end
end

function getApclientStatus()
	local ntm = require "luci.model.network".init()

	local rspDate = {}
	local wanConn = 0
	local apcliSsid, apcliBssid, apcliWpapsk, apcliAuthmode

	if fs.stat("/sys/class/net/apcli0/") then
		local wifiNet = ktWifi.get_wifi_iface_cfg_id("2G")

		apcliSsid = uci:get("wireless", wifiNet, "apcli_ssid")
		apcliBssid = uci:get("wireless", wifiNet, "apcli_bssid")
		apcliWpapsk = uci:get("wireless", wifiNet, "apcli_wpapsk")
		apcliAuthmode = uci:get("wireless", wifiNet, "apcli_encryptype")

	elseif fs.stat("/sys/class/net/wifi0/") then
		local wifiNet = find_qca_sta_vap()

		if not wifiNet then
			luci.http.write_json( {result = false} )
			return
		end

		apcliSsid = uci:get("wireless", wifiNet, "ssid")
		apcliBssid = uci:get("wireless", wifiNet, "bssid")
		apcliWpapsk = uci:get("wireless", wifiNet, "key")
		apcliAuthmode = uci:get("wireless", wifiNet, "encryption")
	end

	local is_set = uci:get("network", "wan", "apclient")
	if is_set and is_set == '1' then
		local wan = ntm:get_wannet()
		if wan then
			if wan:ipaddr() then
				wanConn = 1
			end
		end
	end

	if not apcliSsid then
		luci.http.write_json({result = false})
	else
		rspDate["apcliSsid"] = apcliSsid
		rspDate["apcliBssid"] = apcliBssid
		rspDate["apcliWpapsk"] = apcliWpapsk
		rspDate["apcliAuthmode"] = apcliAuthmode
		rspDate["wanConn"] = wanConn
		rspDate["result"] = true

		luci.http.write_json(rspDate)
	end
end

function cancel_apclient()
	if fs.stat("/sys/class/net/apcli0/") then
		local wifiNet = ktWifi.get_wifi_iface_cfg_id("2G")
		uci:set("wireless", wifiNet, "apcli_enable", "0")
		uci:commit("wireless")
	elseif fs.stat("/sys/class/net/wifi0/") then
		local current_vap = find_qca_sta_vap()

		if current_vap then
			uci:set("wireless", current_vap, "disabled", "1")
			uci:commit("wireless")
		end
	end

	--恢复netwrok网络接口为初始的网口, 并设置关闭中继标志位
	local defifname = uci:get("network", "wan", "defifname")

	if defifname then
		uci:set("network", "wan", "ifname", defifname)
	else
		local ifname = uci:get("network", "wan", "ifname")
		uci:set("network", "wan", "defifname", ifname)
	end

	uci:set("network", "wan", "apclient", "0")
	uci:commit("network")
end

function ctrl_apclient()
	if luci.http.formvalue("cmd") == "0" then
		luci.util.exec("ifdown wan")
	else
		luci.util.exec("ifup wan")
	end

	luci.http.write_json({result = true})
end

function reconnect()
	local respCode = 0
	local device = luci.http.formvalue("device")

	switchWifiState(device, 0)

	luci.http.write_json({code = respCode})
	ktUtil.fork_exec("sleep 1;wifi reload")
end

function shutdown()
	local respCode = 0
	local device = luci.http.formvalue("device")

	switchWifiState(device, 1)

	luci.http.write_json({code = respCode})
	ktUtil.fork_exec("sleep 1;wifi reload")
end

function switchWifiState(dev, action)
	if dev == "all" then
		local cfg2g = ktWifi.get_wifi_iface_cfg_id("2G")
		local cfg5g = ktWifi.get_wifi_iface_cfg_id("5G")
		local dev2g = ktWifi.get_wifi_device_cfg_id("2G")
		local dev5g = ktWifi.get_wifi_device_cfg_id("5G")

		uci:set("wireless", cfg2g, "disabled", action)
		uci:set("wireless", cfg5g, "disabled", action)
		uci:set("wireless", dev2g, "disabled", action)
		uci:set("wireless", dev5g, "disabled", action)
		uci:commit("wireless")

		return
	end

	if dev ~= "guest" then
		local ifac = ktWifi.get_wifi_iface_cfg_id(dev)
		local dev = ktWifi.get_wifi_device_cfg_id(dev)

		uci:set("wireless", ifac, "disabled", action)
		uci:set("wireless", dev, "disabled", action)
	else
		local ifac = ktWifi.getWifiIfaceCfg("guest")
		uci:set("wireless", ifac, "disabled", action)
	end
	uci:commit("wireless")

	return
end