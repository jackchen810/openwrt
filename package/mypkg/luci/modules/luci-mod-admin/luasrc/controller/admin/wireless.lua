-- Copyright 2016 kunteng.org zhangzf@kunteng.org

module("luci.controller.admin.wireless", package.seeall)

function index()

	entry({"admin", "wireless", "scan_ap_list"}, call("scan_ap_list"))
	entry({"admin", "wireless", "set_apclient"}, call("set_apclient"))
	entry({"admin", "wireless", "set_channel"}, call("set_channel"))
	entry({"admin", "wireless", "set_txpower"}, call("set_txpower"))
	entry({"admin", "wireless", "get_apclient_status"}, call("get_apclient_status"))
	entry({"admin", "wireless", "ctrl_apclient"}, call("ctrl_apclient"))
	entry({"admin", "wireless", "set_vap"}, call("set_vap"))
	entry({"admin", "wireless", "set_iface"}, call("set_iface"))

end

local util	= require "luci.util"
local uci  = require "luci.model.uci".cursor()
local ntm = require "luci.model.network".init()
local fs   = require "nixio.fs"
local http = require "luci.http"
local ktapi = require "luci.kt_uci_api"

function set_wireless_iface(cfg, ssid, encryption, key)
	assert(cfg ~= nil, 1);
	assert(ssid ~= nil, 1);
	assert(encryption ~= nil, 1);
	
	uci:set("wireless",cfg, "ssid", ssid)
	uci:set("wireless",cfg, "encryption", encryption)
	uci:set("wireless",cfg, "key", key)
	
	uci:commit("wireless")
	
	return 0
end

function set_iface()
	local json = require "luci.jsonc"
	local sys = require "luci.controller.admin.system"
	
	local result = true
	local httpdata = json.parse(luci.http.formvalue("data"))
	
	local cfg = ktapi.get_wifi_iface_cfg_id(httpdata.iface)
	
	if set_wireless_iface(cfg, httpdata.ssid, httpdata.encryption, httpdata.password) == 1 then
		result = false
	end
	
	luci.http.prepare_content("application/json")  
    luci.http.write_json({ result = result })
	
	sys.fork_exec("sleep 1;wifi reload;sleep 1;ifup wan")
end

function set_vap()
	local sys = require "luci.controller.admin.system"
	local json = require "luci.jsonc"
	
    local ret = true	
	local gateway_changed = false

    local w_data = json.parse(luci.http.formvalue("data"))
	
    local cfg2g = ktapi.get_wifi_iface_cfg_id("2G")
    local cfg5g = ktapi.get_wifi_iface_cfg_id("5G")
	
	if uci:get("network", "lan", "proto") ~= "dhcp" then
		if (uci:get("network", "lan", "ipaddr") ~= w_data.gateway) then 
			uci:set("network", "lan", "ipaddr", w_data.gateway);
			uci:commit("network")
			gateway_changed = true
		end
    end
	
	if set_wireless_iface(cfg2g, w_data.ssid, w_data.encryption, w_data.password) == 1 then
		ret = false
	end
	
    if cfg5g ~= nil then
		if set_wireless_iface(cfg5g, w_data.ssid, w_data.encryption, w_data.password) == 1 then
			ret = false
		end
    end
	
    luci.http.prepare_content("application/json")  
    luci.http.write_json({ result = ret }) 
	
    if gateway_changed == true or (uci:get("network", "wan", "apclient") == "1") then
        sys.fork_exec("sleep 1;/sbin/luci-reload network;/etc/init.d/dnsmasq restart;ifup wan;sleep 1;/etc/init.d/wifidog stop;/etc/init.d/wifidog start")
    else
        sys.fork_exec("sleep 1;wifi reload;sleep 1;ifup wan")
    end
end

function set_channel()
	local sys = require "luci.controller.admin.system"
	local r = false

    local channel = luci.http.formvalue("channel")
    local dev = luci.http.formvalue("device")

    local cfg = ktapi.get_wifi_device_cfg_id(dev)
	
    if cfg then
        uci:set("wireless",cfg,"channel",channel or uci:get("wireless", cfg, "channel"))
        uci:commit("wireless")
        r = true
    end
	
    luci.http.prepare_content("application/json")                                               
    luci.http.write_json({ result = r })
	
    if r == true then
		if (uci:get("network", "wan", "apclient") == "1") then 
			sys.fork_exec("sleep 1;wifi reload;sleep 4;ifup wan")
		else
			sys.fork_exec("sleep 1;wifi reload")
		end
    end
end

function set_txpower()
	local sys = require "luci.controller.admin.system"
	local r = false

    local txpower = luci.http.formvalue("txpower")
    local dev = luci.http.formvalue("device")

    local cfg = ktapi.get_wifi_device_cfg_id(dev)
	
    if cfg then
        uci:set("wireless",cfg, "txpower", txpower or uci:get("wireless", cfg, "txpower"))
        uci:commit("wireless")
        r = true
    end
	
    luci.http.prepare_content("application/json")                                               
    luci.http.write_json({ result = r })
	
    if r == true then
		if (uci:get("network", "wan", "apclient") == "1") then 
			sys.fork_exec("sleep 1;wifi reload;sleep 4;ifup wan")
		else
			sys.fork_exec("sleep 1;wifi reload")
		end
    end
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

function qca_scan_ap_list()
	local iw = require "iwinfo" 
	local dev = "ath0"
	local aplist = {}
	
	local t = assert(iw.type(dev), "Not a wireless device") 
	
	--信号强度
	local function percent_wifi_signal(info)
		local qc = info.quality or 0
		local qm = info.quality_max or 0

		if info.bssid and qc > 0 and qm > 0 then
			return math.floor((100 / qm) * qc / 20)
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
						['signal'] = percent_wifi_signal(v),
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
	local aplist = {}

	util.exec("iwpriv ra0 set SiteSurvey=0")
	util.exec("sleep 4")
	
 	local show = util.execi("iwpriv ra0 get_site_survey")
	
	if not show then
		return
	else
		show()
	end
	
	for line in show do
	
		local channel, ssid, bssid, security, signal, other = line:match("^(%S+)%s+(%S+)%s+(%S+)%s+(%S+)%s+(%S+)%s+(.*)")
		
		if channel and channel ~= "Ch" then
		
			if tonumber(signal) then
			
				table.insert(aplist, {
					['ssid'] 	= ssid,
					['bssid'] 	= bssid,
					['channel'] = channel,
					['signal'] 	= math.floor((tonumber(signal) / 20)),
					['security'] = security
					})
			end
		end
	end
	
	return aplist
end
		
function platform_scan_ap_list()

	if fs.stat("/sys/class/net/apcli0/") then
		return ralink_scan_ap_list()
	elseif
		fs.stat("/sys/class/net/wifi0/") then
		return qca_scan_ap_list()
	else
		return false
	end

end

------------------------------------------------- 中继设置 --------------------------------------------
function ralink_set_apclient(apClientConfig)

	local wifiNet = ktapi.get_wifi_iface_cfg_id("2G")
	local wifiDev = ktapi.get_wifi_device_cfg_id("2G")

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
	uci:set("wireless", wifiNet, "apcli_bssid", apClientConfig.bssid)
	
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
	
	if section.channel then
		uci:set("wireless", "wifi0", "channel", section.channel)
	end
	
	if not section.ssid then
		return false
	end
	
	local nw = require "luci.controller.admin.network"
	nw.clean_wan_set("dhcp")
	
	uci:set("network", "wan", "ifname", "ath01")
	uci:set("network", "wan", "apclient", "1")
	uci:commit("network")
		
	--删除已配置过的vap
	local cVap = find_qca_sta_vap()
	if cVap then
		uci:delete("wireless", cVap)
	end
	
	--重新添加新的sta	
	local vap = uci:add("wireless", "wifi-iface")
	uci:set("wireless", vap, "device", "wifi0")
	uci:set("wireless", vap, "mode", "sta")
	uci:set("wireless", vap, "network", "wan")
	uci:set("wireless", vap, "ssid", section.ssid)
	uci:set("wireless", vap, "bssid", section.bssid)
	
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
	local arr_out_put = {}

	local apList = platform_scan_ap_list()

		local function comps(a,b)
			return a.signal > b.signal
		end
		
		-- 按信号强度排序并返回
		if apList then
			table.sort(apList, comps)
		else
			codeResp = 1
		end

	arr_out_put["aplist"] = apList	
	arr_out_put["code"] = codeResp
	http.write_json(arr_out_put,true)	
end

function set_apclient()
	local sys = require "luci.controller.admin.system"

	local apClientConfig	= {
		channel 	= luci.http.formvalue("channel"),
		ssid		= luci.http.formvalue("ssid"),
		bssid		= luci.http.formvalue("bssid"),
		authmode	= luci.http.formvalue("authmode"),
		key			= luci.http.formvalue("key")
	}
	
	if platform_set_apclient(apClientConfig) then 	
	luci.http.prepare_content("application/json")
	luci.http.write_json({result = true})
	sys.fork_exec("/etc/init.d/network restart;sleep 2;/etc/init.d/dnsmasq restart;kill -USR1 $(pidof udhcpc);/etc/init.d/firewall restart;sleep 1;/etc/init.d/wifidog stop;/etc/init.d/wifidog start")
	end
end

function get_apclient_status()

	local ktUci = require "luci.kt_uci_api"
	local rspDate = {}
	local wanConn = 0
	local apcliSsid, apcliBssid, apcliWpapsk, apcliAuthmode
	
	if fs.stat("/sys/class/net/apcli0/") then
		local wifiNet = ktUci.get_wifi_iface_cfg_id("2G")

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
		local wifiNet = ktapi.get_wifi_iface_cfg_id("2G")
		uci:set("wireless", wifiNet, "apcli_enable", "0")
		uci:commit("wireless")		
	elseif
		fs.stat("/sys/class/net/wifi0/") then		
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
		util.exec("ifdown wan")
	else
		util.exec("ifup wan")
	end
	
	luci.http.write_json({result = true})
end
