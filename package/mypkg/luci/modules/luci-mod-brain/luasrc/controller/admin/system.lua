-- Ckpyright 2008 Steven Barth <steven@midlink.org>
-- Copyright 2008-2011 Jo-Philipp Wich <jow@openwrt.org>
-- Licensed to the public under the Apache License 2.0.

module("luci.controller.admin.system", package.seeall)

function index()

	--entry({"admin", "system", "reboot"}, template("admin_system/reboot"), _("Reboot"), 90)
	entry({"admin", "system", "reboot"}, call("action_reboot"))
	entry({"admin", "system", "reset"}, call("action_reset"))
	entry({"admin", "system", "set_system_clock"}, post("set_system_clock"))
	entry({"admin", "system", "setSysPassword"}, call("setSysPassword"))

	entry({"admin", "system", "dhcp_setup"}, call("dhcp_set"))
	entry({"admin", "system", "language"}, post("change_language"))
	entry({"admin", "system", "getCpuUsage"}, call("getCpuUsage"))
	entry({"admin", "system", "getMemUsage"}, call("getMemUsage"))
	entry({"admin", "system", "getDeviceInfo"}, call("getDeviceInfo"))
	entry({"admin", "system", "wizardSetup"}, call("wizardSetup"))
	entry({"admin", "system", "skipWizard"}, call("removeInitFlag"))
	entry({"admin", "system", "getAlarmMessages"}, call("alarmMessage"))

end

---------------------------------------------------------------------------------------
--	全局函数 变量
---------------------------------------------------------------------------------------

--首次登陆标识
local FIRSTLOGINPATH = "/usr/lib/lua/luci/firstlogin"
local uci  = require "luci.model.uci".cursor()

function set_system_clock()
	local set = tonumber(luci.http.formvalue("set"))

	if set ~= nil and set > 0 then
		local date = os.date("*t",set )
	if date then
			luci.sys.call("date -s '%04d-%02d-%02d %02d:%02d:%02d'" %{
			date.year, date.month, date.day, date.hour, date.min, date.sec
		})
		end
	end

	local ntp = luci.http.formvalue("ntp")

	if ntp == "1" then
		service_action('sysntpd','enable')
	else
		service_action('sysntpd','disable')
	end

	luci.http.prepare_content("application/json")
	luci.http.write_json({result = true})
end

--service_action
--input:service-->service name.action:stop, start,restart,enable,disable....
--return:ture-->success,false-->failed.
function service_action(service,action)
	local sys = require "luci.sys"
	local ret

	if action == "enable" then
	   sys.init.enable(service)
	   ret = sys.init.start(service)
	elseif action == "disable" then
	   sys.init.disable(service)
	   ret =  sys.init.stop(service)
	end

	return ret
end

function action_reboot()
	luci.http.write_json(luci.sys.reboot())
end

function setSysPassword()
	-- 参数
	local passwordReq = luci.http.formvalue("newpwd")
	local old_passwordReq = luci.http.formvalue("oldpwd")

	local checkpass = luci.sys.user.checkpasswd("root", old_passwordReq)

	-- 返回值
	local codeResp = 0
	local msgResp = ""
	local arr_out_put={}
	local stat = nil

	--插入运算代码
	if not checkpass then
		codeResp = 1
		msgResp = "原密码不正确"
	else
		stat = luci.sys.user.setpasswd("root", passwordReq)
		if stat ~= 0 then
			codeResp = 1
			msgResp = "密码设置失败,请重试!"
		end
	end

	arr_out_put["code"] = codeResp
	arr_out_put["msg"] = msgResp

	luci.http.write_json(arr_out_put,true)
end

function dhcp_set()
	local ktUtil = require "ktapi.ktUtil"
	local setting = luci.http.formvalue("reqdata")
	local r = false

	if setting then
		local jsn = require "luci.jsonc"
		local configs = jsn.parse(setting)

		uci:set("dhcp","lan","start",configs.start)
		uci:set("dhcp","lan","limit",configs.limit)
		uci:set("dhcp","lan","leasetime",configs.leasetime)

		-- 20161118 add by zhangzf
		uci:set("dhcp", "lan", "domainserver", (configs.secondDns == "") and configs.primaryDns or (configs.primaryDns .. "," .. configs.secondDns))

		uci:commit("dhcp")

		-- 20180511 add by zhangzf
		uci:set("network", "lan", "ipaddr", configs.lanaddr)
		uci:commit("network")

		r = true
	end

	luci.http.prepare_content("application/json")
	luci.http.write_json({ result = r })
	ktUtil.fork_exec("/usr/sbin/lan-gateway-reload")
end

function change_language()
	local lang = luci.http.formvalue("lang")
	uci:set("luci", "main", "lang", lang)
	uci:commit("luci")
	luci.http.write_json({ result = true })
end

function getCpuUsage()
	local rv

	local cmd = "top -b -n 1 | head -n 2 | grep CPU 2>/dev/null"

	local fd = io.popen(cmd)
	if fd then
		while true do
			local ln = fd:read("*l")

			if not ln then break end

			rv = ln:match("^%D+(%d+).+")

		end

		fd:close()
	end

	luci.http.write(rv)
end

function getMemUsage()
	local sysinfo = luci.util.ubus("system", "info") or { }

	local meminfo = sysinfo.memory or {
		total = 0,
		free = 0,
		buffered = 0,
		shared = 0
	}

	luci.http.write_json(meminfo)
end

function getDeviceInfo()
	local fs		= require "nixio.fs"
	local json		= require "luci.jsonc"
	local client	= require "ktapi.ktClient"
	local ktUtil	= require "ktapi.ktUtil"

	local dataResp = {}
	local wanInfo = {}

	local ubusSysinfo	= luci.util.ubus("system", "info") or { }
	local uptime = ubusSysinfo.uptime or 0
	local meminfo = ubusSysinfo.memory or {total = 0, free = 0, buffered = 0, shared = 0}

	local ubusWanStatus = luci.util.ubus("network.interface", "status", {interface="wan"})
	if ubusWanStatus then
		wanInfo["proto"] = ubusWanStatus.proto
		wanInfo["is_up"] = ubusWanStatus.up

		if ubusWanStatus["ipv4-address"] then
			local ipc = require "luci.ip"
			local ipv4Address = ubusWanStatus["ipv4-address"]
			wanInfo["ipaddr"] = #ipv4Address > 0 and ipv4Address[1].address
			wanInfo["netmask"] = #ipv4Address > 0 and ipc.IPv4("0.0.0.0/%d" % ipv4Address[1].mask):mask():string()
		end
	end

	if uci:get("network", "wan", "apclient") == "1" then
		wanInfo["proto"] = "relay"
	end

	local stateByHotplugEvent = "/tmp/state/switch"
	local stateByNetdoctor = "/tmp/state/internet"

	if fs.stat(stateByHotplugEvent) then
		dataResp["port"] = json.parse(fs.readfile(stateByHotplugEvent))
	else
		dataResp["port"] = json.parse(luci.util.exec("netdoctor get port")) or ""
	end

	local isFitAp = (uci:get("network", "lan", "proto") == "dhcp")

	if wanInfo.is_up or isFitAp  then
	--[[
		if fs.stat(stateByNetdoctor) then
			local wanState = json.parse(fs.readfile("/tmp/state/internet"))

			if wanState.time and (os.time() - wanState.time) < 30 then
				dataResp["wanState"] = wanState
			else
				ktUtil.fork_exec("echo -n $(/usr/sbin/netdoctor -c) > /tmp/state/internet")
			end
		else
			ktUtil.fork_exec("echo -n $(/usr/sbin/netdoctor -c) > /tmp/state/internet")
		end
	]]--
		dataResp["wanState"] = json.parse(luci.util.exec("/usr/sbin/netdoctor -c"))
	else
		dataResp["wanState"] = {code = -1}
	end

	-- 小程序使用
	if luci.http.formvalue("wx") then
		local ktNetwork	= require "ktapi.ktNetwork"
		local ktWifi = require "ktapi.ktWifi"

		local firmwareInfo = ktUtil.getFirmwareInfo()
		local lanInfo = ktNetwork.getLanInfo()

		dataResp["romVersion"] 	= firmwareInfo.version or "0.0.0"
		dataResp["routerMac"]	= ktUtil.officalMac(lanInfo.macaddr) or "unknow"
		dataResp["boardName"]	= (firmwareInfo.board_name):gsub("\n", "") or "unknow"
		dataResp["lanAddr"]		= lanInfo.ipaddr or "wifi.kunteng.org.cn"
		dataResp["wifi0"]		= ktWifi.get_wifi_net("2.4G") or ""
		dataResp["wifi1"]		= ktWifi.get_wifi_net("5G") or ""
		dataResp["channel2G"]	= ktWifi.getCurrentChannel()
	end

	dataResp["wanInfo"] = wanInfo
	dataResp["sessionNum"] = client.getClientNum()
	dataResp["runTime"] = uptime
	dataResp["meminfo"] = meminfo

	luci.http.prepare_content("application/json")
	luci.http.write_json(dataResp)
end

function action_reset()
	local ktUtil = require "ktapi.ktUtil"

	local arr_out_put={}

	arr_out_put["code"] = 0
	ktUtil.fork_exec("echo 'y' | firstboot ;reboot")

	luci.http.write_json(arr_out_put,true)
end

function removeInitFlag()
	uci:set("system", "ntp", "initial", "")
	uci:commit("system")

	luci.http.write_json({ result = true })
end

function wizardSetup()
	local json = require "luci.jsonc"
	local ktWifi = require "ktapi.ktWifi"
	local ktUtil = require "ktapi.ktUtil"
	
	local respCode = 0
	local d = luci.http.formvalue("reqdata")
	local reqData = json.parse(d)

	-- Network
	if reqData.proto then
		uci:set("network","wan","proto", reqData.proto)
	end

	if(reqData.proto == "pppoe") then
		if reqData.username == "" and reqData.password == "" then
			respCode = 1
		else
			uci:set("network", "wan", "username", reqData.username) 
			uci:set("network", "wan", "password", reqData.password)   
		end
	elseif (reqData.proto == "static") then
		if reqData.ipaddr == "" or reqData.netmask == "" or reqData.gateway == "" or reqData.primayDns == "" then
			respCode = 1
		else
			uci:set("network", "wan", "ipaddr", reqData.ipaddr)
			uci:set("network", "wan", "netmask", reqData.netmask)
			uci:set("network", "wan", "gateway", reqData.gateway)
		end
	end

	if reqData.secondDns ~= "" then
		uci:set_list("network", "wan", "dns", {reqData.primayDns, reqData.secondDns})
	else
		uci:set("network", "wan", "dns", reqData.primayDns)
	end

	uci:commit("network")

	-- Wireless
	local cfg2g = ktWifi.get_wifi_iface_cfg_id("2G")
	local cfg5g = ktWifi.get_wifi_iface_cfg_id("5G")

	uci:set("wireless",cfg2g, "ssid", reqData.ssid)
	uci:set("wireless",cfg2g, "encryption", "psk-mixed+tkip+ccmp")
	uci:set("wireless",cfg2g, "key", reqData.key)

	if cfg5g ~= nil then
		uci:set("wireless",cfg5g, "ssid", reqData.ssid .. "_5G")
		uci:set("wireless",cfg5g, "encryption", "psk-mixed+tkip+ccmp")
		uci:set("wireless",cfg5g, "key", reqData.key)
	end

	uci:commit("wireless")

	-- System Password
	luci.sys.user.setpasswd("root", reqData.syspwd)

	luci.http.prepare_content("application/json")
	luci.http.write_json({ code = respCode })

	ktUtil.fork_exec("/usr/sbin/lan-gateway-reload")
end

function alarmMessage()
	local rv = { }
	local logfile = "/tmp/run/state.log"

	local devs = {
		["printer"] = "打印机",
		["box"] = "51盒子",
	}

	local fd = io.open(logfile, "r")
	if fd then
		while true do
			local ln = fd:read("*l")
			if not ln then
				break
			else
				local msg, s_date = ln:match("^(%S+) (.+)")
				if msg and s_date then
					table.insert(rv, 1, {
						--['msg']  = devs[dev] .. ((stat == '0') and "上线" or "离线"),
						['msg']  = msg,
						['s_date']  = s_date,
					})
				end
			end
		end

		fd:close()
	end

	luci.http.prepare_content("application/json")
	luci.http.write_json(rv)
end