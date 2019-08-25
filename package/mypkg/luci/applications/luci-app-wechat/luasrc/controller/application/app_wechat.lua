module("luci.controller.application.app_wechat", package.seeall)

--[[
{"wechat", "miniProgram", "getWanInfo"}
请求参数{config:1} 返回配置信息
请求参数{status:1} 返回WAN口当前状态 

{"wechat", "miniProgram", "getWifiInfo"}
返回 {wifi2G:{}, wifi5G{}}

{"wechat", "miniProgram", "getLanInfo"}
返回Lan配置信息

{"wechat", "miniProgram", "getMTUVaule"}
返回{1500}

{"wechat", "miniProgram", "getDhcpInfo"}
返回Dhcp配置信息
]]

function index()
	local root = node()
	if not root.target then
		root.target = alias("admin")
		root.index = true
	end

	local page		= node("admin")
	page.target		= firstchild()
	page.title		= _("Administration")
	page.ucidata	= true
	page.index		= true

	entry({"wechat"}, firstchild())
	entry({"wechat", "miniProgram"}, firstchild())
	entry({"wechat", "miniProgram", "sysauth"}, call("wechatAuth"))
	entry({"wechat", "miniProgram", "getWanInfo"}, call("getWanInfo"))
	entry({"wechat", "miniProgram", "getWifiInfo"}, call("getWifiInfo"))
	entry({"wechat", "miniProgram", "getLanInfo"}, call("getLanInfo"))
	entry({"wechat", "miniProgram", "getMTUVaule"}, call("getMTUVaule"))
	entry({"wechat", "miniProgram", "getDhcpInfo"}, call("getDhcpInfo"))
	entry({"wechat", "miniProgram", "getMacBind"}, call("getMacBind"))
	entry({"wechat", "miniProgram", "getAppList"}, call("getAppList"))
	entry({"wechat", "miniProgram", "getRebootTask"}, call("getRebootTask"))
	entry({"wechat", "miniProgram", "getAdbybyState"}, call("getAdbybyState"))
	entry({"wechat", "miniProgram", "getForwardRules"}, call("getForwardRules"))
	entry({"wechat", "miniProgram", "getShadowSocksInfo"}, call("getShadowSocksInfo"))
	entry({"wechat", "miniProgram", "getWifiDogInfo"}, call("getWifiDogInfo"))
	entry({"wechat", "miniProgram", "getSambaShare"}, call("getSambaShare"))
	entry({"wechat", "miniProgram", "getBandWidth"}, call("getBandWidth"))
	entry({"wechat", "miniProgram", "getGlobalQosConfig"}, call("getGlobalQosConfig"))
	entry({"wechat", "miniProgram", "getXfrpInfo"}, call("getXfrpInfo"))
end

local uci = require "luci.model.uci".cursor()

function wechatAuth()
	local pwd = luci.http.formvalue("password")
	local user = require "luci.sys".user

	luci.http.prepare_content("application/json")
	luci.http.write_json({user = user.checkpasswd("root", pwd) and true or false})
end

function getWanInfo()
	local ktNetwork = require "ktapi.ktNetwork"

	if luci.http.formvalue("config") == "1" then
		local rv = {
			proto		= uci:get("network", "wan", "proto") or "dhcp",
			password	= uci:get("network", "wan", "password"),
			username	= uci:get("network", "wan", "username"),
			ipaddr		= uci:get("network", "wan", "ipaddr"),
			gateway		= uci:get("network", "wan", "gateway"),
			netmask		= uci:get("network", "wan", "netmask"),
			dns			= uci:get("network", "wan", "dns"),

			--中继状态
			apClientSet = uci:get("network", "wan", "apclient"),
		}

		luci.http.prepare_content("application/json")
		luci.http.write_json(rv)
		return
	elseif luci.http.formvalue("status") == "1" then
		local wanInfo = ktNetwork.getWanInfo()

		wanInfo.proto = wanInfo.proto or uci:get("network", "wan", "proto")
		wanInfo.ipaddr = wanInfo.ipaddr or "0.0.0.0"
		wanInfo.netmask = wanInfo.netmask or "0.0.0.0"
		wanInfo.gateway = wanInfo.gateway or "0.0.0.0"
		wanInfo.dns = wanInfo.dns or "0.0.0.0"

		luci.http.prepare_content("application/json")
		luci.http.write_json(wanInfo)
		return
	end
end

function getLanInfo()
	local rspData = {}

	rspData["ipAddr"] = uci:get("network", "lan", "ipaddr")
	rspData["netmask"] = uci:get("network", "lan", "netmask") or "255.255.255.0"

	luci.http.prepare_content("application/json")
	luci.http.write_json(rspData)
end

function getWifiInfo()
	local ktWifi = require "ktapi.ktWifi"
	local rspData = {}
	local powerMax = 20

	local boardinfo = luci.util.ubus("system", "board") or { }
	local target_board = boardinfo.release.target
	if target_board:find("ramips") then
		powerMax = 100
	end

	rspData["wifi2G"] = ktWifi.get_wifi_net("2.4G")
	rspData["wifi5G"] = ktWifi.get_wifi_net("5G")

	if not rspData.wifi2G.txpower then
		rspData.wifi2G.txpower = powerMax
	end

	if rspData["wifi5G"] then 
		if not rspData.wifi5G.txpower then
			rspData.wifi5G.txpower = powerMax
		end
	end

	luci.http.prepare_content("application/json")
	luci.http.write_json(rspData)
end

function getMTUVaule()
	local mtuValue = 1500

	local wanIfname = uci:get("network", "wan", "ifname")

	if uci:get("network", "wan", "proto") == "pppoe" then
		mtuValue = luci.util.trim(luci.util.exec("ifconfig pppoe-wan | grep MTU|sed 's/.*MTU://'|awk '{print $1}'"))
	else
		mtuValue = luci.util.trim(luci.util.exec("ifconfig "..wanIfname.." | grep MTU|sed 's/.*MTU://'|awk '{print $1}'"))
	end

	luci.http.prepare_content("application/json")
	luci.http.write_json(mtuValue)
end

function getDhcpInfo()
	local rspData = {}

	rspData["ipaddr"]	= uci:get("network", "lan", "ipaddr")
	rspData["start"]	= uci:get("dhcp", "lan", "start")%256
	rspData["limit"]	= uci:get("dhcp", "lan", "limit")
	rspData["leaseTime"]= uci:get("dhcp", "lan", "leasetime")

	local primaryDns  = uci:get("dhcp", "lan", "domainserver")
	local secondDns

	if primaryDns and primaryDns:match(",") then
		primaryDns, secondDns = primaryDns:match("(%S+),(%S+)")
	end

	rspData["dns1"] = primaryDns
	rspData["dns2"] = secondDns

	luci.http.prepare_content("application/json")
	luci.http.write_json(rspData)
end

function getMacBind()
	local status	= require "luci.tools.status"
	local client	= require "ktapi.ktClient"

	local rspData = {}
	rspData.leases	= status.dhcp_leases()
	rspData.ethers = client.getEthersInfo()

	luci.http.prepare_content("application/json")
	luci.http.write_json(rspData)

end

function getAppList()
	local disp = require "luci.dispatcher"
	local system_node = disp.get("admin", "application")
	local childs = disp.node_childs(system_node)

	luci.http.prepare_content("application/json")
	luci.http.write_json(childs)
end

function getAdbybyState()
	luci.http.prepare_content("application/json")
	luci.http.write_json({disabled = uci:get("adbyby", "proxy", "disabled") or 1})
end

function getForwardRules()
	local client = require "ktapi.ktClient"
	local rds = {}

	uci:foreach("firewall", "redirect",
		function(s)
			local t = {}
			t.sname = s[".name"]
			t.name = s.name
			t.proto = s.proto or "all"
			t.destip = s.dest_ip
			t.srcport = tonumber(s.src_dport)
			t.destport = tonumber(s.dest_port)

			table.insert(rds, t)
		end
	)

	local clientAddr = client.getClientList()

	luci.http.prepare_content("application/json")
	luci.http.write_json({rules = rds, clients = clientAddr})
end

function getShadowSocksInfo()
	local fs = require "nixio.fs"

	local Shadowsocks = uci:get_all("shadowsocks")
	local CustomList = fs.readfile("/usr/shadowsocks/custom.txt")

	luci.http.prepare_content("application/json")
	luci.http.write_json({config = Shadowsocks, custom = CustomList})
end

function getBandWidth()
	local downSpeed = uci:get("apfreeqos", "bandwidth", "download") or 0
	local upSpeed = uci:get("apfreeqos", "bandwidth", "upload") or 0

	if downSpeed == 0 then
		local ktUtil	= require "ktapi.ktUtil"
		ktUtil.fork_exec("/usr/sbin/speedtest")
	end

	luci.http.prepare_content("application/json")
	luci.http.write_json({download = string.format("%0.2f", downSpeed / 100), upload= string.format("%0.2f", upSpeed / 100)})
end

function getRebootTask()
	luci.http.prepare_content("application/json")
	luci.http.write_json({task = luci.util.exec("crontab -l | grep reboot | cut -d\" \" -f 1-5"):gsub("\n", "") or ""})
end

function getWifiDogInfo()
	local WifiDog = {}
	uci:foreach("wifidog", "wifidog", function(s) WifiDog[s[".index"]]=s end)

	local Enable	= WifiDog[0].enable or 1
	local HostName	= WifiDog[0].auth_server_hostname
	local Port		= WifiDog[0].auth_server_port
	local Path		= WifiDog[0].auth_server_path
	local PoolMode	= WifiDog[0].pool_mode
	local ThreadNum	= WifiDog[0].thread_number
	local QueueSize	= WifiDog[0].queue_size
	local WiredPass	= WifiDog[0].wired_passed

	-- 访问规则
	local TrustedPanDomains	= WifiDog[0].trusted_pan_domains or ""
	local TrustedDomains	= WifiDog[0].trusted_domains or ""
	local TrustedIPList		= WifiDog[0].trusted_iplist or ""
	local TrustedMACList	= WifiDog[0].trusted_maclist or ""
	local UNTrustedMACList	= WifiDog[0].untrusted_maclist or ""

	luci.http.prepare_content("application/json")
	luci.http.write_json({config = WifiDog})
end

function getSambaShare()
	local _, z
	local share = {}

	local mounts = luci.sys.mounts()

	uci:foreach("samba", "sambashare",
		function(s)
			local t = {}
			t.sname = s[".name"]
			t.name = s.name
			t.path = s.path
			t.read_only = s.read_only
			t.description = s.description
			t.guest_ok = s.guest_ok

			table.insert(share, t)
		end
	)

	luci.http.prepare_content("application/json")
	luci.http.write_json({config = share, mount = mounts})
end

function getGlobalQosConfig()
	local downSpeed = uci:get("apfreeqos", "bandwidth", "download") or 0
	local upSpeed = uci:get("apfreeqos", "bandwidth", "upload") or 0

	luci.http.prepare_content("application/json")
	luci.http.write_json({downSpeed = downSpeed, upSpeed = upSpeed})
end

function getXfrpInfo()
	local config = {}

	uci:foreach("frpc", "proxy",
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

	luci.http.prepare_content("application/json")
	luci.http.write_json(config)
end