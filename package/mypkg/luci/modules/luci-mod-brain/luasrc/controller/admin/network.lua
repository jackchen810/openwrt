-- Copyright 2016 kunteng.org zhangzf@kunteng.org

module("luci.controller.admin.network", package.seeall)

function index()

	entry({"admin", "network", "set_wan_info"}, call("set_wan_info"))
	entry({"admin", "network", "set_lan_info"}, call("set_lan_info"))
	entry({"admin", "network", "set_wan_mtu"}, call("set_wan_mtu"))
	entry({"admin", "network", "set_wan_mac"}, call("set_wan_mac"))
	entry({"admin", "network", "get_pppoe_status"}, call("get_pppoe_status"))
	entry({"admin", "network", "get_pppoe_log"}, call("get_pppoe_log"))

	entry({"admin", "network", "getWanTraffic"}, call("getWanTraffic"))
	entry({"admin", "network", "pppoeSniffer"}, call("pppoeSniffer"))
	entry({"admin", "network", "publicDns"}, call("pingPublicDns"))

end

local fs   = require "nixio.fs"
local ubus = require "ubus"
local json = require "luci.jsonc"
local uci  = require "luci.model.uci".cursor()

local ktUtil = require "ktapi.ktUtil"

function getWanTraffic()
	local http = require "luci.http"
	local iface = luci.http.formvalue("iface")
	local arr_out_put={}

	local cmd = "luci-bwc -i "..iface.."| tail -n 2 2>/dev/null"

	local bwc = io.popen(cmd)
	if bwc then
		while true do
			local ln = bwc:read("*l")

			if not ln then break end

			arr_out_put[#arr_out_put+1]=ln

		end
		bwc:close()
	end

	luci.http.prepare_content("application/json")
	luci.http.write_json(arr_out_put)
end

function set_lan_info()
	local ip = luci.http.formvalue("data")
	local mask = luci.http.formvalue("mask")

	uci:set("network", "lan", "ipaddr", ip)
	uci:set("network", "lan", "netmask", mask)
	uci:commit("network")

	luci.http.prepare_content("application/json")
	luci.http.write_json({ result = true })

	ktUtil.fork_exec("/usr/sbin/lan-gateway-reload")
end

function set_wan_mtu()
	local setting = luci.http.formvalue("mtu_set")

	uci:set("network","wan","mtu",setting)
	uci:commit("network")

	luci.http.prepare_content("application/json")
	luci.http.write_json({ result = true })

	ktUtil.fork_exec("/usr/sbin/lan-gateway-reload")
end

function set_wan_mac()
	local cloneMac = luci.http.formvalue("macaddr")
	local defMac = luci.http.formvalue("defmac")

	if not uci:get("network", "wan", "defmacaddr") then
		uci:set("network", "wan", "defmacaddr", defMac)
	end

	uci:set("network", "wan", "macaddr", cloneMac)
	uci:commit("network")

	luci.http.prepare_content("application/json")
	luci.http.write_json({ result = true })

	ktUtil.fork_exec("/usr/sbin/lan-gateway-reload")
end

function clean_wan_set(proto)
	--清除中继设置
	local wireless = require "luci.controller.admin.wireless"
	wireless.cancel_apclient()

	--清空network配置
	uci:set("network","wan","proto",proto)
	uci:set("network","wan","username","")
	uci:set("network","wan","password","")
	uci:set("network","wan","ipaddr","")
	uci:set("network","wan","netmask","")
	uci:set("network","wan","gateway","")
	uci:set("network","wan","dns","")

	uci:commit("network")
end

function set_wan_info()
	local d = luci.http.formvalue("wanset")
	local requestData = json.parse(d)
	local ret = true

	if(requestData.proto == "pppoe") then
		if requestData.username == "" and requestData.password == "" then
			ret = false
		else
			clean_wan_set("pppoe")
			uci:set("network", "wan", "username", requestData.username) 
			uci:set("network", "wan", "password", requestData.password)   
		end
	elseif (requestData.proto == "dhcp") then
		clean_wan_set("dhcp")

	elseif (requestData.proto == "static") then
		if requestData.ipaddr == "" or requestData.netmask == "" or requestData.gateway == "" or requestData.primayDns == "" then
			ret = false
		else
			clean_wan_set("static")
			uci:set("network", "wan", "ipaddr", requestData.ipaddr)
			uci:set("network", "wan", "netmask", requestData.netmask)
			uci:set("network", "wan", "gateway", requestData.gateway)
		end
	end

	if requestData.secondDns ~= "" then
		uci:set_list("network", "wan", "dns", {requestData.primayDns, requestData.secondDns})
	else
		uci:set("network", "wan", "dns", requestData.primayDns)
	end

	uci:commit("network")

	luci.http.prepare_content("application/json")
	luci.http.write_json({ result = ret})  
	ktUtil.fork_exec("/usr/sbin/lan-gateway-reload")
 end

----------------------- PPPOE状态检查 --------------------------------------------
local PPPOE_RESULT = {
	['PEER_NO_RESP'] =  {
		p = {
			"Timeout waiting for PADO packets\n$",
			"Unable to complete PPPoE Discovery\n$",
			"Timeout waiting for PADS packets\n$"
		},
		msg = "错误678：无法建立连接,远程计算机没有响应。",
		vcode = 678
	},
	['NO_MORE_SESSION'] = {
		p = {
			"CHAP authentication failed: Max Online Number,ErrorNumber:9\n$"
		},
		msg = "错误691：身份认证失败：已超过最高在线数",
		vcode = 691
	},
	['MODEM_HANGUP'] = {
		p = {
			"Modem hangup\n$",
		},
		msg = "错误619：不能建立连接,Modem已挂断",
		vcode = 619
	},
	['AUTH_FAILD'] = {
		p = {
			"CHAP authentication failed\n$",
			"PAP authentication failed\n$"
		},
		msg = "错误691：连接失败,用户名或密码不正确，",
		vcode = 691
	}
}

local PPPOE_CONFIG = { 
	logfile = "/tmp/ppp.log",
	max_log = 4096,
	check_interval = 2
}

function ubus_read_wan_status(conn)
   return conn:call("network.interface", "status", {interface="wan"})
end

function get_wan_status(conn)
   r = ubus_read_wan_status(conn)
   
   if not r then
		conn:call("network", "reload", {})
		luci.util.exec("sleep 1")
		r = ubus_read_wan_status(conn)
	end

	return r
end

local function pop_last_msg(str)
	local rest = str
	local last, prev

	return function ()
		prev = rest
		if not rest then return rest end		 
		rest, last = rest:match('(.+\n)(.+\n)$')
		if last then return last else return prev end
	end
end

function pase_pppoe_log()
	local lines = fs.readfile(PPPOE_CONFIG.logfile)   
	if not lines then return nil end

	if #lines > PPPOE_CONFIG.max_log then -- remove log file
		fs.remove(PPPOE_CONFIG.logfile)
	end

	local function match_pattern(line)
		for key, patterns in pairs(PPPOE_RESULT) do
			for i, p in ipairs(patterns.p) do
				m = line:find(p)
				if m then return patterns end
			end
		end
		return nil
	end

	for line in pop_last_msg(lines) do
		local res = match_pattern(line)
		if res then
			return res.msg
		end
	end

	return nil
end

--[[
	100: 不是pppoe模式
	 -1: ubus连接失败
	  0: 连接成功
	  1: 连接中
	  2: 其他

]]--
function get_pppoe_status()

	local codeResp = 0
	local msgResp = {}

	--判断当前是否为pppoe拨号设置
	local proto = uci:get("network", "wan", "proto")
	if proto ~= "pppoe" then 
		luci.http.write_json({ code = 100})
		return
	end

	--ubus连接
	local conn  = ubus.connect()
	if not conn then
		codeResp = -1
	else
		local stat = get_wan_status(conn)
		if stat.up then
			codeResp = 0
		elseif stat.autostart then
			codeResp = 1
			-- 解析ppp日志
			msgResp = pase_pppoe_log()
		else
			codeResp = 2
		end
	end

	luci.http.write_json({ code = codeResp, msg = msgResp})
end

function get_pppoe_log()
	local logpath = "/tmp/ppp.log"
	fs = io.open(logpath)
	local log
	if fs then
		log = fs:read("*all")
		fs:close()
	end  
	luci.http.prepare_content("application/json") 
	luci.http.write_json({ log = log})
end

function pppoeSniffer()
	local pppdLogFile = "/tmp/pppoe.pwd"
	local pppSniff = "/usr/sbin/pppoe-sniffer "

	local codeResp = 0
	local msgResp = {}
	local cmd = luci.http.formvalue("cmd")
	local mode = luci.http.formvalue("mode")

	local function stopSniff()
		luci.util.exec("killall pppoe-server-sniff")
		luci.util.exec("killall pppoe-sniffer")

		fs.remove(pppdLogFile)
	end

	local function readLog()
		local r = {}
		local f = fs.readfile(pppdLogFile)
		if not f then return nil end

		local hasRun = tonumber((luci.sys.exec(" ps |grep [p]ppoe-sniffer|wc -l") or ""):match("%d+")) or 0
		if hasRun < 1 then
			codeResp = -1;
			return r;
		end

		for ln in pop_last_msg(f) do
		--	local u, p = ln:match('^.+user="(%S+)" password="(%S+)".+')
			local u, p = ln:match("(%S+) (%S+)")
			if u and p then
				for i, v in ipairs(r) do
					if v.user == u and v.passwd == p then
						stopSniff()
						codeResp = 0;
						return r
					end
				end

				table.insert(r, {
					["user"] = u,
					["passwd"] = p
				})

				if mode == "0" then codeResp = 0 end
			end
		end

		return r
	end

	if cmd == "start" then
		stopSniff()

		ktUtil.fork_exec(pppSniff .. ((mode == "1") and "120 more" or "60 one"))

	elseif cmd == "sniffing" then
		codeResp = 1;
		msgResp = readLog()
	end

	luci.http.prepare_content("application/json")
	luci.http.write_json({ code = codeResp, msg = msgResp or ""})
end

function pingPublicDns()
	local dnsFile = "/tmp/publicDns.log"

	local DnsServers = {
			['114.114.114.114']	= "114 DNS",
			['114.114.115.115']	= "114 DNS",
			['1.2.4.8']			= "CNNIC SDNS",
			['210.2.4.8']		= "CNNIC SDNS",
			['223.5.5.5']		= "阿里 AliDNS",
			['223.6.6.6']		= "阿里 AliDNS",
			['180.76.76.76']	= "百度 BaiduDNS",
			['119.29.29.29']	= "DNSPod DNS+",
			['182.254.116.116']	= "DNSPod DNS+",
			['101.226.4.6']		= "DNS 派(非联通)",
			['218.30.118.6']	= "DNS 派(非联通)",
			['123.125.81.6']	= "DNS派(联通)",
			['140.207.198.6']	= "DNS派(联通)",
			['8.8.8.8']			= "谷歌DNS",
		}

	local dataResp = {}

	for line in luci.util.execi("/usr/sbin/pdns.sh") do
		local time, ip = line:match("(%S+) (%S+)")
		table.insert(dataResp, {
			['ipaddr']	= ip,
			['time']	= time,
			['sp']		= DnsServers[ip] or ""
		})
	end

	luci.http.prepare_content("application/json")
	luci.http.write_json(dataResp)
end