-- Copyright 2016 kunteng.org zhangzf@kunteng.org

module("luci.controller.admin.network", package.seeall)

function index()

	entry({"admin", "network", "set_wan_info"}, call("set_wan_info"))
	entry({"admin", "network", "set_wan_mtu"}, call("set_wan_mtu"))
	entry({"admin", "network", "get_pppoe_status"}, call("get_pppoe_status"))
	entry({"admin", "network", "get_pppoe_log"}, call("get_pppoe_log"))
	entry({"admin", "network", "show_pppoe_log"}, template("network/net_ppp_log"), _("PPPOE_LOG"), 90)
	
end

local util	= require "luci.util"
local uci  = require "luci.model.uci".cursor()
local ntm = require "luci.model.network".init()
local fs   = require "nixio.fs"
local http = require "luci.http"
local ubus = require "ubus"
local json = require "luci.jsonc"
local sys = require "luci.controller.admin.system"

function set_wan_mtu()
    local setting = luci.http.formvalue("mtu_set")
	
    uci:set("network","wan","mtu",setting)
    uci:commit("network")
	
    luci.http.prepare_content("application/json")
    luci.http.write_json({ result = true })
    sys.fork_exec("sleep 1;/sbin/luci-reload network;")
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
    local web_data = luci.http.formvalue("wanset")
    local set = json.parse(web_data)	
    local ret = true
	
    if(set.proto == "pppoe") then
        if set.username == "" and set.password == "" then
            ret = false
        else
            clean_wan_set("pppoe")
            uci:set("network","wan","username",set.username) 
            uci:set("network","wan","password",set.password)   
        end
    elseif (set.proto == "dhcp") then
        clean_wan_set("dhcp")

    elseif (set.proto == "static") then
        if set.ipaddr == "" or set.netmask == "" or set.gateway == "" or set.main_dns == "" then
            ret = false
        else
            clean_wan_set("static")
            uci:set("network","wan","ipaddr",set.ipaddr)
            uci:set("network","wan","netmask",set.netmask)
            uci:set("network","wan","gateway",set.gateway)
        end
    end
	

	if set.backup_dns ~= "" then
		uci:set_list("network", "wan", "dns", {set.main_dns, set.backup_dns})
	else
		uci:set("network", "wan", "dns", set.main_dns)
	end

	
	uci:commit("network")
	
    luci.http.prepare_content("application/json")
    luci.http.write_json({ result = ret})  
    sys.fork_exec("sleep 1;/sbin/luci-reload network;/etc/init.d/dnsmasq restart;kill -USR1 $(pidof udhcpc);/etc/init.d/firewall restart;ifup wan;sleep 1;/etc/init.d/wifidog stop;/etc/init.d/wifidog start")
--    sys.fork_exec("sleep 1;/sbin/luci-reload network;sleep 1;/etc/init.d/wifidog restart")
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
	max_log = 1024,
	check_interval = 2
}


function ubus_read_wan_status(conn)
   return conn:call("network.interface", "status", {interface="wan"})
end

function get_wan_status(conn)
   r = ubus_read_wan_status(conn)
   
   if not r then
      conn:call("network", "reload", {})
	  util.exec("sleep 1")
      r = ubus_read_wan_status(conn)
   end
   
   return r
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
		http.write_json({ code = 100})
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
	
	http.write_json({ code = codeResp, msg = msgResp})
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