module("luci.controller.advanced.sellon", package.seeall)

function index()
	entry({"admin", "advanced", "sellon"}, template("advanced/adv_sellon"), _("IPV6 Settings"), 25).index = true
	entry({"admin", "advanced", "sellon", "get_user"}, call("get_user"))
	entry({"admin", "advanced", "sellon", "set_user"}, call("set_user"))
	entry({"admin", "advanced", "sellon", "get_state"}, call("get_state"))
	entry({"admin", "advanced", "sellon", "ctrl_vpn"}, call("ctrl_vpn"))
end

local USER = "/etc/openvpn/user_pass.txt"
local PASS = "/etc/openvpn/pass.txt"

function get_user()
	local fs  = require "nixio.fs"
	
	if fs.access(USER) then	
		local authuser = fs.readfile(USER)		
		username = authuser:match("(%S+)")
		luci.http.write_json({ result = true,
								username = username,
								passwd = "S2E55S3VE5A3E533S3",
								})	
	else
	    luci.http.write_json({ result = false }) 
	end	

end

function get_state()
	local state = luci.util.exec("/etc/openvpn/vpn_ctr vpn_statue")
	
	luci.http.write(state)
end

function set_user()
	local fs  = require "nixio.fs"
	local sys = require "luci.controller.admin.system"
	local uci = require "luci.model.uci".cursor()
	
	local action = luci.http.formvalue("action")
	if action == "clear" then
		fs.writefile(USER, "")
		fs.writefile(PASS, "")
		
		luci.http.write_json({ result = true })
		
		sys.fork_exec("/etc/openvpn/vpn_ctr vpn_stop")
	else
		local username = luci.http.formvalue("user")
		local passwd = luci.http.formvalue("passwd")
		local ap_mac = uci:get("network", "lan", "macaddr")
		
		fs.writefile(USER, username.."\n"..passwd.."\n")
		fs.writefile(PASS, ap_mac.."\n"..passwd.."op\n")
		
		luci.http.write_json({ result = true })
		sys.fork_exec("/etc/openvpn/vpn_ctr vpn_start")
	end
end

function ctrl_vpn()
	local sys = require "luci.controller.admin.system"
    local action = luci.http.formvalue("action")
	
	sys.fork_exec("/etc/openvpn/vpn_ctr " .. action)
	
	luci.http.write_json({ result = true }) 
end