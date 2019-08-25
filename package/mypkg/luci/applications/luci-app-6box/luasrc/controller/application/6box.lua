module("luci.controller.application.6box", package.seeall)

function index()
	entry({"admin", "application", "6box"}, template("application/app_6box"), _("6Box"), 1).index = true
	    
    entry({"admin", "application", "6box", "vpn_set"}, post("openvpn_set")) 
    entry({"admin", "application", "6box", "vpn_status"}, post("vpn_status")) 
end

local sys = require "luci.controller.admin.system"


function openvpn_set()
	local fs  = require "nixio.fs"
	
    local username = luci.http.formvalue("v6user")
    local passwd = luci.http.formvalue("v6pwd")
    local mode = luci.http.formvalue("mode")
	
	fs.writefile("/etc/openvpn/authuser", username.."\n"..passwd.."\n")
	
    luci.http.prepare_content("application/json")
	
    luci.http.write_json({ result = true })
	
	if mode == "6box" then
		sys.fork_exec("kill -9 `pgrep vpn`;sleep 1;saier_go")
	end
end

function vpn_status()
	local fs  = require "nixio.fs"
	
	if fs.access("/etc/openvpn/authuser") then
	
		local authuser = fs.readfile("/etc/openvpn/authuser")
		
		username, passwd = authuser:match("(%S+)\n(%S+)\n")
		luci.http.write_json({ result = true, 
								username = username,
								passwd = passwd,
								})
	
	else
	    luci.http.write_json({ result = false }) 
	end	

end