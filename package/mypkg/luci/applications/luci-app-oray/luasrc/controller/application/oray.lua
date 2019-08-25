module("luci.controller.application.oray", package.seeall)

function index()

	entry({"admin", "application", "oray"}, template("application/app_oray"), _("花生壳动态域名"), 32).index = true	    
    entry({"admin", "application", "oray", "get_oray_status"}, call("get_oray_status")) 
    entry({"admin", "application", "oray", "switch_service"}, call("switch_service"))
    entry({"admin", "application", "oray", "reset_service"}, call("reset_service"))
end

local fs  = require "nixio.fs"
ORAYSL_STATUS = "/tmp/oraysl.status"
ORAYSL_INIT= "/etc/init.status"

function get_oray_status()
	
	if fs.access(ORAYSL_STATUS) then
	
		local r = fs.readfile(ORAYSL_STATUS)
		local sn = r:match("sn=(%S+)")
		local status = r:match("status=(%S+)")
		luci.http.write_json({ result = true, sn = sn , status = status})	
	else
	    luci.http.write_json({ result = false }) 
	end	
	
end

function switch_service()
	 
	if luci.http.formvalue("action") == "on" then
		luci.util.exec("/etc/init.d/oray enable;/etc/init.d/oray start")
	else
		luci.util.exec("/etc/init.d/oray disable;/etc/init.d/oray stop")
	end
	
	luci.http.write_json({result = true})
end

function reset_service()	 
	
	if fs.access(ORAYSL_INIT) then
		fs.remove(ORAYSL_INIT)
		luci.http.write_json({ result = true})	
	else
	    luci.http.write_json({ result = false }) 
	end	
	
end