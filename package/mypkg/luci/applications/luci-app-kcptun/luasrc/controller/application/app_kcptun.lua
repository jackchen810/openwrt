module("luci.controller.application.app_kcptun", package.seeall)

function index()
		entry({"admin", "application", "kcptun"}, template("application/app_kcptun"), _("KCP加速"), 61).index = true
		entry({"admin", "application", "kcptun", "getServiceInfo"}, call("getServiceInfo"))
		entry({"admin", "application", "kcptun", "turnOffService"}, call("turnOffService"))
		entry({"admin", "application", "kcptun", "setKcptun"}, call("setKcptun"))
end

local uci = require "luci.model.uci".cursor()
local fs = require "nixio".fs

local json_file_path = "/usr/local/xkcptun/client.json"

function getServiceInfo()
	local rspData = {}
	local configData = {}

	uci:foreach("xkcptun", "client", function(s) configData[s[".index"]]=s end)

	rspData["code"] = configData[#configData]
	rspData["conf"] = fs.readfile(json_file_path)

	luci.http.prepare_content("application/json")  
	luci.http.write_json(rspData)
end

function setKcptun()
	local json = require "luci.jsonc"

	local rspCode = 0
	local formValue = luci.http.formvalue("reqdata")
	local reqData = json.parse(formValue)
	local cfgName 

	uci:foreach("xkcptun", "client", function(s) cfgName = s[".name"] end)

	if cfgName then
		uci:set("xkcptun", cfgName, "enable", "1")
		uci:set("xkcptun", cfgName, "command", reqData.command)

		if reqData.jsonData then
			uci:set("xkcptun", cfgName, "jsonfile", 1)
			fs.writefile(json_file_path, reqData.jsonData)
		else
			uci:set("xkcptun", cfgName, "jsonfile", 0)
			uci:set("xkcptun", cfgName, "localport", reqData.localPort)
			uci:set("xkcptun", cfgName, "remoteaddr", reqData.serverAddr)
			uci:set("xkcptun", cfgName, "remoteport", reqData.serverPort)
			uci:set("xkcptun", cfgName, "key", reqData.key or "")
			uci:set("xkcptun", cfgName, "crypt", reqData.crypt)
			uci:set("xkcptun", cfgName, "mode", reqData.mode)
			uci:set("xkcptun", cfgName, "mtu", reqData.mtu)
			uci:set("xkcptun", cfgName, "sndwnd", reqData.sndwnd)
			uci:set("xkcptun", cfgName, "rcvwnd", reqData.rcvwnd)
			uci:set("xkcptun", cfgName, "datashard", reqData.datashard)
			uci:set("xkcptun", cfgName, "parityshard", reqData.parityshard)
			uci:set("xkcptun", cfgName, "nocomp", reqData.nocomp)
			uci:set("xkcptun", cfgName, "acknodelay", reqData.acknodelay)
			uci:set("xkcptun", cfgName, "interval", reqData.interval)
			uci:set("xkcptun", cfgName, "resend", reqData.resend)
			uci:set("xkcptun", cfgName, "nc", reqData.nc)
			uci:set("xkcptun", cfgName, "sockbuf", reqData.sockbuf)
			uci:set("xkcptun", cfgName, "sockbuf", reqData.sockbuf)
			uci:set("xkcptun", cfgName, "keepalive", reqData.keepalive)
		end
	end

	uci:commit("xkcptun")

	luci.util.exec("/etc/init.d/xkcptun restart")

	luci.http.prepare_content("application/json")  
	luci.http.write_json({ code = rspCode })
end

function turnOffService()
	local rspCode = 0
	local cfgName 

	uci:foreach("xkcptun", "client", function(s) cfgName = s[".name"] end)

	if cfgName then
		uci:set("xkcptun", cfgName, "enable", "0")
		uci:commit("xkcptun")
	else
		rspCode = 2
	end

	if rspCode == 0 then
		luci.util.exec("/etc/init.d/xkcptun restart")
	end

	luci.http.prepare_content("application/json")  
	luci.http.write_json({ code = rspCode })
end