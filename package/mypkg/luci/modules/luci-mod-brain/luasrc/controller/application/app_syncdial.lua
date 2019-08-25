module("luci.controller.application.app_syncdial", package.seeall)

function index()
		entry({"admin", "application", "syncdial"}, template("application/app_syncdial"), _("单线多拨"), 65).index = true
		entry({"admin", "application", "syncdial", "turnOffService"}, call("switchService"))
		entry({"admin", "application", "syncdial", "configure"}, call("setSyncdial"))
		entry({"admin", "application", "syncdial", "status"}, call("getStatus"))
end

local uci = require "luci.model.uci".cursor()

function switchService()
	uci:set("syncdial", "config", "enabled", "0")
	uci:commit("syncdial")

	luci.util.exec("/usr/sbin/syncdial")

	luci.http.prepare_content("application/json")
	luci.http.write_json({ code = 0 })
end

function setSyncdial()
	local json = require "luci.jsonc"
	local rspCode = 1

	local r = json.parse(luci.http.formvalue("reqdata"))
	local proto = uci:get("network", "wan", "proto")

	if proto == "pppoe" then
		local ktUtil = require "ktapi.ktUtil"
		rspCode = 0

		uci:set("syncdial", "config", "enabled", "1")

		uci:set("syncdial", "config", "wannum", r.WanNum)
		uci:set("syncdial", "config", "dialwait", r.WaitSec)
		uci:set("syncdial", "config", "dialnum", r.DialNum)
		uci:set("syncdial", "config", "dialchk", r.DialChk)
		uci:set("syncdial", "config", "old_frame", r.oldFram)

		uci:commit("syncdial")

		ktUtil.fork_exec("/usr/sbin/syncdial")
	end

	luci.http.prepare_content("application/json")
	luci.http.write_json({ code = rspCode })
end

function getStatus()
	luci.http.write(luci.util.exec("mwan3 status | grep interface"))
end