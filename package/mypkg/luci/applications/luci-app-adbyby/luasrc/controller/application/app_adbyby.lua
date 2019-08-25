module("luci.controller.application.app_adbyby", package.seeall)

local uci = require "luci.model.uci".cursor()

function index()
	local opkg = require "luci.model.ipkg"
	local packageName = "adbyby"

	if opkg.status(packageName)[packageName] then
		entry({"admin", "application", "adbyby"}, template("application/app_adbyby"), _("广告屏蔽大师"), 62).index = true
		entry({"admin", "application", "adbyby", "switchService"}, call("switchService"))
	end
end

function switchService()
	local ac = luci.http.formvalue("action")
	
	uci:set("adbyby", "proxy", "disabled", ac)
	uci:commit("adbyby")
	
	luci.util.exec("/etc/init.d/adbyby restart")
	
    luci.http.prepare_content("application/json")
    luci.http.write_json({ code = 0 })
end