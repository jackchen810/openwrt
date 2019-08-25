module("luci.controller.application.app_loadbalance", package.seeall)

function index()
	entry({"admin", "application", "loadbalance"}, template("application/app_loadbalance"), _("WiFi负载均衡"), 32).index = true
	entry({"admin", "application", "loadbalance", "switchService"}, call("switchService"))
	entry({"admin", "application", "loadbalance", "getConnect"}, call("getConnect"))
	entry({"admin", "application", "loadbalance", "getServiceStatus"}, call("getServiceStatus"))
end

local uci = require "luci.model.uci".cursor()

function getServiceStatus()
	local disabled = 0
	local cfgName
	uci:foreach("loadbalance", "loadbalance", function(s) cfgName = s[".name"] end)
	if cfgName then
		disabled = uci:get("loadbalance", cfgName, "disabled")
	end

	luci.http.prepare_content("application/json")
	luci.http.write_json({disabled = disabled})
end

function switchService()
	local ac = luci.http.formvalue("action")
	local cfgName
	uci:foreach("loadbalance", "loadbalance", function(s) cfgName = s[".name"] end)

	if cfgName then
		uci:set("loadbalance", cfgName, "disabled", ac)
		uci:commit("loadbalance")
	end

	luci.util.exec("/etc/init.d/loadbalance restart")

	luci.http.prepare_content("application/json")
	luci.http.write_json({ code = 0 })
end

function getConnect()
	local util = require "luci.util"
	local date = {}
	local code = 0
	local k = {"no", "mac address", "ssid", "group", "type", "lbcount", "drvcount"}

	local show = util.execi("loadbalance remote-show connect")
	if not show then
		code = 1
	else
		show()
		for line in show do
			local row = {}
			local j = 1

			for value in line:gmatch("[^%s]+") do
				row[k[j]] = value
				j = j + 1
			end

			if row[k[1]] then
				table.insert(date, row)
			end
		end
	end

	luci.http.prepare_content("application/json")
	luci.http.write_json({ code = code, remote = date })
end