module("luci.controller.application.app_apfree_wifidog", package.seeall)

local uci = require "luci.model.uci".cursor()

function index()
	local opkg = require "luci.model.ipkg"
	local packageName = "apfree_wifidog"

	if opkg.status(packageName)[packageName] then
		entry({"admin", "application", "apfreeWifiDog"}, template("application/app_apfree_wifidog"), _("Apfree_WifiDog"), 30).index = true
		entry({"admin", "application", "apfreeWifiDog", "setWifiDog"}, call("setWifiDog"))
		entry({"admin", "application", "apfreeWifiDog", "turnOffWifiDog"}, call("turnOffWifiDog"))
	end
end

function _setWifiDogGlobal(cfgName, HostName, port, path, pool, threadNum, queueSize, wirePass)
	assert(HostName ~= nil, 1);
	assert(port ~= nil, 1);
	assert(path ~= nil, 1);
	assert(pool ~= nil, 1);
	assert(threadNum ~= nil, 1);
	assert(queueSize ~= nil, 1);
	assert(wirePass ~= nil, 1);

	uci:set("wifidog", cfgName, "auth_server_hostname", HostName)
	uci:set("wifidog", cfgName, "auth_server_port", port)
	uci:set("wifidog", cfgName, "auth_server_path", path)
	uci:set("wifidog", cfgName, "pool_mode", pool)
	uci:set("wifidog", cfgName, "thread_number", threadNum)
	uci:set("wifidog", cfgName, "queue_size", queueSize)
	uci:set("wifidog", cfgName, "wired_passed", wirePass)

	return 0
end

function setWifiDog()
	local json = require "luci.jsonc"

	local rspCode = 0
	local formValue = luci.http.formvalue("reqdata")
	local reqData = json.parse(formValue)
	local cfgName 

	uci:foreach("wifidog", "wifidog", function(s) cfgName = s[".name"] end)

	if cfgName then
		uci:set("wifidog", cfgName, "enable", "1")

		-- 可以允许空值，空值为删除规则
		uci:set("wifidog", cfgName, "trusted_pan_domains", reqData.TrustedPanDomains)
		uci:set("wifidog", cfgName, "trusted_domains", reqData.TrustedDomains)
		uci:set("wifidog", cfgName, "trusted_iplist", reqData.TrustedIPList)
		uci:set("wifidog", cfgName, "trusted_maclist", reqData.TrustedMACList)
		uci:set("wifidog", cfgName, "untrusted_maclist", reqData.UNTrustedMACList)

		-- 基本设置， 不允许空值
		rspCode = _setWifiDogGlobal(cfgName,reqData.HostName, reqData.Port, reqData.Path, reqData.PoolMod, reqData.ThreadNum, reqData.QueueSize, reqData.WiredPass)

		uci:commit("wifidog")
	else
		rspCode = 2
	end

	if rspCode == 0 then
		luci.util.exec("/usr/sbin/service-reload wifidog")
	end

	luci.http.prepare_content("application/json")  
	luci.http.write_json({ code = rspCode })
end

function turnOffWifiDog()
	local rspCode = 0
	local cfgName 

	uci:foreach("wifidog", "wifidog", function(s) cfgName = s[".name"] end)

	if cfgName then
		uci:set("wifidog", cfgName, "enable", "0")
		uci:commit("wifidog")
	else
		rspCode = 2
	end

	if rspCode == 0 then
		luci.util.exec("/usr/sbin/service-reload wifidog")
	end

	luci.http.prepare_content("application/json")  
	luci.http.write_json({ code = rspCode })
end